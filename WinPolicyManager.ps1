<#
.SYNOPSIS
    Windows Policy Manager - one-screen GUI to apply / revert Windows restrictions
    (remove apps, block programs, lock down taskbar, Quick Access, Settings, ...).

.DESCRIPTION
    Every restriction ("policy") is defined in policies.json. Tick a policy and click
    Apply to enforce it; untick it and click Apply to revert it.

    Action types supported in policies.json:
      registry    - set a registry value (HKLM = whole PC, HKCU = every user profile)
      blockApp    - block a program by file name (Explorer "DisallowRun" list, per user)
      removeAppx  - uninstall a Store app for all users and de-provision it for new users
      uninstallProgram - uninstall a desktop program (.msi or .exe installer) by its
                    name in Settings > Apps

.PARAMETER ConfigPath
    Path to the policies file. Defaults to policies.json next to this script.

.PARAMETER Silent
    No GUI. Applies the "enabled" flags saved in the config file. Useful for rolling the
    same configuration out to many PCs (Task Scheduler, Intune, a login script, ...).
#>
param(
    [string]$ConfigPath,
    [switch]$Silent
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ConfigPath) { $ConfigPath = Join-Path $ScriptDir 'policies.json' }
$ConfigPath = [IO.Path]::GetFullPath($ConfigPath)

# ---------------------------------------------------------------------------
# Elevation: registry machine keys, other users' profiles and app removal all
# need admin rights. Appx cmdlets also need Windows PowerShell (not pwsh 7).
# ---------------------------------------------------------------------------
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin  = ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -or $PSVersionTable.PSEdition -eq 'Core') {
    $argList = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$($MyInvocation.MyCommand.Path)`" -ConfigPath `"$ConfigPath`""
    if ($Silent) { $argList += ' -Silent' }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    exit
}

$CurrentSid  = $identity.User.Value
$CurrentUser = $identity.Name
$LogFile     = Join-Path $ScriptDir 'WinPolicyManager.log'
$script:LogBox = $null
$script:InstalledAppx = @{}
$script:ProvisionedAppx = $null

$DisallowRunKey = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
$ProfileListKey = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
function Write-Log([string]$Message) {
    $line = '{0:yyyy-MM-dd HH:mm:ss}  {1}' -f (Get-Date), $Message
    try { Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8 } catch { }
    if ($script:LogBox) {
        $script:LogBox.AppendText($line + "`r`n")
        [System.Windows.Forms.Application]::DoEvents()
    } else {
        Write-Host $line
    }
}

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
function Read-Config {
    if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "Config file not found: $ConfigPath" }
    $cfg = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json

    if (-not $cfg.settings) { $cfg | Add-Member -NotePropertyName settings -NotePropertyValue ([pscustomobject]@{}) }
    $defaults = @{ userScope = 'AllUsers'; excludeUsers = @() }
    foreach ($k in $defaults.Keys) {
        if ($null -eq $cfg.settings.$k) { $cfg.settings | Add-Member -NotePropertyName $k -NotePropertyValue $defaults[$k] -Force }
    }
    $cfg.settings.excludeUsers = @($cfg.settings.excludeUsers | Where-Object { $_ })
    if ($null -eq $cfg.policies) { $cfg | Add-Member -NotePropertyName policies -NotePropertyValue @() -Force }
    $cfg.policies = @($cfg.policies)

    $ids = @{}
    foreach ($p in $cfg.policies) {
        if (-not $p.id) { throw "A policy is missing its 'id' (name: '$($p.name)')" }
        if ($ids[$p.id]) { throw "Duplicate policy id '$($p.id)' in config" }
        $ids[$p.id] = $true
    }
    $script:Config = $cfg

    # First run: "excludeCurrentUser" means "add whoever opens the GUI to the
    # never-restrict list". Done once, then the flag is dropped.
    if ($cfg.settings.excludeCurrentUser -and -not $Silent) {
        Set-UserExcluded (Get-MyProfileName) $true
        $cfg.settings.PSObject.Properties.Remove('excludeCurrentUser')
        Save-Config
    }
}

function Save-Config {
    $json = $script:Config | ConvertTo-Json -Depth 10
    [IO.File]::WriteAllText($ConfigPath, $json, (New-Object Text.UTF8Encoding $false))
}

function Set-PolicyEnabled($Policy, [bool]$Enabled) {
    $Policy | Add-Member -NotePropertyName enabled -NotePropertyValue $Enabled -Force
}

# ---------------------------------------------------------------------------
# Registry helpers (all paths use the Registry:: provider form)
# ---------------------------------------------------------------------------
function Get-RegValue([string]$Path, [string]$Name) {
    try { (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

function Set-RegValue([string]$Path, [string]$Name, [string]$Type, $Value) {
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
}

function Remove-RegValue([string]$Path, [string]$Name) {
    if (Test-Path -LiteralPath $Path) { Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue }
}

function Get-ActionRegPath($Action, [string]$UserRoot) {
    if ($Action.hive -eq 'HKLM') { "Registry::HKEY_LOCAL_MACHINE\$($Action.path)" } else { "$UserRoot\$($Action.path)" }
}

# ---------------------------------------------------------------------------
# User profile hives. HKCU-type settings are written into every user's
# NTUSER.DAT (plus the Default profile, so brand-new users get them too).
# ---------------------------------------------------------------------------
# Excluded accounts are matched by profile folder name (C:\Users\<name>), which
# stays the same on imaged PCs where SIDs change. New accounts copy the Default
# profile, so excluded ones get any copied restrictions actively removed.
function Get-UserHiveTargets {
    $settings = $script:Config.settings
    if ($settings.userScope -eq 'CurrentUser') {
        return [pscustomobject]@{ Name = $CurrentUser; Sid = $CurrentSid; ProfilePath = $null; Excluded = $false }
    }
    $excluded = @($settings.excludeUsers)
    $targets = @()
    foreach ($p in Get-ChildItem -LiteralPath $ProfileListKey) {
        $sid = $p.PSChildName
        if ($sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { continue }   # real local/domain accounts only
        $profilePath = Get-RegValue $p.PSPath 'ProfileImagePath'
        if (-not $profilePath) { continue }
        $userName = Split-Path $profilePath -Leaf
        $targets += [pscustomobject]@{ Name = $userName; Sid = $sid; ProfilePath = $profilePath; Excluded = ($excluded -contains $userName) }
    }
    $defaultPath = Get-RegValue $ProfileListKey 'Default'
    if ($defaultPath) { $targets += [pscustomobject]@{ Name = 'Default profile (new users)'; Sid = 'DEFAULT'; ProfilePath = $defaultPath; Excluded = $false } }
    $targets
}

function Get-MyProfileName {
    $path = Get-RegValue "$ProfileListKey\$CurrentSid" 'ProfileImagePath'
    if ($path) { Split-Path $path -Leaf } else { $env:USERNAME }
}

function Set-UserExcluded([string]$Name, [bool]$Excluded) {
    $list = @(@($script:Config.settings.excludeUsers) | Where-Object { $_ -and $_ -ne $Name })
    if ($Excluded) { $list += $Name }
    $script:Config.settings | Add-Member -NotePropertyName excludeUsers -NotePropertyValue $list -Force
}

function Mount-UserHive($Target) {
    if ($Target.Sid -eq $CurrentSid -and -not $Target.ProfilePath) {
        return [pscustomobject]@{ Root = 'Registry::HKEY_CURRENT_USER'; Mount = $null }
    }
    # User is signed in -> hive is already loaded under HKEY_USERS
    if ($Target.Sid -ne 'DEFAULT' -and (Test-Path -LiteralPath "Registry::HKEY_USERS\$($Target.Sid)")) {
        return [pscustomobject]@{ Root = "Registry::HKEY_USERS\$($Target.Sid)"; Mount = $null }
    }
    $dat = Join-Path $Target.ProfilePath 'NTUSER.DAT'
    if (-not (Test-Path -LiteralPath $dat)) { return $null }
    $mount = 'WPM_' + ($Target.Sid -replace '[^A-Za-z0-9]', '_')
    if (Test-Path -LiteralPath "Registry::HKEY_USERS\$mount") {
        # left over from an earlier crash
        $null = & reg.exe unload "HKU\$mount" 2>$null
    }
    $null = & reg.exe load "HKU\$mount" "$dat" 2>$null
    if ($LASTEXITCODE -ne 0) { return $null }
    [pscustomobject]@{ Root = "Registry::HKEY_USERS\$mount"; Mount = $mount }
}

function Dismount-UserHive($Mounted) {
    if (-not $Mounted -or -not $Mounted.Mount) { return }
    # Release any registry handles PowerShell still holds before unloading
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    for ($i = 0; $i -lt 5; $i++) {
        $null = & reg.exe unload "HKU\$($Mounted.Mount)" 2>$null
        if ($LASTEXITCODE -eq 0) { return }
        Start-Sleep -Milliseconds 500
        [GC]::Collect()
    }
    Write-Log "WARNING: could not unload hive $($Mounted.Mount) - it will be released on reboot."
}

# ---------------------------------------------------------------------------
# blockApp: Explorer DisallowRun list (per user)
# ---------------------------------------------------------------------------
function Get-DisallowRunEntries([string]$ListPath) {
    $entries = @{}
    if (Test-Path -LiteralPath $ListPath) {
        $key = Get-Item -LiteralPath $ListPath
        foreach ($n in $key.GetValueNames()) { $entries[$n] = [string]$key.GetValue($n) }
        $key.Close()
    }
    $entries
}

function Add-DisallowRun([string]$UserRoot, [string]$Exe) {
    $base = "$UserRoot\$DisallowRunKey"
    $list = "$base\DisallowRun"
    Set-RegValue $base 'DisallowRun' 'DWord' 1
    if (-not (Test-Path -LiteralPath $list)) { New-Item -Path $list -Force | Out-Null }
    $entries = Get-DisallowRunEntries $list
    if ($entries.Values -contains $Exe) { return }
    $n = 1
    while ($entries.ContainsKey("$n")) { $n++ }
    New-ItemProperty -LiteralPath $list -Name "$n" -PropertyType String -Value $Exe -Force | Out-Null
}

function Remove-DisallowRun([string]$UserRoot, [string]$Exe) {
    $base = "$UserRoot\$DisallowRunKey"
    $list = "$base\DisallowRun"
    $entries = Get-DisallowRunEntries $list
    foreach ($k in @($entries.Keys)) {
        if ($entries[$k] -eq $Exe) { Remove-ItemProperty -LiteralPath $list -Name $k -ErrorAction SilentlyContinue }
    }
    if ((Get-DisallowRunEntries $list).Count -eq 0) {
        Remove-RegValue $base 'DisallowRun'
        if (Test-Path -LiteralPath $list) { Remove-Item -LiteralPath $list -Force -ErrorAction SilentlyContinue }
    }
}

function Test-DisallowRun([string]$UserRoot, [string]$Exe) {
    $base = "$UserRoot\$DisallowRunKey"
    (Get-RegValue $base 'DisallowRun') -eq 1 -and (Get-DisallowRunEntries "$base\DisallowRun").Values -contains $Exe
}

# ---------------------------------------------------------------------------
# removeAppx: Store apps
# ---------------------------------------------------------------------------
function Update-AppxCache {
    $script:InstalledAppx = @{}
    $script:AppxListOk = $false
    try {
        Get-AppxPackage -AllUsers -ErrorAction Stop | ForEach-Object { $script:InstalledAppx[$_.Name] = $true }
        $script:AppxListOk = $true
    } catch {
        Write-Log "WARNING: could not list installed Store apps: $($_.Exception.Message)"
    }
}

function Test-AppxInstalled([string]$Package) {
    @($script:InstalledAppx.Keys | Where-Object { $_ -like $Package }).Count -gt 0
}

function Remove-StoreApp([string]$Package) {
    $removedSomething = $false
    foreach ($pkg in @(Get-AppxPackage -AllUsers -Name $Package -ErrorAction SilentlyContinue)) {
        try {
            Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
            Write-Log "    removed $($pkg.PackageFullName)"
            $removedSomething = $true
        } catch {
            Write-Log "    WARNING: could not remove $($pkg.PackageFullName): $($_.Exception.Message)"
        }
    }
    if ($null -eq $script:ProvisionedAppx) {
        $script:ProvisionedAppx = @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue)
    }
    foreach ($pp in @($script:ProvisionedAppx | Where-Object { $_.DisplayName -like $Package })) {
        try {
            Remove-AppxProvisionedPackage -Online -PackageName $pp.PackageName -ErrorAction Stop | Out-Null
            Write-Log "    de-provisioned $($pp.DisplayName) (new users won't get it)"
            $removedSomething = $true
        } catch {
            Write-Log "    WARNING: could not de-provision $($pp.DisplayName): $($_.Exception.Message)"
        }
    }
    if (-not $removedSomething) { Write-Log "    $Package is already removed" }
}

# ---------------------------------------------------------------------------
# uninstallProgram: desktop programs listed in Settings > Apps (MSI or EXE)
# ---------------------------------------------------------------------------
function Get-InstalledPrograms {
    $roots = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
             'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($k in Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue) {
            $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
            if (-not $p.DisplayName -or -not $p.UninstallString) { continue }
            if ($p.SystemComponent -eq 1 -or $p.ParentKeyName -or $p.ReleaseType) { continue }   # hidden parts / updates
            $code = $null
            if ($p.WindowsInstaller -eq 1 -or $p.UninstallString -match 'msiexec') {
                if ($k.PSChildName -match '^\{[0-9A-Fa-f-]{36}\}$') { $code = $k.PSChildName }
                elseif ($p.UninstallString -match '\{[0-9A-Fa-f-]{36}\}') { $code = $Matches[0] }
            }
            [pscustomobject]@{
                DisplayName          = [string]$p.DisplayName
                Publisher            = [string]$p.Publisher
                Version              = [string]$p.DisplayVersion
                UninstallString      = [string]$p.UninstallString
                QuietUninstallString = [string]$p.QuietUninstallString
                ProductCode          = $code
            }
        }
    }
}

function Update-InstalledCache {
    Update-AppxCache
    $script:InstalledPrograms = @(Get-InstalledPrograms)
}

function Test-ProgramInstalled([string]$Pattern) {
    @($script:InstalledPrograms | Where-Object { $_.DisplayName -like $Pattern }).Count -gt 0
}

# "7-Zip 23.01 (x64)" -> "7-Zip*" so the policy still matches after the program updates
function Get-NamePattern([string]$Name) {
    if ($Name -match '^(.*?[^\s_-])[\s_-]+v?\d+(\.\d+)+.*$') { return [WildcardPattern]::Escape($Matches[1]) + '*' }
    [WildcardPattern]::Escape($Name)
}

function Split-CommandLine([string]$CommandLine) {
    $cl = $CommandLine.Trim()
    if ($cl.StartsWith('"')) {
        $end = $cl.IndexOf('"', 1)
        if ($end -lt 0) { return @($cl.Trim('"'), '') }
        return @($cl.Substring(1, $end - 1), $cl.Substring($end + 1).Trim())
    }
    $i = $cl.ToLower().IndexOf('.exe')
    if ($i -ge 0) { return @($cl.Substring(0, $i + 4), $cl.Substring($i + 4).Trim()) }
    @($cl, '')
}

function Wait-ProcessUi($Process, [int]$TimeoutMinutes = 15) {
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    while (-not $Process.HasExited) {
        if ((Get-Date) -gt $deadline) { return $false }
        if ($script:LogBox) { [System.Windows.Forms.Application]::DoEvents() }
        Start-Sleep -Milliseconds 250
    }
    $true
}

function Uninstall-DesktopProgram([string]$Pattern) {
    $found = @(Get-InstalledPrograms | Where-Object { $_.DisplayName -like $Pattern })
    if ($found.Count -eq 0) { Write-Log "    '$Pattern' is not installed"; return }
    foreach ($prog in $found) {
        if ($prog.ProductCode) {
            $exe = 'msiexec.exe'
            $arguments = "/x $($prog.ProductCode) /qn /norestart"
        } else {
            $silent = $true
            if ($prog.QuietUninstallString) {
                $exe, $arguments = Split-CommandLine $prog.QuietUninstallString
            } else {
                $exe, $arguments = Split-CommandLine $prog.UninstallString
                $leaf = Split-Path $exe -Leaf
                if ($leaf -match '^unins\d+\.exe$') { $arguments = "$arguments /VERYSILENT /SUPPRESSMSGBOXES /NORESTART".Trim() }   # Inno Setup
                elseif ($leaf -match '^(uninst|uninstall|uninstaller)\.exe$') { $arguments = "$arguments /S".Trim() }          # NSIS
                else { $silent = $false }
            }
            if (-not $silent) {
                if (-not $script:LogBox) {
                    Write-Log "    SKIPPED $($prog.DisplayName): its uninstaller needs someone to click through it - use the GUI on this PC"
                    continue
                }
                Write-Log "    $($prog.DisplayName): its uninstaller window is opening - please click through it"
            }
        }
        Write-Log "    uninstalling $($prog.DisplayName)..."
        try {
            $proc = if ($arguments) { Start-Process -FilePath $exe -ArgumentList $arguments -PassThru } else { Start-Process -FilePath $exe -PassThru }
            $null = $proc.Handle   # keeps ExitCode readable after the process ends
            if (-not (Wait-ProcessUi $proc)) { Write-Log "    WARNING: uninstaller still running after 15 minutes - not waiting for it"; continue }
            switch ($proc.ExitCode) {
                { $_ -in 0, 1605 } { Write-Log "    removed $($prog.DisplayName)" }
                3010   { Write-Log "    removed $($prog.DisplayName) (restart needed to finish)" }
                1625   { Write-Log "    BLOCKED: untick 'Block installing .msi packages', Apply, then try again" }
                default { Write-Log "    WARNING: uninstaller for $($prog.DisplayName) exited with code $($proc.ExitCode)" }
            }
        } catch {
            Write-Log "    WARNING: could not run uninstaller for $($prog.DisplayName): $($_.Exception.Message)"
        }
    }
}

function Get-MsiProductName([string]$Path) {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $db = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($Path, 0))
    $view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @("SELECT Value FROM Property WHERE Property = 'ProductName'"))
    [void]$view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null)
    $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
    $name = $null
    if ($record) { $name = $record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, 1) }
    [void]$view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null)
    foreach ($o in @($record, $view, $db, $installer)) { if ($o) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($o) } }
    $name
}

# ---------------------------------------------------------------------------
# Lists for the pickers in "Add policy"
# ---------------------------------------------------------------------------
$ShellCriticalExes = 'explorer.exe', 'ApplicationFrameHost.exe', 'sihost.exe', 'ShellExperienceHost.exe',
                     'StartMenuExperienceHost.exe', 'SearchHost.exe', 'TextInputHost.exe', 'LockApp.exe',
                     'ShellHost.exe', 'winlogon.exe', 'dwm.exe', 'csrss.exe'

# MSI "advertised" shortcuts (e.g. Office 2016) point at an icon file, not the
# real program - ask Windows Installer where the program actually is.
function Resolve-AdvertisedShortcut([string]$LnkPath) {
    if (-not ('WPM.Msi' -as [type])) {
        Add-Type -Namespace WPM -Name Msi -MemberDefinition @'
[DllImport("msi.dll", CharSet = CharSet.Unicode)]
public static extern uint MsiGetShortcutTarget(string szShortcutTarget, System.Text.StringBuilder szProductCode, System.Text.StringBuilder szFeatureId, System.Text.StringBuilder szComponentCode);
[DllImport("msi.dll", CharSet = CharSet.Unicode)]
public static extern int MsiGetComponentPath(string szProduct, string szComponent, System.Text.StringBuilder lpPathBuf, ref uint pcchBuf);
'@
    }
    $product = New-Object Text.StringBuilder 39
    $feature = New-Object Text.StringBuilder 39
    $component = New-Object Text.StringBuilder 39
    if ([WPM.Msi]::MsiGetShortcutTarget($LnkPath, $product, $feature, $component) -ne 0) { return $null }
    $len = [uint32]1024
    $buf = New-Object Text.StringBuilder 1024
    $installState = [WPM.Msi]::MsiGetComponentPath($product.ToString(), $component.ToString(), $buf, [ref]$len)
    if ($installState -eq 3 -or $installState -eq 4) { return $buf.ToString() }   # installed locally / from source
    $null
}

function Get-StartMenuPrograms {
    $shell = New-Object -ComObject WScript.Shell
    $dirs = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs")
    $dirs += Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
             ForEach-Object { Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs' }
    $seen = @{}
    $rows = foreach ($d in $dirs) {
        if (-not (Test-Path -LiteralPath $d -ErrorAction SilentlyContinue)) { continue }
        foreach ($lnk in Get-ChildItem -LiteralPath $d -Recurse -Filter *.lnk -ErrorAction SilentlyContinue) {
            try { $target = $shell.CreateShortcut($lnk.FullName).TargetPath } catch { continue }
            if (-not $target -or $target -like "$env:windir\Installer\*") { $target = Resolve-AdvertisedShortcut $lnk.FullName }
            if ($target -notlike '*.exe') { continue }
            $exe = Split-Path $target -Leaf
            if ($exe -match '^unins' -or $lnk.BaseName -match 'uninstall' -or $ShellCriticalExes -contains $exe) { continue }
            if ($seen[$exe]) { continue }
            $seen[$exe] = $true
            [pscustomobject]@{ Cols = @($lnk.BaseName, $exe, $target); Value = $exe; Label = $lnk.BaseName }
        }
    }
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell)
    $rows | Sort-Object { $_.Cols[0] }
}

function Get-RunningPrograms {
    $seen = @{}
    $rows = foreach ($p in Get-Process | Where-Object { $_.MainWindowHandle -ne 0 -and $_.Path }) {
        $exe = Split-Path $p.Path -Leaf
        if ($seen[$exe] -or $ShellCriticalExes -contains $exe) { continue }
        $seen[$exe] = $true
        $label = if ($p.Description) { $p.Description } else { $p.ProcessName }
        [pscustomobject]@{ Cols = @($label, $exe, $p.MainWindowTitle, $p.Path); Value = $exe; Label = $label }
    }
    $rows | Sort-Object { $_.Cols[0] }
}

function Get-StoreAppChoices {
    $friendly = @{}
    try {
        Get-StartApps | Where-Object { $_.AppID -match '!' } | ForEach-Object {
            $family = $_.AppID.Split('!')[0]
            if (-not $friendly[$family]) { $friendly[$family] = $_.Name }
        }
    } catch { }
    $rows = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
        Where-Object { -not $_.IsFramework -and -not $_.NonRemovable -and $_.SignatureKind -ne 'System' } |
        Sort-Object Name -Unique |
        ForEach-Object {
            $label = if ($friendly[$_.PackageFamilyName]) { $friendly[$_.PackageFamilyName] } else { $_.Name }
            [pscustomobject]@{ Cols = @($label, $_.Name); Value = $_.Name; Label = $label }
        }
    $rows | Sort-Object { $_.Cols[0] }
}

# ---------------------------------------------------------------------------
# Generic action dispatch
# ---------------------------------------------------------------------------
function Test-IsUserAction($Action) {
    ($Action.type -eq 'blockApp') -or ($Action.type -eq 'registry' -and $Action.hive -eq 'HKCU')
}

function Get-PolicyScope($Policy) {
    $user = @(@($Policy.actions) | Where-Object { Test-IsUserAction $_ }).Count
    $machine = @($Policy.actions).Count - $user
    if ($user -and $machine) { 'PC + users' } elseif ($user) { 'Each user' } else { 'Whole PC' }
}

function Invoke-PolicyAction($Action, [bool]$Enable, [string]$UserRoot) {
    switch ($Action.type) {
        'registry' {
            $path = Get-ActionRegPath $Action $UserRoot
            if ($Enable) {
                Set-RegValue $path $Action.name $Action.valueType $Action.value
            } elseif ($null -ne $Action.revertValue) {
                Set-RegValue $path $Action.name $Action.valueType $Action.revertValue
            } else {
                Remove-RegValue $path $Action.name
            }
        }
        'blockApp' {
            if ($Enable) { Add-DisallowRun $UserRoot $Action.exe } else { Remove-DisallowRun $UserRoot $Action.exe }
        }
        'removeAppx' {
            if ($Enable) {
                Remove-StoreApp $Action.package
            } elseif (-not (Test-AppxInstalled $Action.package)) {
                Write-Log "    note: $($Action.package) stays uninstalled - reinstall it from Microsoft Store if needed"
            }
        }
        'uninstallProgram' {
            if ($Enable) {
                Uninstall-DesktopProgram $Action.displayName
            } elseif (-not (Test-ProgramInstalled $Action.displayName)) {
                Write-Log "    note: $($Action.displayName) stays uninstalled - reinstall it manually if needed"
            }
        }
        default { Write-Log "    unknown action type '$($Action.type)' - skipped" }
    }
}

function Test-PolicyAction($Action, [string]$UserRoot) {
    if ((Test-IsUserAction $Action) -and -not $UserRoot) { return $false }
    switch ($Action.type) {
        'registry' {
            $cur = Get-RegValue (Get-ActionRegPath $Action $UserRoot) $Action.name
            return ($null -ne $cur -and "$cur" -eq "$($Action.value)")
        }
        'blockApp'   { return [bool](Test-DisallowRun $UserRoot $Action.exe) }
        'removeAppx' { return $script:AppxListOk -and -not (Test-AppxInstalled $Action.package) }
        'uninstallProgram' { return -not (Test-ProgramInstalled $Action.displayName) }
    }
    $false
}

# ---------------------------------------------------------------------------
# Status: machine settings are read directly. User settings are read from the
# Default profile (all-users mode) or HKCU (current-user mode).
# ---------------------------------------------------------------------------
function Get-AllPolicyStatus {
    Update-InstalledCache
    $mounted = $null
    if ($script:Config.settings.userScope -eq 'CurrentUser') {
        $mounted = [pscustomobject]@{ Root = 'Registry::HKEY_CURRENT_USER'; Mount = $null }
    } else {
        $def = Get-UserHiveTargets | Where-Object { $_.Sid -eq 'DEFAULT' } | Select-Object -First 1
        if ($def) { $mounted = Mount-UserHive $def }
        if (-not $mounted) { Write-Log 'WARNING: could not open the Default profile - per-user status unknown' }
    }
    $root = if ($mounted) { $mounted.Root } else { $null }

    $status = @{}
    try {
        foreach ($p in $script:Config.policies) {
            $actions = @($p.actions)
            $ok = 0
            foreach ($a in $actions) { if (Test-PolicyAction $a $root) { $ok++ } }
            $status[$p.id] = if ($actions.Count -eq 0) { 'No actions' }
                             elseif ($ok -eq $actions.Count) { 'Applied' }
                             elseif ($ok -eq 0) { 'Not applied' }
                             else { 'Partial' }
        }
    } finally {
        Dismount-UserHive $mounted
    }
    $status
}

# ---------------------------------------------------------------------------
# Apply. $Desired = @{ policyId = $true/$false }. Ticked policies are enforced,
# unticked ones are reverted.
# ---------------------------------------------------------------------------
function Invoke-ApplyPolicies([hashtable]$Desired, $Policies = $script:Config.policies) {
    $Policies = @($Policies)
    $script:ProvisionedAppx = $null
    Update-InstalledCache
    $onCount = @($Policies | Where-Object { $Desired[$_.id] }).Count
    Write-Log "===== Applying: $onCount ON, $($Policies.Count - $onCount) OFF ====="

    # 1) Whole-PC actions
    foreach ($p in $Policies) {
        $enable = [bool]$Desired[$p.id]
        $machineActions = @(@($p.actions) | Where-Object { -not (Test-IsUserAction $_) })
        if ($machineActions.Count -eq 0) { continue }
        Write-Log ("  [{0}] {1}" -f $(if ($enable) { 'ON ' } else { 'OFF' }), $p.name)
        foreach ($a in $machineActions) {
            try { Invoke-PolicyAction $a $enable $null } catch { Write-Log "    ERROR: $($_.Exception.Message)" }
        }
    }

    # 2) Per-user actions, one profile hive at a time
    $userPolicies = @($Policies | Where-Object { @(@($_.actions) | Where-Object { Test-IsUserAction $_ }).Count -gt 0 })
    if ($userPolicies.Count -gt 0) {
        foreach ($t in Get-UserHiveTargets) {
            $mounted = Mount-UserHive $t
            if (-not $mounted) { Write-Log "  User '$($t.Name)': profile not available - skipped"; continue }
            if ($t.Excluded) { Write-Log "  User '$($t.Name)': never-restrict account - removing any restrictions" }
            else { Write-Log "  User '$($t.Name)': updating user settings" }
            try {
                foreach ($p in $userPolicies) {
                    $enable = [bool]$Desired[$p.id] -and -not $t.Excluded
                    foreach ($a in @($p.actions)) {
                        if (-not (Test-IsUserAction $a)) { continue }
                        try { Invoke-PolicyAction $a $enable $mounted.Root } catch { Write-Log "    ERROR ($($p.name)): $($_.Exception.Message)" }
                    }
                }
            } finally {
                Dismount-UserHive $mounted
            }
        }
    }
    Write-Log '===== Done. Users should sign out and back in (or restart Explorer) to see every change. ====='
}

function Restart-Explorer {
    Write-Log 'Restarting Explorer...'
    Get-Process explorer -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 3
    if (-not (Get-Process explorer -ErrorAction SilentlyContinue)) { Start-Process explorer.exe }
}

# ---------------------------------------------------------------------------
# Install on this PC: copy to Program Files (admin-only) and re-apply the saved
# ticks at every startup via a SYSTEM scheduled task. Survives disk imaging.
# ---------------------------------------------------------------------------
$InstallDir = Join-Path $env:ProgramFiles 'WinPolicyManager'
$TaskName = 'Windows Policy Manager - reapply'

function Test-Installed {
    [bool](Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
}

function Test-RunningFromInstallDir {
    $ScriptDir.TrimEnd('\') -eq $InstallDir.TrimEnd('\')
}

# Keeps the installed copy's config in step when the GUI runs from elsewhere
function Sync-InstalledConfig {
    if ((Test-RunningFromInstallDir) -or -not (Test-Installed)) { return }
    Copy-Item -LiteralPath $ConfigPath -Destination (Join-Path $InstallDir 'policies.json') -Force
    Write-Log "Updated the installed copy in $InstallDir"
}

function Install-OnThisPC {
    if (-not (Test-RunningFromInstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        foreach ($f in 'WinPolicyManager.ps1', 'Start Policy Manager.bat', 'Apply Silently.bat', 'README.md') {
            $src = Join-Path $ScriptDir $f
            if (Test-Path -LiteralPath $src) { Copy-Item -LiteralPath $src -Destination $InstallDir -Force }
        }
        Copy-Item -LiteralPath $ConfigPath -Destination (Join-Path $InstallDir 'policies.json') -Force
    }
    $ps1 = Join-Path $InstallDir 'WinPolicyManager.ps1'
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ps1`" -Silent"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $trigger.Delay = 'PT2M'
    $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $taskSettings `
        -Description 'Re-applies the restrictions ticked in Windows Policy Manager at every startup.' -Force | Out-Null
    Write-Log "Installed in $InstallDir - the ticked policies will be re-applied at every startup."
}

function Uninstall-FromThisPC {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    if (Test-RunningFromInstallDir) {
        Write-Log "Startup task removed. Close this window and delete $InstallDir to finish."
    } else {
        Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "Uninstalled: startup task and $InstallDir removed. Restrictions already applied stay as they are."
    }
}

# ---------------------------------------------------------------------------
# Silent mode (no GUI)
# ---------------------------------------------------------------------------
if ($Silent) {
    try {
        Read-Config
        $desired = @{}
        foreach ($p in $script:Config.policies) { $desired[$p.id] = [bool]$p.enabled }
        Invoke-ApplyPolicies $desired
        exit 0
    } catch {
        Write-Log "FATAL: $($_.Exception.Message)"
        exit 1
    }
}

# ===========================================================================
# GUI
# ===========================================================================
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

function Show-Message([string]$Text, [string]$Icon = 'Information', [string]$Buttons = 'OK') {
    [System.Windows.Forms.MessageBox]::Show($Text, 'Windows Policy Manager', $Buttons, $Icon)
}

try { Read-Config } catch { Show-Message "Could not read the config file:`n`n$($_.Exception.Message)" 'Error' | Out-Null; exit 1 }

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Windows Policy Manager'
$form.Size = New-Object System.Drawing.Size(1220, 780)
$form.MinimumSize = New-Object System.Drawing.Size(850, 550)
$form.StartPosition = 'CenterScreen'
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

# ---- Header -----------------------------------------------------------------
$header = New-Object System.Windows.Forms.Panel
$header.Dock = 'Top'
$header.Height = 92

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = 'Windows Policy Manager'
$lblTitle.Font = New-Object System.Drawing.Font('Segoe UI', 14, [System.Drawing.FontStyle]::Bold)
$lblTitle.Location = New-Object System.Drawing.Point(12, 6)
$lblTitle.AutoSize = $true
$header.Controls.Add($lblTitle)

$lblHelp = New-Object System.Windows.Forms.Label
$lblHelp.Text = "Tick = apply the restriction, untick = revert it. Then click Apply.   Config: $ConfigPath"
$lblHelp.ForeColor = [System.Drawing.Color]::DimGray
$lblHelp.Location = New-Object System.Drawing.Point(14, 38)
$lblHelp.AutoSize = $true
$header.Controls.Add($lblHelp)

$lblScope = New-Object System.Windows.Forms.Label
$lblScope.Text = 'User restrictions apply to:'
$lblScope.Location = New-Object System.Drawing.Point(14, 64)
$lblScope.AutoSize = $true
$header.Controls.Add($lblScope)

$cmbScope = New-Object System.Windows.Forms.ComboBox
$cmbScope.DropDownStyle = 'DropDownList'
$cmbScope.Location = New-Object System.Drawing.Point(170, 60)
$cmbScope.Width = 260
[void]$cmbScope.Items.Add('All users on this PC (existing + new)')
[void]$cmbScope.Items.Add("Only me ($CurrentUser)")
$cmbScope.SelectedIndex = if ($script:Config.settings.userScope -eq 'CurrentUser') { 1 } else { 0 }
$header.Controls.Add($cmbScope)

$btnExclude = New-Object System.Windows.Forms.Button
$btnExclude.Text = 'Never-restrict accounts...'
$btnExclude.Location = New-Object System.Drawing.Point(445, 58)
$btnExclude.Size = New-Object System.Drawing.Size(180, 27)
$btnExclude.Enabled = ($cmbScope.SelectedIndex -eq 0)
$header.Controls.Add($btnExclude)

$MyProfileName = Get-MyProfileName
$chkExcludeMe = New-Object System.Windows.Forms.CheckBox
$chkExcludeMe.Text = "Don't restrict me ($MyProfileName)"
$chkExcludeMe.Location = New-Object System.Drawing.Point(640, 62)
$chkExcludeMe.AutoSize = $true
$chkExcludeMe.Checked = @($script:Config.settings.excludeUsers) -contains $MyProfileName
$chkExcludeMe.Enabled = ($cmbScope.SelectedIndex -eq 0)
$header.Controls.Add($chkExcludeMe)

# ---- Policy list ------------------------------------------------------------
$lv = New-Object System.Windows.Forms.ListView
$lv.View = 'Details'
$lv.CheckBoxes = $true
$lv.FullRowSelect = $true
$lv.GridLines = $true
$lv.HideSelection = $false
$lv.ShowItemToolTips = $true
$lv.Dock = 'Fill'
[void]$lv.Columns.Add('Policy', 340)
[void]$lv.Columns.Add('Current status', 105)
[void]$lv.Columns.Add('Applies to', 90)
[void]$lv.Columns.Add('Description', 580)

# ---- Bottom: buttons + log --------------------------------------------------
$bottom = New-Object System.Windows.Forms.Panel
$bottom.Dock = 'Bottom'
$bottom.Height = 210

$buttons = New-Object System.Windows.Forms.FlowLayoutPanel
$buttons.Dock = 'Top'
$buttons.Height = 44
$buttons.Padding = New-Object System.Windows.Forms.Padding(6, 6, 6, 0)

function New-Button([string]$Text, [int]$Width = 110) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $Text
    $b.Width = $Width
    $b.Height = 30
    $buttons.Controls.Add($b)
    $b
}
$btnApply    = New-Button 'Apply' 100
$btnApply.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$btnRefresh  = New-Button 'Reload / Refresh' 120
$btnAll      = New-Button 'Tick all' 80
$btnNone     = New-Button 'Untick all' 80
$btnAdd      = New-Button 'Add policy...' 105
$btnRemove   = New-Button 'Remove policy' 110
$btnEdit     = New-Button 'Edit config file' 120
$btnExplorer = New-Button 'Restart Explorer' 120
$btnLog      = New-Button 'Open log' 80
$btnInstall  = New-Button 'Install on this PC...' 140

$txtLog = New-Object System.Windows.Forms.TextBox
$txtLog.Multiline = $true
$txtLog.ReadOnly = $true
$txtLog.ScrollBars = 'Vertical'
$txtLog.Dock = 'Fill'
$txtLog.Font = New-Object System.Drawing.Font('Consolas', 9)
$txtLog.BackColor = [System.Drawing.Color]::White

$bottom.Controls.Add($txtLog)
$bottom.Controls.Add($buttons)
$txtLog.BringToFront()

$form.Controls.Add($lv)
$form.Controls.Add($header)
$form.Controls.Add($bottom)
$lv.BringToFront()   # Fill control must be docked last

# ---- List population --------------------------------------------------------
function Update-PolicyList([hashtable]$Status) {
    $lv.BeginUpdate()
    $lv.Items.Clear()
    $lv.Groups.Clear()
    $groups = @{}
    foreach ($p in $script:Config.policies) {
        $cat = if ($p.category) { [string]$p.category } else { 'Other' }
        if (-not $groups.ContainsKey($cat)) {
            $g = New-Object System.Windows.Forms.ListViewGroup($cat, $cat)
            [void]$lv.Groups.Add($g)
            $groups[$cat] = $g
        }
        $st = if ($Status -and $Status[$p.id]) { $Status[$p.id] } else { 'Unknown' }
        $item = New-Object System.Windows.Forms.ListViewItem([string]$p.name, $groups[$cat])
        [void]$item.SubItems.Add($st)
        [void]$item.SubItems.Add((Get-PolicyScope $p))
        [void]$item.SubItems.Add([string]$p.description)
        $item.Tag = $p.id
        $item.ToolTipText = [string]$p.description
        $item.UseItemStyleForSubItems = $false
        $item.SubItems[1].ForeColor = switch ($st) {
            'Applied' { [System.Drawing.Color]::ForestGreen }
            'Partial' { [System.Drawing.Color]::DarkOrange }
            default   { [System.Drawing.Color]::Gray }
        }
        $item.Checked = ($st -eq 'Applied' -or $st -eq 'Partial')
        [void]$lv.Items.Add($item)
    }
    $lv.EndUpdate()
}

function Update-StatusView {
    $form.Cursor = 'WaitCursor'
    try {
        Write-Log 'Reading current state of this PC...'
        $status = Get-AllPolicyStatus
        Update-PolicyList $status
        $applied = @($status.Values | Where-Object { $_ -eq 'Applied' }).Count
        Write-Log "Ready. $($script:Config.policies.Count) policies loaded, $applied currently applied."
    } finally {
        $form.Cursor = 'Default'
    }
}

function Get-DesiredFromList {
    $desired = @{}
    foreach ($it in $lv.Items) { $desired[[string]$it.Tag] = $it.Checked }
    $desired
}

# ---- Add-policy dialog ------------------------------------------------------
function New-DialogLabel($Parent, [string]$Text, [int]$X, [int]$Y) {
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $Text
    $l.Location = New-Object System.Drawing.Point($X, $Y)
    $l.AutoSize = $true
    $Parent.Controls.Add($l)
}

function New-DialogControl($Parent, [string]$TypeName, [int]$X, [int]$Y, [int]$Width) {
    $c = New-Object "System.Windows.Forms.$TypeName"
    $c.Location = New-Object System.Drawing.Point($X, $Y)
    $c.Width = $Width
    $Parent.Controls.Add($c)
    $c
}

function New-DialogButton($Parent, [string]$Text, [int]$X, [int]$Y, [int]$Width) {
    $b = New-DialogControl $Parent 'Button' $X $Y $Width
    $b.Text = $Text
    $b.Height = 30
    $b
}

function Get-TextLines($TextBox) {
    @($TextBox.Text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Add-TextLines($TextBox, [string[]]$Values) {
    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($l in (Get-TextLines $TextBox)) { $lines.Add($l) }
    foreach ($v in $Values) { if ($v -and -not ($lines -contains $v)) { $lines.Add($v) } }
    $TextBox.Text = $lines -join "`r`n"
}

# Searchable, tickable list. $Rows = objects with .Cols (string[]), .Value and .Label.
# Returns the ticked rows.
function Show-PickerDialog([string]$Title, [string]$Hint, [string[]]$Columns, [int[]]$Widths, $Rows, $Owner) {
    $Rows = @($Rows)
    $state = @{ Checked = @{}; Filling = $false; Result = @() }

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = $Title
    $dlg.Size = New-Object System.Drawing.Size(860, 560)
    $dlg.MinimizeBox = $false
    $dlg.StartPosition = 'CenterParent'
    $dlg.Font = $form.Font

    $top = New-Object System.Windows.Forms.Panel
    $top.Dock = 'Top'
    $top.Height = 66
    if ($Rows.Count -eq 0) { $Hint = 'Nothing found.' }
    New-DialogLabel $top $Hint 10 8
    New-DialogLabel $top 'Search:' 10 38
    $txtSearch = New-DialogControl $top 'TextBox' 65 35 320

    $list = New-Object System.Windows.Forms.ListView
    $list.View = 'Details'
    $list.CheckBoxes = $true
    $list.FullRowSelect = $true
    $list.GridLines = $true
    $list.Dock = 'Fill'
    for ($i = 0; $i -lt $Columns.Count; $i++) { [void]$list.Columns.Add($Columns[$i], $Widths[$i]) }

    $bottomBar = New-Object System.Windows.Forms.FlowLayoutPanel
    $bottomBar.Dock = 'Bottom'
    $bottomBar.Height = 44
    $bottomBar.FlowDirection = 'RightToLeft'
    $bottomBar.Padding = New-Object System.Windows.Forms.Padding(6)
    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = 'Cancel'; $btnCancel.Size = New-Object System.Drawing.Size(90, 30)
    $btnCancel.DialogResult = 'Cancel'
    $btnOk = New-Object System.Windows.Forms.Button
    $btnOk.Text = 'Use ticked'; $btnOk.Size = New-Object System.Drawing.Size(100, 30)
    $bottomBar.Controls.AddRange(@($btnCancel, $btnOk))

    $dlg.Controls.Add($list)
    $dlg.Controls.Add($top)
    $dlg.Controls.Add($bottomBar)
    $list.BringToFront()
    $dlg.CancelButton = $btnCancel

    $fill = {
        $state.Filling = $true
        $list.BeginUpdate()
        $list.Items.Clear()
        $filter = $txtSearch.Text.Trim()
        foreach ($r in $Rows) {
            if ($filter -and -not (@($r.Cols) | Where-Object { ([string]$_).IndexOf($filter, [StringComparison]::OrdinalIgnoreCase) -ge 0 })) { continue }
            $item = New-Object System.Windows.Forms.ListViewItem([string]$r.Cols[0])
            for ($i = 1; $i -lt $r.Cols.Count; $i++) { [void]$item.SubItems.Add([string]$r.Cols[$i]) }
            $item.Tag = $r.Value
            $item.Checked = $state.Checked.ContainsKey($r.Value)
            [void]$list.Items.Add($item)
        }
        $list.EndUpdate()
        $state.Filling = $false
    }

    $list.Add_ItemChecked({
        if ($state.Filling) { return }
        if ($_.Item.Checked) { $state.Checked[$_.Item.Tag] = $true } else { $state.Checked.Remove($_.Item.Tag) }
    })
    $txtSearch.Add_TextChanged({ & $fill })
    $btnOk.Add_Click({
        $state.Result = @($Rows | Where-Object { $state.Checked.ContainsKey($_.Value) })
        $dlg.DialogResult = 'OK'
        $dlg.Close()
    })

    & $fill
    [void]$dlg.ShowDialog($Owner)
    $dlg.Dispose()
    $state.Result
}

function Show-AddPolicyDialog {
    $result = @{ Policy = $null }

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = 'Add policy'
    $dlg.Size = New-Object System.Drawing.Size(660, 620)
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MaximizeBox = $false
    $dlg.MinimizeBox = $false
    $dlg.StartPosition = 'CenterParent'
    $dlg.Font = $form.Font

    New-DialogLabel $dlg 'What should it do?' 15 18
    $cmbType = New-DialogControl $dlg 'ComboBox' 140 15 480
    $cmbType.DropDownStyle = 'DropDownList'
    [void]$cmbType.Items.Add('Block a program from running')
    [void]$cmbType.Items.Add('Uninstall a Store app (Solitaire, Xbox, ...)')
    [void]$cmbType.Items.Add('Uninstall a desktop program (installed from .exe or .msi)')
    [void]$cmbType.Items.Add('Set a registry value (advanced)')

    New-DialogLabel $dlg 'Name' 15 53
    $txtName = New-DialogControl $dlg 'TextBox' 140 50 480

    New-DialogLabel $dlg 'Category' 15 88
    $cmbCat = New-DialogControl $dlg 'ComboBox' 140 85 480
    foreach ($c in @($script:Config.policies | ForEach-Object { $_.category } | Where-Object { $_ } | Sort-Object -Unique)) { [void]$cmbCat.Items.Add($c) }

    New-DialogLabel $dlg 'Description' 15 123
    $txtDesc = New-DialogControl $dlg 'TextBox' 140 120 480
    $txtDesc.Multiline = $true
    $txtDesc.Height = 44

    $panelLocation = New-Object System.Drawing.Point(5, 175)
    $panelSize = New-Object System.Drawing.Size(640, 350)

    # Fills the Name box from the picked items if the user hasn't typed one
    $suggestName = {
        param([string]$Verb, $Labels)
        $Labels = @($Labels | Where-Object { $_ })
        if ($txtName.Text.Trim() -or $Labels.Count -eq 0) { return }
        $txtName.Text = "$Verb " + (($Labels | Select-Object -First 3) -join ', ')
        if ($Labels.Count -gt 3) { $txtName.Text += ' ...' }
    }

    $newMultiline = {
        param($Parent)
        $t = New-DialogControl $Parent 'TextBox' 10 30 610
        $t.Multiline = $true
        $t.ScrollBars = 'Vertical'
        $t.Height = 80
        $t
    }

    # -- panel 0: block a program
    $pnlExe = New-Object System.Windows.Forms.Panel
    $pnlExe.Location = $panelLocation; $pnlExe.Size = $panelSize
    New-DialogLabel $pnlExe 'Program file names to block (one per line). Use the buttons below to pick them:' 10 8
    $txtExe = & $newMultiline $pnlExe
    $btnPickStart   = New-DialogButton $pnlExe 'Pick from Start menu...' 10 118 190
    $btnPickRunning = New-DialogButton $pnlExe 'Pick from running apps...' 210 118 190
    $btnBrowseExe   = New-DialogButton $pnlExe 'Browse for file...' 410 118 150
    New-DialogLabel $pnlExe ("Easiest way: open the program you want to block, then click 'Pick from running apps'.`n`n" +
        "The program is blocked when started from Start, the taskbar, desktop or File Explorer,`n" +
        "for every user (except excluded ones). Store apps (Solitaire etc.) should use 'Uninstall a Store app'.") 10 165

    # -- panel 1: Store app
    $pnlAppx = New-Object System.Windows.Forms.Panel
    $pnlAppx.Location = $panelLocation; $pnlAppx.Size = $panelSize
    New-DialogLabel $pnlAppx 'Store app package names (one per line, * wildcards allowed):' 10 8
    $txtAppx = & $newMultiline $pnlAppx
    $btnPickAppx = New-DialogButton $pnlAppx 'Pick from installed Store apps...' 10 118 240
    New-DialogLabel $pnlAppx ("Uninstalls the app for every user and stops it being installed for new users.`n" +
        "Unticking the policy later does NOT reinstall it (use Microsoft Store).") 10 165

    # -- panel 2: desktop program
    $pnlProg = New-Object System.Windows.Forms.Panel
    $pnlProg.Location = $panelLocation; $pnlProg.Size = $panelSize
    New-DialogLabel $pnlProg 'Program names as shown in Settings > Apps (one per line, * wildcards allowed):' 10 8
    $txtProg = & $newMultiline $pnlProg
    $btnPickProg = New-DialogButton $pnlProg 'Pick from installed programs...' 10 118 230
    $btnBrowseMsi = New-DialogButton $pnlProg 'Read name from .msi file...' 250 118 210
    New-DialogLabel $pnlProg ("Uninstalls the program for the whole PC. Version numbers are replaced with * so the`n" +
        "policy still matches after the program updates.`n`n" +
        "Programs installed from .msi always uninstall silently. Some .exe-based programs show`n" +
        "their own uninstall window that needs clicking through (silent mode skips those).`n`n" +
        "To stop people installing .msi files in the first place, tick 'Block installing .msi packages'.") 10 165

    # -- panel 3: registry
    $pnlReg = New-Object System.Windows.Forms.Panel
    $pnlReg.Location = $panelLocation; $pnlReg.Size = $panelSize
    New-DialogLabel $pnlReg 'Hive' 10 13
    $cmbHive = New-DialogControl $pnlReg 'ComboBox' 135 10 480
    $cmbHive.DropDownStyle = 'DropDownList'
    [void]$cmbHive.Items.Add('HKLM  (whole PC)'); [void]$cmbHive.Items.Add('HKCU  (every user)'); $cmbHive.SelectedIndex = 0
    New-DialogLabel $pnlReg 'Key path' 10 48
    $txtKey = New-DialogControl $pnlReg 'TextBox' 135 45 480
    New-DialogLabel $pnlReg 'Value name' 10 83
    $txtValName = New-DialogControl $pnlReg 'TextBox' 135 80 480
    New-DialogLabel $pnlReg 'Value type' 10 118
    $cmbValType = New-DialogControl $pnlReg 'ComboBox' 135 115 480
    $cmbValType.DropDownStyle = 'DropDownList'
    foreach ($t in 'DWord', 'String', 'ExpandString', 'QWord') { [void]$cmbValType.Items.Add($t) }
    $cmbValType.SelectedIndex = 0
    New-DialogLabel $pnlReg 'Value when ON' 10 153
    $txtValOn = New-DialogControl $pnlReg 'TextBox' 135 150 480
    New-DialogLabel $pnlReg 'Value when OFF' 10 188
    $txtValOff = New-DialogControl $pnlReg 'TextBox' 135 185 480
    New-DialogLabel $pnlReg ("Leave 'Value when OFF' empty to delete the value when unticked.`n" +
        "You can paste a full path like HKEY_CURRENT_USER\Software\... into Key path.") 10 222

    $panels = @($pnlExe, $pnlAppx, $pnlProg, $pnlReg)
    $dlg.Controls.AddRange($panels)

    $cmbType.Add_SelectedIndexChanged({
        for ($i = 0; $i -lt $panels.Count; $i++) { $panels[$i].Visible = ($cmbType.SelectedIndex -eq $i) }
    })
    $cmbType.SelectedIndex = 0

    # -- picker buttons
    $btnPickStart.Add_Click({
        $dlg.Cursor = 'WaitCursor'
        $rows = Get-StartMenuPrograms
        $dlg.Cursor = 'Default'
        $picked = @(Show-PickerDialog 'Programs in the Start menu' 'Tick the programs to block.' @('Program', 'File name', 'Location') @(240, 160, 420) $rows $dlg)
        if ($picked.Count) {
            Add-TextLines $txtExe @($picked | ForEach-Object { $_.Value })
            & $suggestName 'Block' @($picked | ForEach-Object { $_.Label })
        }
    })

    $btnPickRunning.Add_Click({
        $rows = Get-RunningPrograms
        $picked = @(Show-PickerDialog 'Running programs' 'Programs that currently have a window open. Tick the ones to block.' @('Program', 'File name', 'Window title', 'Location') @(200, 140, 200, 280) $rows $dlg)
        if ($picked.Count) {
            Add-TextLines $txtExe @($picked | ForEach-Object { $_.Value })
            & $suggestName 'Block' @($picked | ForEach-Object { $_.Label })
        }
    })

    $btnBrowseExe.Add_Click({
        $ofd = New-Object System.Windows.Forms.OpenFileDialog
        $ofd.Title = 'Choose the program to block'
        $ofd.Filter = 'Programs and installers (*.exe;*.msi)|*.exe;*.msi|All files (*.*)|*.*'
        $ofd.InitialDirectory = $env:ProgramFiles
        if ($ofd.ShowDialog($dlg) -ne 'OK') { return }
        if ($ofd.FileName -like '*.msi') {
            # An .msi is an installer, not a program: switch to uninstalling what it installs
            $product = $null
            try { $product = Get-MsiProductName $ofd.FileName } catch { }
            if (-not $product) { Show-Message 'Could not read the program name from that .msi file.' 'Warning' | Out-Null; return }
            Show-Message ("That file is an installer (.msi), not a program, so it can't be blocked from running.`n`n" +
                "It installs: $product`n`nSwitching to 'Uninstall a desktop program' for it. To stop people installing .msi files, " +
                "also tick the 'Block installing .msi packages' policy.") | Out-Null
            $cmbType.SelectedIndex = 2
            Add-TextLines $txtProg @(Get-NamePattern $product)
            & $suggestName 'Remove' @($product)
            return
        }
        $leaf = Split-Path $ofd.FileName -Leaf
        Add-TextLines $txtExe @($leaf)
        $info = (Get-Item -LiteralPath $ofd.FileName).VersionInfo
        & $suggestName 'Block' @($(if ($info.FileDescription) { $info.FileDescription } else { $leaf }))
    })

    $btnPickAppx.Add_Click({
        $dlg.Cursor = 'WaitCursor'
        $rows = Get-StoreAppChoices
        $dlg.Cursor = 'Default'
        $picked = @(Show-PickerDialog 'Installed Store apps' 'Tick the apps to uninstall.' @('App', 'Package name') @(320, 460) $rows $dlg)
        if ($picked.Count) {
            Add-TextLines $txtAppx @($picked | ForEach-Object { $_.Value })
            & $suggestName 'Remove' @($picked | ForEach-Object { $_.Label })
        }
    })

    $btnPickProg.Add_Click({
        $dlg.Cursor = 'WaitCursor'
        $rows = Get-InstalledPrograms | Sort-Object DisplayName | ForEach-Object {
            $kind = if ($_.ProductCode) { 'MSI' } else { 'EXE' }
            [pscustomobject]@{ Cols = @($_.DisplayName, $_.Publisher, $_.Version, $kind); Value = (Get-NamePattern $_.DisplayName); Label = $_.DisplayName }
        }
        $dlg.Cursor = 'Default'
        $picked = @(Show-PickerDialog 'Installed programs' 'Same list as Settings > Apps. Tick the programs to uninstall.' @('Program', 'Publisher', 'Version', 'Installer') @(340, 220, 140, 70) $rows $dlg)
        if ($picked.Count) {
            Add-TextLines $txtProg @($picked | ForEach-Object { $_.Value })
            & $suggestName 'Remove' @($picked | ForEach-Object { $_.Label })
        }
    })

    $btnBrowseMsi.Add_Click({
        $ofd = New-Object System.Windows.Forms.OpenFileDialog
        $ofd.Title = 'Choose the .msi installer of the program to remove'
        $ofd.Filter = 'Windows Installer packages (*.msi)|*.msi'
        if ($ofd.ShowDialog($dlg) -ne 'OK') { return }
        $product = $null
        try { $product = Get-MsiProductName $ofd.FileName } catch { }
        if (-not $product) { Show-Message 'Could not read the program name from that .msi file.' 'Warning' | Out-Null; return }
        Add-TextLines $txtProg @(Get-NamePattern $product)
        & $suggestName 'Remove' @($product)
    })

    # -- OK / Cancel
    $btnOk = New-DialogButton $dlg 'Add' 430 535 90
    $btnCancel = New-DialogButton $dlg 'Cancel' 530 535 90
    $btnCancel.DialogResult = 'Cancel'
    $dlg.CancelButton = $btnCancel

    $btnOk.Add_Click({
        $name = $txtName.Text.Trim()
        if (-not $name) { Show-Message 'Please enter a name (or pick something - the name fills in automatically).' 'Warning' | Out-Null; return }

        $actions = @()
        switch ($cmbType.SelectedIndex) {
            0 {
                foreach ($exe in (Get-TextLines $txtExe)) {
                    if ($exe -like '*.msi') {
                        Show-Message "'$exe' is an installer, not a program. Use 'Uninstall a desktop program' (Read name from .msi file) instead." 'Warning' | Out-Null
                        return
                    }
                    if ($exe -notlike '*.exe') { $exe += '.exe' }
                    if ($ShellCriticalExes -contains $exe) {
                        Show-Message "'$exe' is part of Windows itself - blocking it would break the desktop." 'Warning' | Out-Null
                        return
                    }
                    $actions += [pscustomobject]@{ type = 'blockApp'; exe = $exe }
                }
                if (-not $actions) { Show-Message 'Pick or type at least one program.' 'Warning' | Out-Null; return }
            }
            1 {
                foreach ($pkg in (Get-TextLines $txtAppx)) { $actions += [pscustomobject]@{ type = 'removeAppx'; package = $pkg } }
                if (-not $actions) { Show-Message 'Pick or type at least one Store app.' 'Warning' | Out-Null; return }
            }
            2 {
                foreach ($prog in (Get-TextLines $txtProg)) { $actions += [pscustomobject]@{ type = 'uninstallProgram'; displayName = $prog } }
                if (-not $actions) { Show-Message 'Pick or type at least one program.' 'Warning' | Out-Null; return }
            }
            3 {
                $hive = if ($cmbHive.SelectedIndex -eq 0) { 'HKLM' } else { 'HKCU' }
                $keyPath = $txtKey.Text.Trim().Trim('\')
                if ($keyPath -match '^(HKEY_LOCAL_MACHINE|HKLM):?\\(.+)$') { $hive = 'HKLM'; $keyPath = $Matches[2] }
                elseif ($keyPath -match '^(HKEY_CURRENT_USER|HKCU):?\\(.+)$') { $hive = 'HKCU'; $keyPath = $Matches[2] }
                $valName = $txtValName.Text.Trim()
                $valType = [string]$cmbValType.SelectedItem
                if (-not $keyPath -or -not $valName -or $txtValOn.Text -eq '') {
                    Show-Message 'Key path, value name and "Value when ON" are required.' 'Warning' | Out-Null; return
                }
                $convert = {
                    param($text)
                    if ($valType -eq 'DWord') { [int]$text } elseif ($valType -eq 'QWord') { [long]$text } else { $text }
                }
                try {
                    $action = [ordered]@{ type = 'registry'; hive = $hive; path = $keyPath; name = $valName; valueType = $valType; value = (& $convert $txtValOn.Text) }
                    if ($txtValOff.Text -ne '') { $action.revertValue = (& $convert $txtValOff.Text) }
                } catch {
                    Show-Message "The value is not a valid number for type $valType." 'Warning' | Out-Null; return
                }
                $actions += [pscustomobject]$action
            }
        }

        $baseId = ($name.ToLower() -replace '[^a-z0-9]+', '-').Trim('-')
        if (-not $baseId) { $baseId = 'policy' }
        $id = $baseId; $n = 2
        while (@($script:Config.policies | Where-Object { $_.id -eq $id }).Count) { $id = "$baseId-$n"; $n++ }

        $category = $cmbCat.Text.Trim()
        if (-not $category) { $category = 'Custom' }
        $result.Policy = [pscustomobject][ordered]@{
            id = $id; name = $name; category = $category
            description = $txtDesc.Text.Trim(); enabled = $false; actions = $actions
        }
        $dlg.DialogResult = 'OK'
        $dlg.Close()
    })

    [void]$dlg.ShowDialog($form)
    $dlg.Dispose()
    $result.Policy
}

# ---- Button handlers --------------------------------------------------------
$btnApply.Add_Click({
    $desired = Get-DesiredFromList
    $on = @($desired.Values | Where-Object { $_ }).Count
    $off = $desired.Count - $on
    $neverRestrict = @($script:Config.settings.excludeUsers)
    $who = if ($script:Config.settings.userScope -eq 'CurrentUser') { "only $CurrentUser" }
           elseif ($neverRestrict.Count) { "all users except $($neverRestrict -join ', ')" }
           else { 'all users' }
    $answer = Show-Message "Apply $on policies and revert $off?`n`nUser restrictions go to: $who." 'Question' 'YesNo'
    if ($answer -ne 'Yes') { return }

    $form.Cursor = 'WaitCursor'
    $buttons.Enabled = $false
    try {
        foreach ($p in $script:Config.policies) { Set-PolicyEnabled $p $desired[$p.id] }
        Save-Config
        Sync-InstalledConfig
        Invoke-ApplyPolicies $desired
    } catch {
        Write-Log "ERROR: $($_.Exception.Message)"
    } finally {
        $buttons.Enabled = $true
        $form.Cursor = 'Default'
    }
    if ((Show-Message "Done.`n`nRestart Explorer now so taskbar / Start / File Explorer changes show immediately?`n(Open File Explorer windows will close.)" 'Question' 'YesNo') -eq 'Yes') {
        Restart-Explorer
    }
    Update-StatusView
})

$btnRefresh.Add_Click({
    try {
        Read-Config
        $cmbScope.SelectedIndex = if ($script:Config.settings.userScope -eq 'CurrentUser') { 1 } else { 0 }
        $chkExcludeMe.Checked = @($script:Config.settings.excludeUsers) -contains $MyProfileName
        Update-StatusView
    } catch {
        Show-Message "Could not read the config file:`n`n$($_.Exception.Message)" 'Error' | Out-Null
    }
})

$btnAll.Add_Click({ foreach ($it in $lv.Items) { $it.Checked = $true } })
$btnNone.Add_Click({ foreach ($it in $lv.Items) { $it.Checked = $false } })

$btnAdd.Add_Click({
    $policy = Show-AddPolicyDialog
    if (-not $policy) { return }
    $script:Config.policies = @($script:Config.policies) + $policy
    Save-Config
    Write-Log "Added policy '$($policy.name)'. Tick it and click Apply to enforce it."
    Update-StatusView
})

$btnRemove.Add_Click({
    if ($lv.SelectedItems.Count -eq 0) { Show-Message 'Select (highlight) a policy in the list first.' | Out-Null; return }
    $item = $lv.SelectedItems[0]
    $policy = $script:Config.policies | Where-Object { $_.id -eq $item.Tag } | Select-Object -First 1
    $answer = Show-Message "Remove '$($policy.name)' from the list?`n`nYes = revert it on this PC first, then remove`nNo = just remove it from the list (leave PC as is)" 'Question' 'YesNoCancel'
    if ($answer -eq 'Cancel') { return }
    if ($answer -eq 'Yes') {
        $form.Cursor = 'WaitCursor'
        try { Invoke-ApplyPolicies @{ $policy.id = $false } @($policy) } finally { $form.Cursor = 'Default' }
    }
    $script:Config.policies = @($script:Config.policies | Where-Object { $_.id -ne $policy.id })
    Save-Config
    Write-Log "Removed policy '$($policy.name)' from the config."
    Update-StatusView
})

$btnEdit.Add_Click({
    Start-Process notepad.exe -ArgumentList "`"$ConfigPath`""
    Write-Log 'Opened config in Notepad. Save it, then click "Reload / Refresh".'
})

$btnExplorer.Add_Click({ Restart-Explorer })
$btnLog.Add_Click({ if (Test-Path -LiteralPath $LogFile) { Start-Process notepad.exe -ArgumentList "`"$LogFile`"" } })

$cmbScope.Add_SelectionChangeCommitted({
    $scope = if ($cmbScope.SelectedIndex -eq 1) { 'CurrentUser' } else { 'AllUsers' }
    $script:Config.settings.userScope = $scope
    $chkExcludeMe.Enabled = ($scope -eq 'AllUsers')
    $btnExclude.Enabled = ($scope -eq 'AllUsers')
    Save-Config
    Update-StatusView
})

$chkExcludeMe.Add_Click({
    Set-UserExcluded $MyProfileName $chkExcludeMe.Checked
    Save-Config
    Write-Log "Never-restrict accounts: $(@($script:Config.settings.excludeUsers) -join ', '). Click Apply to update the PC."
})

$btnExclude.Add_Click({
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = 'Never-restrict accounts'
    $dlg.Size = New-Object System.Drawing.Size(520, 470)
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MaximizeBox = $false
    $dlg.MinimizeBox = $false
    $dlg.StartPosition = 'CenterParent'
    $dlg.Font = $form.Font

    $existing = @(Get-UserHiveTargets | Where-Object { $_.Sid -ne 'DEFAULT' } | ForEach-Object { $_.Name }) -join ', '
    New-DialogLabel $dlg ("Accounts listed here are never restricted, and any restrictions they got`n" +
        "are removed on the next Apply (or startup, if installed).`n`n" +
        "One account per line - use the folder name under C:\Users.`n" +
        "Add IT/admin accounts that will be created later too, e.g. on imaged laptops.`n`n" +
        "Accounts on this PC now: $existing") 12 10
    $txtList = New-DialogControl $dlg 'TextBox' 15 140 470
    $txtList.Multiline = $true
    $txtList.ScrollBars = 'Vertical'
    $txtList.Height = 230
    $txtList.Text = @($script:Config.settings.excludeUsers) -join "`r`n"

    $btnSave = New-DialogButton $dlg 'Save' 300 385 90
    $btnSave.DialogResult = 'OK'
    $btnCancel = New-DialogButton $dlg 'Cancel' 395 385 90
    $btnCancel.DialogResult = 'Cancel'
    $dlg.CancelButton = $btnCancel

    if ($dlg.ShowDialog($form) -eq 'OK') {
        $script:Config.settings | Add-Member -NotePropertyName excludeUsers -NotePropertyValue @(Get-TextLines $txtList) -Force
        Save-Config
        $chkExcludeMe.Checked = @($script:Config.settings.excludeUsers) -contains $MyProfileName
        Write-Log "Never-restrict accounts: $(@($script:Config.settings.excludeUsers) -join ', '). Click Apply to update the PC."
    }
    $dlg.Dispose()
})

$btnInstall.Add_Click({
    try {
        if (Test-Installed) {
            $answer = Show-Message ("Already installed in $InstallDir and re-applying at every startup.`n`n" +
                "Yes = update it with the current ticks and settings`n" +
                "No = uninstall it (stops re-applying; restrictions already applied stay)") 'Question' 'YesNoCancel'
            if ($answer -eq 'Cancel') { return }
            if ($answer -eq 'No') { Uninstall-FromThisPC; return }
        } else {
            $answer = Show-Message ("Install on this PC?`n`n" +
                "- Copies the tool to $InstallDir (only admins can change it)`n" +
                "- Re-applies the currently ticked policies every time the PC starts`n`n" +
                "Do this on the master laptop before making a disk image, and every cloned`n" +
                "laptop will keep enforcing the restrictions by itself.") 'Question' 'YesNo'
            if ($answer -ne 'Yes') { return }
        }
        $desired = Get-DesiredFromList
        foreach ($p in $script:Config.policies) { Set-PolicyEnabled $p $desired[$p.id] }
        Save-Config
        Install-OnThisPC
        Show-Message ("Done. Installed in $InstallDir.`n`nFrom now on, open the tool from there (Start Policy Manager.bat).`n" +
            "Click Apply too if you want the ticks applied right now rather than at next startup.") | Out-Null
    } catch {
        Write-Log "ERROR: $($_.Exception.Message)"
        Show-Message "Install failed:`n`n$($_.Exception.Message)" 'Error' | Out-Null
    }
})

$form.Add_Shown({
    $script:LogBox = $txtLog
    $form.Activate()
    Update-StatusView
})

try {
    [void]$form.ShowDialog()
} catch {
    Show-Message "Unexpected error:`n`n$($_.Exception.Message)" 'Error' | Out-Null
}
