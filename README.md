# Dynamic Window Policy

![Windows 10/11](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D6)
![PowerShell 5.1](https://img.shields.io/badge/PowerShell-5.1-5391FE)
![License: MIT](https://img.shields.io/badge/License-MIT-green)

**Lock down Windows office PCs from one screen.** Every restriction is a checkbox:
**tick + Apply = enforced, untick + Apply = reverted.** The list of restrictions lives in a
JSON file, so each company can add or remove its own.

It's built for small offices that don't have Intune or Active Directory, and want to:
remove Solitaire and Paint, stop people pinning apps to the taskbar, keep Quick Access
empty, block Settings, block USB drives and so on.

Nothing to install: it's a single PowerShell script with a Windows GUI.

## Features

- **One screen, one checkbox per restriction**, grouped by category, with a live
  **Current status** column (Applied / Not applied / Partial) read from the PC itself.
- **25 built-in restrictions** (see [list below](#built-in-restrictions)).
- **Add your own without typing file names:** pick programs from the Start menu, from
  running apps, from Settings → Apps, or from an `.msi` file.
- **Applies to every user account**, including accounts created later.
- **Never-restrict accounts** so the IT/admin account can't be locked out.
- **Silent mode** to roll the same setup out to other PCs.
- **Install on this PC:** re-applies the restrictions at every startup, and works with
  disk images.
- Every change is logged to `WinPolicyManager.log`.

## Requirements

- Windows 10 or 11 (Pro, Enterprise or Education)
- An administrator account
- Nothing else. It uses the Windows PowerShell 5.1 built into Windows.

## Quick start

1. **Download:** click **Code → Download ZIP** and extract it (or `git clone` this repo).
   For a ZIP, first right-click it → **Properties** → tick **Unblock** → OK, so Windows
   doesn't block the scripts.
2. Double-click **`Start Policy Manager.bat`** and click **Yes** on the admin prompt.
3. Tick the restrictions you want and click **Apply**.
4. Click **Yes** to restart Explorer so taskbar/Start changes show immediately.
   Some changes need users to sign out and back in.

> **Test on a spare PC or a virtual machine first.** Options like *Block Settings* or
> *Disable Task Manager* really do lock a PC down.

## Built-in restrictions

"Applies to" shows where a restriction lives: the **whole PC**, or **each user** account
(the admin running the tool and never-restrict accounts are skipped).

| Category | Restriction | Applies to |
|---|---|---|
| Apps | Remove Microsoft Solitaire Collection | Whole PC |
| Apps | Remove and block MS Paint | PC + users |
| Apps | Remove Xbox / gaming apps | Whole PC |
| Apps | Remove consumer apps (Clipchamp, News, Weather) | Whole PC |
| Apps | Stop Windows auto-installing suggested apps | PC + users |
| Taskbar & Start | Prevent pinning/unpinning apps on the taskbar | Each user |
| Taskbar & Start | Lock the taskbar | Each user |
| Taskbar & Start | Prevent changes to the Start menu | Each user |
| Taskbar & Start | Hide recent files in Start and jump lists | PC + users |
| Taskbar & Start | Disable Widgets (news feed) | Whole PC |
| Taskbar & Start | Disable / remove Copilot | PC + users |
| Taskbar & Start | Disable web results in Start search | Each user |
| File Explorer & Quick Access | Show no recent files or frequent folders | Each user |
| File Explorer & Quick Access | Hide Quick Access / Home from File Explorer | PC + users |
| Settings & Control Panel | Block Settings app and Control Panel | Each user |
| Settings & Control Panel | Hide selected Settings pages | Whole PC |
| System tools | Disable Command Prompt | Each user |
| System tools | Block PowerShell | Each user |
| System tools | Disable Registry Editor | Each user |
| System tools | Disable Task Manager | Each user |
| System tools | Disable the Run dialog (Win+R) | Each user |
| Devices | Block USB storage devices | Whole PC |
| Devices | Disable the camera | Whole PC |
| Windows features | Disable Microsoft Store (Enterprise/Education only) | Whole PC |
| Windows features | Block installing .msi packages | Whole PC |

## Adding your own restrictions

Click **Add policy...** and choose what it should do. Every option has a searchable list,
and the name fills in automatically.

| Type | How you pick |
|---|---|
| **Block a program from running** | From **running apps** (open the program first: easiest), the **Start menu**, or **Browse** |
| **Uninstall a Store app** | From the installed Store apps (Solitaire, Xbox, ...) |
| **Uninstall a desktop program** | From the same list as **Settings → Apps**, or **read the name from an `.msi` file** |
| **Set a registry value** | Advanced: any Windows policy setting |

**Remove policy** deletes a restriction from the list and can undo it on the PC first.
You can also edit `policies.json` directly (**Edit config file**, then **Reload / Refresh**).

**About `.msi` files:** an `.msi` is an *installer*, not a program, so it can't be blocked
like an `.exe`. Use *Uninstall a desktop program* to remove what it installed, and the
built-in *Block installing .msi packages* to stop new installs.

## Who gets restricted

- **Whole-PC** restrictions affect everyone.
- **Per-user** restrictions are written into every user profile on the PC and into the
  **Default profile**, so accounts created later get them automatically.
- **Never-restrict accounts** (button at the top) are never restricted, and any
  restrictions they picked up are removed. *"Don't restrict me"* is on by default for the
  admin running the tool.
- Employees should use **Standard (non-admin) accounts**. An admin can undo anything.

## Rolling out to many PCs

| Situation | What to do |
|---|---|
| PCs already in use | Set it up once, click **Apply** (this saves the ticks), copy the folder to each PC and run **`Apply Silently.bat`** as admin. The folder can be deleted afterwards. |
| Keep enforcing after updates | Click **Install on this PC...**. It copies the tool to `C:\Program Files\WinPolicyManager` and re-applies the ticked restrictions 2 minutes after every startup. |
| New or freshly reset laptops | Use a disk image (below). |

### Using a disk image

An image copies one fully set-up laptop onto others. **Restoring an image wipes the
target laptop**, so use it only on new or reset laptops.

1. **Master laptop:** install Windows and press **Ctrl+Shift+F3** on the first setup
   screen (Audit mode). Keep it offline.
2. Install the company software.
3. In the tool: tick restrictions → **Apply** → add the IT account name to
   **Never-restrict accounts** → **Install on this PC...**.
4. Run `C:\Windows\System32\Sysprep\sysprep.exe` with **OOBE + Generalize + Shutdown**.
5. Capture the disk with a Clonezilla (or Macrium) USB.
6. **Each new laptop:** restore the image, create the **IT admin account first**, add
   employees as **Standard users**, then restart once.

## Configuration reference

Each entry in `policies.json`:

```json
{
  "id": "block-paint",
  "name": "Remove and block MS Paint",
  "category": "Apps",
  "description": "Shown in the list",
  "enabled": false,
  "actions": [
    { "type": "removeAppx", "package": "Microsoft.Paint" },
    { "type": "blockApp", "exe": "mspaint.exe" }
  ]
}
```

| Action type | Fields | What it does | On untick |
|---|---|---|---|
| `registry` | `hive` (`HKLM` / `HKCU`), `path`, `name`, `valueType` (`DWord`, `String`, `ExpandString`, `QWord`), `value`, optional `revertValue` | Sets a registry value (`HKLM` = whole PC, `HKCU` = every user) | Deletes the value, or sets `revertValue` |
| `blockApp` | `exe` | Blocks the program by file name (Explorer *DisallowRun*) | Removes the block |
| `removeAppx` | `package` (`*` wildcards ok) | Uninstalls a Store app for all users and new users | Stays uninstalled |
| `uninstallProgram` | `displayName` (`*` wildcards ok) | Uninstalls a desktop program (MSI or EXE) | Stays uninstalled |

`settings` holds `userScope` (`AllUsers` / `CurrentUser`) and `excludeUsers` (the
never-restrict account names, as their folder names under `C:\Users`).

## Limitations

- **Program blocking can be bypassed** by renaming the `.exe`. Uninstall the app where
  possible; for strict whitelisting use AppLocker (Enterprise/Education).
- **Unticking an uninstall does not reinstall** the app.
- Some settings only work on **Enterprise/Education** editions (noted in their descriptions).
- On PCs joined to a **domain**, Group Policy from the domain wins over this tool.
- Some EXE-based uninstallers show their own window that needs clicking through; silent
  mode skips those.

## Files

| File | Purpose |
|---|---|
| `Start Policy Manager.bat` | Opens the tool (asks for admin rights) |
| `WinPolicyManager.ps1` | The application |
| `policies.json` | The list of restrictions and settings |
| `Apply Silently.bat` | Applies the saved ticks without the GUI |
| `GUIDE.md` | One-page quick guide |

## License

[MIT](LICENSE) © 2026 Fahad Rizwan
