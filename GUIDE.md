# Windows Policy Manager: Quick Guide

A one-screen tool to lock down office PCs. **Tick = restrict, untick = undo, then click Apply.**

## Files

| File | Use |
|---|---|
| `Start Policy Manager.bat` | Opens the tool (needs admin) |
| `policies.json` | List of restrictions (editable) |
| `Apply Silently.bat` | Applies saved ticks without opening the tool |

## Daily use

1. Run `Start Policy Manager.bat` and click **Yes** on the admin prompt.
2. Tick/untick restrictions. **Current status** shows what's actually applied.
3. Click **Apply**, then **Yes** to restart Explorer.

## Add / remove restrictions

**Add policy...** lets you pick from lists, so no typing is needed:
- **Block a program**: pick from running apps, the Start menu, or browse.
- **Uninstall a Store app**: Solitaire, Xbox, etc.
- **Uninstall a desktop program**: same list as Settings → Apps (works for `.msi` too).
- **Registry value**: advanced.

**Remove policy** deletes one from the list, and can undo it on this PC first.

## Who gets restricted

- All user accounts, including ones created later.
- **Never-restrict accounts**: listed accounts (e.g. IT admin) stay unrestricted.
- Employees must be **Standard users**. Admins can undo anything.

## Rolling out

| Situation | Do this |
|---|---|
| Laptops already in use | Copy folder → run `Apply Silently.bat` as admin |
| Keep enforcing after updates | Click **Install on this PC** (re-applies at every startup) |
| New laptops | Use a disk image (below) |

## Disk image (new / reset laptops only; it wipes the disk)

1. On the master laptop, install Windows and press **Ctrl+Shift+F3** at the first setup screen. Keep it offline.
2. Install company software.
3. In the tool: tick restrictions → **Apply** → add the IT account to **Never-restrict** → **Install on this PC**.
4. Run `C:\Windows\System32\Sysprep\sysprep.exe` with **OOBE + Generalize + Shutdown**.
5. Capture the disk with a Clonezilla USB.
6. On each new laptop, restore the image, create the **IT admin account first**, add employees as **Standard users**, then restart once.

## Limits

- Program blocking can be bypassed by renaming the `.exe`. Uninstall the app where possible.
- Unticking an uninstall does **not** reinstall the app.
- Some settings work on Enterprise/Education editions only (noted in the tool).
- Company Group Policy (domain) overrides this tool.
- **Test on one spare laptop first.**
