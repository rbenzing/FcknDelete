# Fckn Delete

A small Windows tool that force-deletes files and folders when Explorer says no.

- Permanent delete (skips the Recycle Bin), recursive, handles read-only/hidden/system items and paths longer than 260 characters.
- Never follows junctions or symlinks: only the link itself is removed.
- If something is locked, it shows which programs are using it and can close them for you.
- If something needs admin rights, it can take ownership via UAC and then delete it.
- Extra-loud warning before touching protected locations (drive roots, your profile, Windows, Program Files, ProgramData).

## Build

```
cargo build --release
```

The result is `target\release\FcknDelete.exe`. It is a single self-contained exe (Windows only).

## Use

Double-click `FcknDelete.exe` to get a menu: pick a file, pick a folder, or add/remove the right-click entry.

### Right-click menu

Double-click the exe and choose **Add "Fckn Delete" to the right-click menu**. This copies the exe to `%LOCALAPPDATA%\Programs\FcknDelete\` and registers a `Fckn Delete` entry for files and folders under your user account (no admin needed). You can also run `FcknDelete.exe --install`.

On Windows 11 the entry lives under **Show more options** (or press Shift+F10) in the right-click menu; the new top-level menu needs a packaged shell extension, which this tool does not provide.

When you select several items, Explorer starts one Fckn Delete per item, so you get one confirmation each.

### Command line

```
FcknDelete.exe <path> [<path> ...]   delete the given paths (with confirmation)
FcknDelete.exe --install             add the right-click entry
FcknDelete.exe --uninstall           remove the right-click entry
```

Exit code is `0` on success or cancel, `1` on failure.

## Uninstall

Double-click the exe and choose **Remove "Fckn Delete" from the right-click menu** (or run `FcknDelete.exe --uninstall`). This removes the registry entries only; delete `%LOCALAPPDATA%\Programs\FcknDelete\` yourself if you want the copied exe gone (use Fckn Delete, naturally).
