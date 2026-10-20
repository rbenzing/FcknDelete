# Fckn Delete

<div align="center">

[![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![Build](https://img.shields.io/badge/Build-Release-orange?style=for-the-badge)](#build)
[![Release](https://img.shields.io/github/v/release/rbenzing/FcknDelete?style=for-the-badge)](https://github.com/rbenzing/FcknDelete/releases/latest)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/russellbenzing)

**A small Windows tool for force-removing stubborn locked, read-only, and path-hostile files and folders**

⚙️ **Force delete** • 🧹 **Protected item handling** • 🪟 **Explorer integration** • 🦀 **Rust**

[Features](#-features) • [Build](#-build) • [Use](#-use) • [Command Line](#-command-line) • [Uninstall](#-uninstall)

</div>

---

**Fckn Delete** is a Windows utility built for the cases where normal delete behavior gets blocked by locked files, read-only attributes, long paths, protected folders, or stubborn Explorer permission checks.

> When Explorer says “no,” FcknDelete says “challenge accepted.”

---

## ✨ Features

- **🧹 Permanent delete** — skips the Recycle Bin and removes files/folders recursively
- **🔒 Handles protected items** — works through read-only, hidden, and system files
- **📏 Long path support** — can operate on paths longer than 260 characters
- **🛡️ Safe by default** — never follows junctions or symlinks; only the link itself is removed
- **🔍 Locked-file detection** — identifies which programs are using a file or folder
- **🪟 Optional takeover** — can close locks or request admin rights to take ownership when needed
- **⚠️ Extra warning layer** — warns before touching protected locations such as drive roots, your profile, Windows, Program Files, or ProgramData
- **📁 Explorer integration** — add/remove a right-click entry for quick access from File Explorer

---

## 🏗️ Build

Requires:

- Windows
- Rust toolchain (`cargo`)

```bash
cargo build --release
```

The output is:

```text
target\release\FcknDelete.exe
```

This produces a single self-contained Windows executable.

---

## 🚀 Use

Double-click `FcknDelete.exe` to launch the app. From there you can:

- delete a file
- delete a folder
- add/remove the right-click menu entry

### Right-click menu

To add the command to Explorer:

1. Run `FcknDelete.exe`
2. Choose **Add "Fckn Delete" to the right-click menu**
3. The program copies itself to:
   `%LOCALAPPDATA%\Programs\FcknDelete\`
4. A `Fckn Delete` entry is registered for files and folders

On Windows 11, the entry appears under **Show more options** (or by pressing `Shift+F10`). The new top-level menu requires a packaged shell extension, which this tool does not provide.

When multiple items are selected, Explorer launches one instance per item, so each selection gets its own confirmation prompt.

---

## 💻 Command line

```text
FcknDelete.exe <path> [<path> ...]   delete the given paths (with confirmation)
FcknDelete.exe --install             add the right-click entry
FcknDelete.exe --uninstall           remove the right-click entry
```

Exit codes:

- `0` — success or user canceled
- `1` — failure

---

## 🧹 Uninstall

You can remove the Explorer integration either by:

- launching the app and choosing **Remove "Fckn Delete" from the right-click menu**, or
- running:

```bash
FcknDelete.exe --uninstall
```

This removes the registry entries only. If you want to remove the copied executable from `%LOCALAPPDATA%\Programs\FcknDelete\`, delete that folder manually.

---

## ⚠️ Safety notes

This tool is intentionally aggressive. It is meant for cases where ordinary delete behavior fails, but it still performs a strong confirmation step before acting on dangerous or protected locations.

Use it carefully and only when you understand exactly what you are deleting.

---

## ❤️ Support

If FcknDelete is useful to you, you can support the work:

<div align="center">

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/russellbenzing)

</div>
