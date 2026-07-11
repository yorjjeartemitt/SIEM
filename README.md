# SIEM

GTK3 SIEM (Security Information and Event Management) prototype — log collection, rule-based alerting, and live monitoring.
Written in C.

## Why I built this

Wanted to understand how real SIEM tools actually work under the hood — not just clicking around Splunk/Wazuh, but writing the log parsing, alert correlation, and buffering myself. Started with `pacman.log`/`auth.log`/`journalctl` as data sources since that's what's actually running on my machine.

## Stack

<div align="center">

![C](https://img.shields.io/badge/C-00599C?style=for-the-badge&logo=c&logoColor=white)
![GTK3](https://img.shields.io/badge/GTK3-215732?style=for-the-badge&logo=gtk&logoColor=white)
![CMake](https://img.shields.io/badge/CMake-064F8C?style=for-the-badge&logo=cmake&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)

</div>

## Features

- Log ingestion from 3 real sources + generic file import:
  - `pacman.log`, `auth.log`, live `journalctl`
- Incremental parsing — live capture only reads new lines (byte offset for files, `--since` timestamp for journalctl), no re-reading the whole log on every poll
- Rule-based alert engine — ~35 keyword rules across 4 severity tiers (CRITICAL/HIGH/MEDIUM/LOW) and 6 categories (auth, network, malware, integrity, recon, system), plus log-level baseline (ERROR/WARNING/CRITICAL)
- Whole-word matching (not naive substring), pacman noise suppression for routine install/remove/upgrade lines
- Expandable tree view — full entry details on expand
- TP/FP verdict marking per alert
- CSV export
- Dark/white theme (`Ctrl+W` toggle), fullscreen, toggleable sidebar, toggleable columns

## Not implemented yet

- scanner / network view (UI placeholders only)

## Dependencies

**Arch Linux:**
```sh
sudo pacman -S gtk3 cmake pkgconf
```

**Ubuntu/Debian:**
```sh
sudo apt install libgtk-3-dev cmake pkg-config
```

## Build & Run

```sh
git clone https://github.com/yorjjeartemitt/SIEM.git
cd SIEM

./run gcc     # build with gcc and run
./run cmake   # build with cmake and run
./run docker  # run in docker
```

## Roadmap

- Network scanner with real backend (currently UI stub)
- Hook up `scan_btn` and `scan_progress` to real functionality
- Persistent storage (SQLite) instead of in-memory buffer only
