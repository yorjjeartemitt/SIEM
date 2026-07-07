# SIEM

Lightweight SIEM (Security Information and Event Management) prototype with a log parsing engine and GTK3 GUI. Written in C.

Educational project — not production-ready. Built to learn low-level C, GTK3, and how real SIEM systems collect/parse/alert on logs.

## Features

- Custom log parsers for:
  - `pacman.log` (Arch package manager)
  - `auth.log` (Debian/Ubuntu style auth log — **not present on Arch**, will return empty on this distro)
  - Live `journalctl` stream (last 100 lines)
  - Generic log file (via File > Open, timestamp/level auto-detected if present)
- Dynamic log buffer (malloc/realloc growable array), no fixed size limits
- Simple rule-based alert engine:
  - Alerts on `ERROR` / `CRITICAL` / `WARNING` levels
  - Alerts on keyword match in message body: `error`, `failed`, `denied`, `warning`
- GTK3 GUI:
  - Expandable tree view (each log entry expands to show full message)
  - Source picker: System / Auth / Pacman / All Sources
  - "Show All Logs" toggle (default: only alerts shown)
  - Dark/White theme switch, `Ctrl+W` theme toggle
  - Menubar (File/View), toolbar (Start/Stop/Clear — currently stubs)

## Not implemented yet (stubs)

- Start/Stop capture (toolbar buttons print to stdout only)
- Clear View button
- Network scanner (left panel button, progress bar is hardcoded demo value)
- ML checkbox (UI only, no logic behind it)
- Live log streaming (journal is a one-time snapshot on click, not continuous)
- Export logs, New session, Preferences (menu items, no handlers)

## Build

### Makefile
```sh
make
./siem
# or
make run   # runs with GDK_BACKEND=wayland
```

### CMake
```sh
mkdir build && cd build
cmake ..
make
./siem
```

### Docker
```sh
docker build -t siem .
docker run -it --rm \
  -e WAYLAND_DISPLAY=$WAYLAND_DISPLAY \
  -e XDG_RUNTIME_DIR=/tmp \
  -v $XDG_RUNTIME_DIR/$WAYLAND_DISPLAY:/tmp/$WAYLAND_DISPLAY \
  siem
```

## Dependencies

- GTK3 (`libgtk-3-dev` / `gtk3` on Arch)
- pkg-config
- gcc

## Behavior notes

- On startup, log view is empty — pick a source from the left panel.
- "All Sources" loads pacman + auth + journal into one buffer.
- Switching source clears the current buffer and loads fresh (no accumulation across sources unless "All Sources" is used).
- Default view shows only alerts; toggle "Show All Logs" to see everything parsed.

## Known limitations

- `AppWidgets` and its log buffer are never freed on window close (leak on exit — acceptable for a single-window app that dies with the process, not fixed yet).
- Auth log parser expects Debian/Ubuntu-style `auth.log` format; empty on Arch systems.
- Scanner/ML/Live-stream are UI placeholders, no backing logic.