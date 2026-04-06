# processmonitor (privwatch)

Linux process auditor that walks `/proc`, prints each running process with PID, command name, owning user, full command line, and flags **writable execution targets** when the process runs as **root** but a resolved path is **not** owned by root and is **group- or world-writable**. That pattern is a common privilege-escalation signal (root executing code others can modify).

Author: c0d3Ninja (see source header).

## What it does

- Enumerates numeric `/proc` entries and reads `comm`, `status` (UID), and `cmdline`.
- Builds a set of **execution targets**: the main executable (if absolute), scripts passed to known interpreters (Python, shell, Node, etc.), and other absolute path arguments that are not `key=value` style.
- Resolves paths with `realpath` where possible.
- For each target, uses `stat(2)`: if the process real UID is `0`, the file owner is **not** `0`, and the mode includes `S_IWGRP` or `S_IWOTH`, the line is annotated with a **HIGH RISK** message.

There is **no CLI**: run the binary and read stdout.

## Output format

Each line is colorized terminal output:

`PID -> comm -> username -> cmdline -> [HIGH RISK: path]`  

The risk suffix is empty when no matching target is found.

## Requirements

- Linux with `/proc` (process filesystem).
- C++20 compiler (`std::filesystem`).

## Build (standalone)

From the repository root:

```bash
g++ -std=c++20 -Wall -Wextra -O2 -o processmonitor tools/processmonitor.cpp
```

Or from `tools/`:

```bash
g++ -std=c++20 -Wall -Wextra -O2 -o processmonitor processmonitor.cpp
```

No extra libraries are required beyond the C++ standard library and POSIX (`unistd`, `pwd`, `sys/stat`).

## Build (ShadowHarvester)

`processmonitor.cpp` is compiled as part of the main `shadowharvester` target in the project `Makefile` (together with `processmonitor.h`, which declares `getProcess()` for linkage with the rest of the project). The standalone program above uses only the `.cpp` file’s `main()`.

## Files

| File | Role |
|------|------|
| `tools/processmonitor.cpp` | Implementation and `main()` for the standalone tool |
| `tools/processmonitor.h` | `std::vector<std::string> getProcess()` for integration with ShadowHarvester |

## Limitations

- Heuristic only: many writable paths are benign; some risky cases may be missed.
- Interpreter and “absolute path argument” detection is substring- and path-shape-based, not a full parser.
- Requires permission to read the relevant `/proc` entries (typical unprivileged users see their own processes; root sees all).

Use only on systems you are authorized to assess.
