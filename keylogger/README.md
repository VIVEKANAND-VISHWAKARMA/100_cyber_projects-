# keylogger

A cross-platform, educational keylogger written in Rust that demonstrates three
different ways a program can observe keystrokes on Linux.

> **⚠️ LEGAL & ETHICAL WARNING**
>
> This project is **for educational and security-research purposes only**.
> Installing a keylogger on any machine you do not own — or on any machine
> without the explicit consent of its owner — is **illegal** in most
> jurisdictions and is generally unethical. You are responsible for how you
> use this software. Use it only on your own devices.

## What it does

`keylogger` captures keystrokes using three independent Linux mechanisms and
writes them as timestamped JSON lines to a log file:

1. **evdev** — reads raw key events straight from the kernel input subsystem
   (`/dev/input/event*`).
2. **X11 / XRecord** — records key events at the X server level via the
   XRecord extension, without the need for special privileges.
3. **ptrace** — intercepts every `read()` system call of a traced process and
   saves whatever it reads from its standard input (e.g. text typed into a
   shell).

Each mechanism shows a different "layer" of the input pipeline: kernel →
display server → process.

---

## Features

- Three capture backends, selectable at runtime (`--method`).
- Clean JSONL output (one JSON object per line) — easy to parse, append-only,
  and ready to be imported into any database or analysis tool.
- Key decoder with Shift / CapsLock handling for the US QWERTY layout.
- Non-privileged operation for most use cases (see [Privileges](#privileges)).
- Pure Rust, small dependency footprint, builds with `cargo`.

---

## How it works

### 1. evdev (`--method evdev`)

The kernel exposes input devices as character devices in `/dev/input/`. For
each device that advertises the `KEY_A` capability bit (a good heuristic for
"this is a keyboard"), the program:

- opens the device node with `O_RDONLY | O_NONBLOCK`,
- reads 24-byte `struct input_event` records (timestamp, type, code, value),
- forwards `EV_KEY` events (code = keycode, value = 1 press / 0 release / 2
  repeat) to the decoder.

With `--grab`, each device is claimed exclusively with `EVIOCGRAB`, which
prevents the normal compositor/X server from receiving those keys — only use
this on a spare keyboard.

### 2. X11 / XRecord (`--method x11`)

The X server's **XRecord** extension allows a client to record the core X
events delivered to *all* other clients. This program:

- connects to the X server (`$DISPLAY`),
- creates an XRecord context covering **all clients**, device events in the
  range `KeyPress` (2) … `KeyRelease` (3), with a `FromServerTime` header,
- `EnableContext` streams the recorded data; each datum is 4 bytes of server
  time + a 32-byte core event. The event type and keycode sit at fixed
  offsets in that 36-byte datum.

X keycodes are the kernel keycode + 8, so they are converted back before
decoding. Because it records at the server level it needs no special
permissions, but it does require a running X session.

### 3. ptrace (`--method ptrace`)

The classic "debugger" mechanism. The program either spawns a child shell
(`--spawn`) or attaches to an existing process (`--pid`) and then:

- sets `PTRACE_O_TRACESYSGOOD` so syscall stops are distinguishable,
- single-steps through every syscall entry/exit with `PTRACE_SYSCALL`,
- uses `PTRACE_GET_SYSCALL_INFO` to learn which syscall it is,
- when a `read()` on file descriptor `0` (stdin) completes, copies the bytes
  out of the tracee's memory with `PTRACE_PEEKDATA` and logs them.

This captures exactly what the target process reads from its standard input
(a shell reads your commands, `cat` reads piped text, etc.).

### The decoder & logger (`keycore`)

All three backends feed events into the shared `Decoder`, which tracks the
state of Shift and CapsLock and maps kernel keycodes (Linux input keycodes) to
characters for a US QWERTY layout. The `JsonlLogger` appends each decoded
event as a JSON line.

---

## Project layout

```
keylogger/
├── Cargo.toml                  # workspace definition
└── crates/
    ├── core/                   # keycore: events, decoder, JSONL logger
    ├── capture-evdev/          # evdev backend
    ├── capture-x11/            # XRecord backend
    ├── capture-ptrace/         # ptrace backend
    └── cli/                    # the `keylogger` binary
```

---

## Requirements

- Linux (all three backends are Linux-specific).
- Rust toolchain (`cargo`). Everything else is fetched automatically.
- The **x11** backend needs a running X server (`$DISPLAY`).
- The **evdev** backend needs read access to `/dev/input/event*`
  (membership in the `input` group, or root).
- The **ptrace** backend can only trace processes that belong to you (or use
  root). Attaching to other users' processes is restricted by `ptrace_scope`
  on most distros.

### Privileges

| Method  | Minimum privilege              | Notes                                       |
|---------|--------------------------------|---------------------------------------------|
| evdev   | `input` group membership (or root) | no sudo if you're in the `input` group  |
| x11     | none (just an X session)       | your own session only                       |
| ptrace  | same user as the target (or root) | attach to a process you own, or `--spawn` |

---

## Build

```bash
cd keylogger
cargo build --release
```

The binary will be at `target/release/keylogger`. (For a debug build, drop
`--release`.)

---

## Usage

```
keylogger --method evdev|x11|ptrace [--log PATH] [--grab] [--pid N] [--spawn SHELL]

  --method evdev       capture via /dev/input event devices (input group or root)
  --method x11         capture via the XRecord extension (needs a running X session)
  --method ptrace      intercept read() on a traced process (needs root or child)
  --log PATH           output file (default: keys.log.jsonl)
  --pid N              ptrace: attach to running process N
  --spawn SHELL        ptrace: trace a forked child running SHELL
  --grab               evdev: exclusively grab devices (use only on a spare keyboard)
  --list-devices       evdev: print detected keyboard devices and exit
  -h, --help           show this help
```

### Examples

List detected keyboards:

```bash
keylogger --list-devices
# /dev/input/event0
```

Log your physical keystrokes (US QWERTY) to a file:

```bash
keylogger --method evdev --log ~/keys.jsonl
```

Record all keystrokes at the X server level:

```bash
keylogger --method x11 --log ~/keys.jsonl
```

Trace a shell and log everything you type into it:

```bash
keylogger --method ptrace --spawn /bin/bash --log ~/keys.jsonl
```

Attach to a process you already have running and capture what it reads on
stdin:

```bash
keylogger --method ptrace --pid 12345 --log ~/keys.jsonl
```

Stop with `Ctrl-C` (the ptrace child is released when the tracer exits).

---

## Output format

The log is JSONL: one JSON object per line.

### Key events (evdev / x11)

```json
{"timestamp":"2026-08-07T10:46:25.655219681+05:30","source":"Evdev","keycode":20,"keyname":"Key","char":"t","action":"Press"}
{"timestamp":"2026-08-07T10:46:25.749951204+05:30","source":"Evdev","keycode":20,"keyname":"Key","char":null,"action":"Release"}
```

| Field       | Meaning                                                        |
|-------------|----------------------------------------------------------------|
| `timestamp` | local time, RFC 3339                                            |
| `source`    | `Evdev`, `X11`, or `Ptrace`                                     |
| `keycode`   | Linux input keycode (X keycodes are converted back by −8)       |
| `keyname`   | readable name: `Key`, `Space`, `Enter`, `Backspace`, `LeftCtrl` |
| `char`      | decoded character, or `null` for non-printing keys              |
| `action`    | `Press`, `Release`, or `Repeat`                                 |

Special keys produce control characters: Backspace = `⌫` (U+232B), Tab = `\t`,
Enter = `\n`, Space = `' '`.

### Byte events (ptrace)

```json
{"timestamp":"2026-08-07T01:19:45.700818518+05:30","source":"Ptrace","bytes":[104,101,108,108,111,10]}
```

`bytes` is an array of the raw bytes the traced process read from stdin.

---

## Limitations

- **Layout**: the decoder assumes a **US QWERTY** layout. Other layouts will
  produce wrong characters.
- **evdev**: logs the raw keycode stream; the character shown is the decoder's
  guess, but the raw keycode is always in the log for your own interpretation.
- **x11**: only works under a running X server (not Wayland), and only records
  events delivered through the X server.
- **ptrace**: Linux-specific; on kernels without `PTRACE_GET_SYSCALL_INFO`
  (pre-5.3) the syscall-detection path will not work. It also slows the traced
  process down and cannot trace setuid/root processes unless you are root.
- This is a **demo/research tool**, not a stealth product: it writes its log
  to a file you choose, prints messages to stderr, and does nothing to hide
  itself.

---

## Tests

```bash
cargo test
```

The core crate includes unit tests for the decoder (lowercase rows, shifted
digits, CapsLock, Shift state restoration, special keys).

---

## License

No license file is included yet. If you plan to publish this, pick a license
first (e.g. MIT or GPL) and add the corresponding `LICENSE` file.
