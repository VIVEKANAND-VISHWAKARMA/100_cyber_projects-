use keycore::{Action, Decoder, KeyEvent, Source};
use libc::{close, ioctl, open, read, O_NONBLOCK, O_RDONLY};
use std::fs;
use std::io;
use std::os::unix::io::RawFd;

const EV_KEY: u16 = 1;

const fn ioc_write(t: u8, nr: u32, size: u32) -> u32 {
    (1u32 << 30) | ((t as u32) << 8) | nr | (size << 16)
}

const fn ioc_read(t: u8, nr: u32, size: u32) -> u32 {
    (2u32 << 30) | ((t as u32) << 8) | nr | (size << 16)
}

const EVIOCGRAB: u32 = ioc_write(b'E', 0x90, 4);
const EVIOCGBIT_KEY: u32 = ioc_read(b'E', 0x20 + EV_KEY as u32, 8);

#[repr(C)]
struct InputEvent {
    time_sec: i64,
    time_usec: i64,
    etype: u16,
    code: u16,
    value: i32,
}

const KEY_A_BIT: usize = 30;

fn open_and_check(path: &str) -> io::Result<RawFd> {
    let cpath = std::ffi::CString::new(path).unwrap();
    let fd = unsafe { open(cpath.as_ptr(), O_RDONLY | O_NONBLOCK) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut mask = [0u8; 8];
    let rc = unsafe { ioctl(fd, EVIOCGBIT_KEY as libc::c_ulong, &mut mask) };
    if rc < 0 {
        let e = io::Error::last_os_error();
        unsafe { close(fd) };
        return Err(e);
    }
    let has_key_a = mask[KEY_A_BIT / 8] & (1 << (KEY_A_BIT % 8)) != 0;
    if !has_key_a {
        unsafe { close(fd) };
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "not a keyboard device",
        ));
    }
    Ok(fd)
}

pub fn list_keyboards() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir("/dev/input") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("event") {
                let path = format!("/dev/input/{}", name);
                match open_and_check(&path) {
                    Ok(fd) => {
                        unsafe { close(fd) };
                        out.push(path);
                    }
                    Err(_) => {}
                }
            }
        }
    }
    out
}

pub fn run_devices(grab: bool, mut on_key: impl FnMut(KeyEvent)) -> Result<(), String> {
    let devices = list_keyboards();
    if devices.is_empty() {
        return Err("no keyboard devices found in /dev/input".to_string());
    }

    let mut decoder = Decoder::new();
    let mut fds = Vec::new();
    for path in &devices {
        let fd = open_and_check(path).map_err(|e| format!("open {}: {}", path, e))?;
        if grab {
            let rc = unsafe { ioctl(fd, EVIOCGRAB as libc::c_ulong, 1) };
            if rc < 0 {
                let e = io::Error::last_os_error();
                unsafe { close(fd) };
                return Err(format!("grab {}: {}", path, e));
            }
        }
        eprintln!("[evdev] watching {}", path);
        fds.push(fd);
    }

    loop {
        let mut raw = [0u8; std::mem::size_of::<InputEvent>()];
        let mut progress = false;
        for fd in &fds {
            let n = unsafe { read(*fd, raw.as_mut_ptr() as *mut libc::c_void, raw.len()) };
            if n == std::mem::size_of::<InputEvent>() as isize {
                let ev: InputEvent = unsafe { std::ptr::read_unaligned(raw.as_ptr() as *const InputEvent) };
                if ev.etype == EV_KEY {
                    let action = match ev.value {
                        1 => Action::Press,
                        0 => Action::Release,
                        2 => Action::Repeat,
                        _ => continue,
                    };
                    if let Some(event) = decoder.feed(Source::Evdev, ev.code, action) {
                        on_key(event);
                    }
                }
                progress = true;
            }
        }
        if !progress {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}
