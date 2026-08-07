use chrono::Local;
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Source {
    Evdev,
    X11,
    Ptrace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Action {
    Press,
    Release,
    Repeat,
}

#[derive(Debug, Clone, Serialize)]
pub struct KeyEvent {
    pub timestamp: String,
    pub source: Source,
    pub keycode: u16,
    pub keyname: String,
    pub char: Option<char>,
    pub action: Action,
}

impl KeyEvent {
    pub fn new(
        source: Source,
        keycode: u16,
        keyname: String,
        char: Option<char>,
        action: Action,
    ) -> Self {
        Self {
            timestamp: Local::now().to_rfc3339(),
            source,
            keycode,
            keyname,
            char,
            action,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ByteEvent {
    pub timestamp: String,
    pub source: Source,
    pub bytes: Vec<u8>,
}

impl ByteEvent {
    pub fn new(source: Source, bytes: Vec<u8>) -> Self {
        Self {
            timestamp: Local::now().to_rfc3339(),
            source,
            bytes,
        }
    }
}

const CAPSLOCK: u16 = 58;
const LEFTSHIFT: u16 = 42;
const RIGHTSHIFT: u16 = 54;
const LEFTCTRL: u16 = 29;
const RIGHTCTRL: u16 = 97;
const LEFTALT: u16 = 56;
const RIGHTALT: u16 = 100;

const QWERTY: &[u8] = b"qwertyuiop";
const ASDF: &[u8] = b"asdfghjkl";
const ZXCV: &[u8] = b"zxcvbnm";

fn base_char(keycode: u16) -> Option<char> {
    match keycode {
        2..=11 => Some((b'1' + (keycode - 2) as u8) as char),
        12 => Some('-'),
        13 => Some('='),
        16..=25 => Some(QWERTY[(keycode - 16) as usize] as char),
        30..=38 => Some(ASDF[(keycode - 30) as usize] as char),
        44..=50 => Some(ZXCV[(keycode - 44) as usize] as char),
        57 => Some(' '),
        _ => None,
    }
}

fn shifted_char(keycode: u16) -> Option<char> {
    match keycode {
        2 => Some('!'),
        3 => Some('@'),
        4 => Some('#'),
        5 => Some('$'),
        6 => Some('%'),
        7 => Some('^'),
        8 => Some('&'),
        9 => Some('*'),
        10 => Some('('),
        11 => Some(')'),
        12 => Some('_'),
        13 => Some('+'),
        _ => base_char(keycode).map(|c| c.to_ascii_uppercase()),
    }
}

fn key_name(keycode: u16) -> Option<&'static str> {
    match keycode {
        1 => Some("Esc"),
        14 => Some("Backspace"),
        15 => Some("Tab"),
        28 => Some("Enter"),
        29 => Some("LeftCtrl"),
        42 => Some("LeftShift"),
        54 => Some("RightShift"),
        56 => Some("LeftAlt"),
        57 => Some("Space"),
        58 => Some("CapsLock"),
        97 => Some("RightCtrl"),
        100 => Some("RightAlt"),
        111 => Some("Delete"),
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub struct Decoder {
    pub capslock: bool,
    pub shift: bool,
}

fn describe(keycode: u16) -> (String, Option<char>) {
    if let Some(name) = key_name(keycode) {
        return (name.to_string(), None);
    }
    if let Some(c) = base_char(keycode) {
        return ("Key".to_string(), Some(c));
    }
    ("Unknown".to_string(), None)
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            capslock: false,
            shift: false,
        }
    }

    pub fn feed(&mut self, source: Source, keycode: u16, action: Action) -> Option<KeyEvent> {
        if action == Action::Release {
            if matches!(keycode, LEFTSHIFT | RIGHTSHIFT) {
                self.shift = false;
            }
            let (name, _) = describe(keycode);
            return Some(KeyEvent::new(source, keycode, name, None, action));
        }

        match keycode {
            CAPSLOCK => {
                if action == Action::Press {
                    self.capslock = !self.capslock;
                }
                return Some(KeyEvent::new(
                    source,
                    keycode,
                    "CapsLock".to_string(),
                    None,
                    action,
                ));
            }
            LEFTSHIFT | RIGHTSHIFT => {
                self.shift = true;
                return Some(KeyEvent::new(
                    source,
                    keycode,
                    key_name(keycode).unwrap_or("?").to_string(),
                    None,
                    action,
                ));
            }
            LEFTCTRL | RIGHTCTRL | LEFTALT | RIGHTALT => {
                return Some(KeyEvent::new(
                    source,
                    keycode,
                    key_name(keycode).unwrap_or("?").to_string(),
                    None,
                    action,
                ));
            }
            _ => {}
        }

        let shifted = self.shift ^ self.capslock;
        let c = if shifted {
            shifted_char(keycode)
        } else {
            base_char(keycode)
        };
        let (name, _) = describe(keycode);
        let ch = match keycode {
            14 => Some('\u{232B}'),
            15 => Some('\t'),
            28 => Some('\n'),
            _ => c,
        };
        Some(KeyEvent::new(source, keycode, name, ch, action))
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct JsonlLogger {
    writer: BufWriter<File>,
}

impl JsonlLogger {
    pub fn new(path: &Path) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            writer: BufWriter::new(file),
        })
    }

    pub fn log(&mut self, event: &KeyEvent) -> std::io::Result<()> {
        serde_json::to_writer(&mut self.writer, event)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()
    }

    pub fn log_bytes(&mut self, event: &ByteEvent) -> std::io::Result<()> {
        serde_json::to_writer(&mut self.writer, event)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn type_text(decoder: &mut Decoder, keys: &[(u16, Action)]) -> String {
        let mut out = String::new();
        for (keycode, action) in keys {
            if let Some(ev) = decoder.feed(Source::Evdev, *keycode, *action) {
                if let Some(c) = ev.char {
                    out.push(c);
                }
            }
        }
        out
    }

    #[test]
    fn lowercase_row() {
        let mut d = Decoder::new();
        let keys: Vec<(u16, Action)> = (16..=25)
            .chain(30..=38)
            .chain(44..=50)
            .map(|k| (k, Action::Press))
            .collect();
        let text = type_text(&mut d, &keys);
        assert_eq!(text, "qwertyuiopasdfghjklzxcvbnm");
    }

    #[test]
    fn shifted_digits() {
        let mut d = Decoder::new();
        let mut keys = vec![(42, Action::Press)];
        for k in 2..=13 {
            keys.push((k, Action::Press));
        }
        keys.push((42, Action::Release));
        let text = type_text(&mut d, &keys);
        assert_eq!(text, "!@#$%^&*()_+");
    }

    #[test]
    fn capslock_inverts_case() {
        let mut d = Decoder::new();
        let mut keys = vec![(58, Action::Press)];
        for k in 16..=25 {
            keys.push((k, Action::Press));
        }
        keys.push((58, Action::Press));
        for k in 30..=38 {
            keys.push((k, Action::Press));
        }
        let text = type_text(&mut d, &keys);
        assert_eq!(text, "QWERTYUIOPasdfghjkl");
    }

    #[test]
    fn shift_release_restores_state() {
        let mut d = Decoder::new();
        let mut keys = vec![(42, Action::Press), (30, Action::Press)];
        keys.push((42, Action::Release));
        keys.push((30, Action::Press));
        let text = type_text(&mut d, &keys);
        assert_eq!(text, "Aa");
    }

    #[test]
    fn special_keys() {
        let mut d = Decoder::new();
        let mut keys = vec![(57, Action::Press), (28, Action::Press), (15, Action::Press)];
        keys.push((14, Action::Press));
        let text = type_text(&mut d, &keys);
        assert_eq!(text, " \n\t\u{232B}");
    }
}
