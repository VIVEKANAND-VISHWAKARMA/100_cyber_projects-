use keycore::{Action, Decoder, KeyEvent, Source};
use x11rb::connection::Connection;
use x11rb::protocol::record::{
    self, CS, Context, ExtRange, HType, Range, Range16, Range8,
};

const KEY_PRESS: u8 = 2;
const KEY_RELEASE: u8 = 3;
const SERVER_TIME_LEN: usize = 4;
const CORE_EVENT_LEN: usize = 32;
const DATUM_LEN: usize = SERVER_TIME_LEN + CORE_EVENT_LEN;
const X_KEYCODE_OFFSET: u16 = 8;

fn empty_range() -> Range8 {
    Range8 { first: 0, last: 0 }
}

fn empty_ext_range() -> ExtRange {
    ExtRange {
        major: empty_range(),
        minor: Range16 { first: 0, last: 0 },
    }
}

pub fn run(mut on_key: impl FnMut(KeyEvent)) -> Result<(), String> {
    let (control, _) = x11rb::connect(None).map_err(|e| format!("connect to X server: {}", e))?;
    let mut decoder = Decoder::new();

    record::query_version(&control, 1, 13)
        .map_err(|e| format!("query version: {}", e))?
        .reply()
        .map_err(|e| format!("query version reply: {}", e))?;

    let context: Context = control
        .generate_id()
        .map_err(|e| format!("generate id: {}", e))?;

    let range = Range {
        core_requests: empty_range(),
        core_replies: empty_range(),
        ext_requests: empty_ext_range(),
        ext_replies: empty_ext_range(),
        delivered_events: empty_range(),
        device_events: Range8 {
            first: KEY_PRESS,
            last: KEY_RELEASE,
        },
        errors: empty_range(),
        client_started: false,
        client_died: false,
    };

    let specs = vec![CS::ALL_CLIENTS.into()];
    let header: u8 = HType::FROM_SERVER_TIME.into();

    record::create_context(&control, context, header, &specs, &[range])
        .map_err(|e| format!("create context: {}", e))?
        .check()
        .map_err(|e| format!("create context check: {}", e))?;

    eprintln!("[x11] XRecord context {} active, listening for key events", context);

    let cookie = record::enable_context(&control, context)
        .map_err(|e| format!("enable context: {}", e))?;

    for reply in cookie {
        let reply = reply.map_err(|e| format!("record reply: {}", e))?;
        let mut off = 0usize;
        while off + DATUM_LEN <= reply.data.len() {
            let datum = &reply.data[off..off + DATUM_LEN];
            let event_type = datum[SERVER_TIME_LEN];
            let keycode = datum[SERVER_TIME_LEN + 1] as u16 - X_KEYCODE_OFFSET;
            let action = match event_type {
                KEY_PRESS => Action::Press,
                KEY_RELEASE => Action::Release,
                _ => {
                    off += DATUM_LEN;
                    continue;
                }
            };
            if let Some(event) = decoder.feed(Source::X11, keycode, action) {
                on_key(event);
            }
            off += DATUM_LEN;
        }
    }

    Ok(())
}
