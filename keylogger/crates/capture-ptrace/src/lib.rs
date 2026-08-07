use keycore::{ByteEvent, Source};
use libc::{c_long, c_void, pid_t, execvp, fork, ptrace, waitpid};
use std::ffi::CString;
use std::ptr;

const SYS_READ: u64 = 0;

const PTRACE_GET_SYSCALL_INFO: libc::c_uint = 0x420e;
const PTRACE_SYSCALL_INFO_ENTRY: u8 = 1;
const PTRACE_SYSCALL_INFO_EXIT: u8 = 2;

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct SyscallEntry {
    nr: u64,
    args: [u64; 6],
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct SyscallExit {
    rval: i64,
    is_error: u8,
}

#[repr(C)]
union SyscallData {
    entry: SyscallEntry,
    exit: SyscallExit,
}

#[repr(C)]
struct SyscallInfo {
    op: u8,
    reserved: u8,
    flags: u16,
    arch: u32,
    instruction_pointer: u64,
    stack_pointer: u64,
    data: SyscallData,
}

impl Default for SyscallInfo {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

fn syscall_info(pid: pid_t) -> Result<SyscallInfo, String> {
    let mut info = SyscallInfo::default();
    let rc = unsafe {
        ptrace(
            PTRACE_GET_SYSCALL_INFO,
            pid,
            std::mem::size_of::<SyscallInfo>() as *mut c_void,
            &mut info as *mut SyscallInfo as *mut c_void,
        )
    };
    if rc < 0 {
        return Err(format!(
            "ptrace get_syscall_info: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(info)
}

fn peek_mem(pid: pid_t, addr: usize) -> Result<c_long, String> {
    unsafe {
        *libc::__errno_location() = 0;
        let value = ptrace(
            libc::PTRACE_PEEKDATA,
            pid,
            addr as *mut c_void,
            ptr::null_mut::<c_void>(),
        );
        if value == -1 && std::io::Error::last_os_error().raw_os_error() != Some(0) {
            return Err(format!(
                "ptrace peekdata: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(value)
    }
}

fn wait_stop(pid: pid_t) -> Result<(), String> {
    let mut status = 0;
    if unsafe { waitpid(pid, &mut status, 0) } < 0 {
        return Err(format!("waitpid: {}", std::io::Error::last_os_error()));
    }
    if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
        return Err("target exited".to_string());
    }
    Ok(())
}

fn enable_tracesysgood(pid: pid_t) -> Result<(), String> {
    unsafe {
        if ptrace(
            libc::PTRACE_SETOPTIONS,
            pid,
            ptr::null_mut::<c_void>(),
            libc::PTRACE_O_TRACESYSGOOD as *mut c_void,
        ) != 0
        {
            return Err(format!("ptrace setoptions: {}", std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

fn syscall_loop(pid: pid_t, on_bytes: &mut impl FnMut(&ByteEvent)) -> Result<(), String> {
    let mut pending_fd = -1i64;
    let mut pending_buf = 0usize;

    loop {
        unsafe {
            ptrace(libc::PTRACE_SYSCALL, pid, ptr::null_mut::<libc::c_void>(), ptr::null_mut::<libc::c_void>());
        }
        let mut status = 0;
        if unsafe { waitpid(pid, &mut status, 0) } < 0 {
            return Err(format!("waitpid: {}", std::io::Error::last_os_error()));
        }
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            return Ok(());
        }
        if libc::WIFSTOPPED(status) {
            let sig = libc::WSTOPSIG(status);
            if sig != (libc::SIGTRAP | 0x80) {
                unsafe {
                    ptrace(
                        libc::PTRACE_SYSCALL,
                        pid,
                        ptr::null_mut::<libc::c_void>(),
                        sig as *mut c_void,
                    );
                }
                continue;
            }
        }

        let info = syscall_info(pid)?;
        match info.op {
            PTRACE_SYSCALL_INFO_ENTRY => {
                let nr = unsafe { info.data.entry.nr };
                if nr == SYS_READ {
                    let args = unsafe { info.data.entry.args };
                    pending_fd = args[0] as i64;
                    pending_buf = args[1] as usize;
                }
            }
            PTRACE_SYSCALL_INFO_EXIT => {
                let rval = unsafe { info.data.exit.rval };
                let is_error = unsafe { info.data.exit.is_error };
                if pending_fd == 0 && is_error == 0 && rval > 0 {
                    let nread = rval as usize;
                    let mut bytes = Vec::with_capacity(nread);
                    let mut off = 0usize;
                    while off < nread {
                        let word = peek_mem(pid, pending_buf + off)? as u64;
                        let n = std::cmp::min(8, nread - off);
                        bytes.extend_from_slice(&word.to_le_bytes()[..n]);
                        off += 8;
                    }
                    on_bytes(&ByteEvent::new(Source::Ptrace, bytes));
                }
                pending_fd = -1;
                pending_buf = 0;
            }
            _ => {}
        }
    }
}

pub fn trace_pid(pid: pid_t, on_bytes: impl FnMut(&ByteEvent)) -> Result<(), String> {
    unsafe {
        if ptrace(libc::PTRACE_ATTACH, pid, ptr::null_mut::<libc::c_void>(), ptr::null_mut::<libc::c_void>()) != 0 {
            return Err(format!("ptrace attach: {}", std::io::Error::last_os_error()));
        }
    }
    wait_stop(pid)?;
    enable_tracesysgood(pid)?;
    eprintln!("[ptrace] attached to pid {}", pid);
    syscall_loop(pid, &mut Box::new(on_bytes))
}

pub fn spawn_and_trace(shell: &str, on_bytes: impl FnMut(&ByteEvent)) -> Result<(), String> {
    let shell = CString::new(shell).map_err(|_| "invalid shell path".to_string())?;
    let child = unsafe { fork() };
    if child == 0 {
        unsafe {
            ptrace(libc::PTRACE_TRACEME, 0, ptr::null_mut::<libc::c_void>(), ptr::null_mut::<libc::c_void>());
            let argv: [*const libc::c_char; 2] = [shell.as_ptr(), ptr::null()];
            execvp(shell.as_ptr(), argv.as_ptr());
        }
        std::process::exit(127);
    }
    if child < 0 {
        return Err(format!("fork: {}", std::io::Error::last_os_error()));
    }
    wait_stop(child)?;
    enable_tracesysgood(child)?;
    eprintln!("[ptrace] tracing child {} running {:?}", child, shell);
    syscall_loop(child, &mut Box::new(on_bytes))
}
