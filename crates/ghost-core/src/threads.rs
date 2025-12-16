//! Thread enumeration and management
//!
//! Provides functionality to enumerate threads, get/set thread context, and manage thread state.

use ghost_common::{Error, Registers, Result, Thread, ThreadState};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{
    GetThreadContext, SetThreadContext, CONTEXT, CONTEXT_FLAGS,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::Threading::{
    GetCurrentProcessId, OpenThread, ResumeThread, SuspendThread, THREAD_GET_CONTEXT,
    THREAD_QUERY_INFORMATION, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
};

/// Enumerate all threads in the current process
pub fn enumerate_threads() -> Result<Vec<Thread>> {
    enumerate_threads_for_process(unsafe { GetCurrentProcessId() })
}

/// Enumerate all threads for a specific process
pub fn enumerate_threads_for_process(pid: u32) -> Result<Vec<Thread>> {
    let mut threads = Vec::new();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            .map_err(|e| Error::Internal(format!("CreateToolhelp32Snapshot failed: {}", e)))?;

        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        if Thread32First(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32OwnerProcessID == pid {
                    threads.push(Thread {
                        id: entry.th32ThreadID,
                        base_priority: entry.tpBasePri,
                        state: ThreadState::Unknown, // Would need NtQueryInformationThread for actual state
                    });
                }

                entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                if Thread32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
    }

    Ok(threads)
}

/// Get the thread context (registers) for a thread
#[cfg(target_arch = "x86_64")]
pub fn get_thread_context(tid: u32) -> Result<Registers> {
    unsafe {
        let handle = OpenThread(
            THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME,
            false,
            tid,
        )
        .map_err(|e| Error::Internal(format!("OpenThread failed: {}", e)))?;

        // Suspend thread to get consistent context
        let suspend_count = SuspendThread(handle);
        if suspend_count == u32::MAX {
            let _ = CloseHandle(handle);
            return Err(Error::Internal("SuspendThread failed".into()));
        }

        let mut context = CONTEXT {
            ContextFlags: CONTEXT_FLAGS(0x10001F), // CONTEXT_ALL
            ..Default::default()
        };

        let result = GetThreadContext(handle, &mut context);

        // Resume the thread
        ResumeThread(handle);
        let _ = CloseHandle(handle);

        if result.is_err() {
            return Err(Error::Internal("GetThreadContext failed".into()));
        }

        Ok(context_to_registers(&context))
    }
}

/// Set the thread context (registers) for a thread
#[cfg(target_arch = "x86_64")]
pub fn set_thread_context(tid: u32, regs: &Registers) -> Result<()> {
    unsafe {
        let handle = OpenThread(
            THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME,
            false,
            tid,
        )
        .map_err(|e| Error::Internal(format!("OpenThread failed: {}", e)))?;

        // Suspend thread to set context
        let suspend_count = SuspendThread(handle);
        if suspend_count == u32::MAX {
            let _ = CloseHandle(handle);
            return Err(Error::Internal("SuspendThread failed".into()));
        }

        // Get current context first to preserve flags we're not modifying
        let mut context = CONTEXT {
            ContextFlags: CONTEXT_FLAGS(0x10001F), // CONTEXT_ALL
            ..Default::default()
        };

        if GetThreadContext(handle, &mut context).is_err() {
            ResumeThread(handle);
            let _ = CloseHandle(handle);
            return Err(Error::Internal("GetThreadContext failed".into()));
        }

        // Update with new register values
        registers_to_context(regs, &mut context);

        let result = SetThreadContext(handle, &context);

        // Resume the thread
        ResumeThread(handle);
        let _ = CloseHandle(handle);

        if result.is_err() {
            return Err(Error::Internal("SetThreadContext failed".into()));
        }

        Ok(())
    }
}

/// Suspend a thread
pub fn suspend_thread(tid: u32) -> Result<u32> {
    unsafe {
        let handle = OpenThread(THREAD_SUSPEND_RESUME, false, tid)
            .map_err(|e| Error::Internal(format!("OpenThread failed: {}", e)))?;

        let count = SuspendThread(handle);
        let _ = CloseHandle(handle);

        if count == u32::MAX {
            return Err(Error::Internal("SuspendThread failed".into()));
        }

        Ok(count)
    }
}

/// Resume a thread
pub fn resume_thread(tid: u32) -> Result<u32> {
    unsafe {
        let handle = OpenThread(THREAD_SUSPEND_RESUME, false, tid)
            .map_err(|e| Error::Internal(format!("OpenThread failed: {}", e)))?;

        let count = ResumeThread(handle);
        let _ = CloseHandle(handle);

        if count == u32::MAX {
            return Err(Error::Internal("ResumeThread failed".into()));
        }

        Ok(count)
    }
}

/// Get the raw CONTEXT structure for a thread (for stack walking, etc.)
#[cfg(target_arch = "x86_64")]
pub fn get_thread_context_raw(tid: u32) -> Result<CONTEXT> {
    unsafe {
        let handle = OpenThread(
            THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME,
            false,
            tid,
        )
        .map_err(|e| Error::Internal(format!("OpenThread failed: {}", e)))?;

        // Suspend thread to get consistent context
        let suspend_count = SuspendThread(handle);
        if suspend_count == u32::MAX {
            let _ = CloseHandle(handle);
            return Err(Error::Internal("SuspendThread failed".into()));
        }

        let mut context = CONTEXT {
            ContextFlags: CONTEXT_FLAGS(0x10001F), // CONTEXT_ALL
            ..Default::default()
        };

        let result = GetThreadContext(handle, &mut context);

        // Resume the thread
        ResumeThread(handle);
        let _ = CloseHandle(handle);

        if result.is_err() {
            return Err(Error::Internal("GetThreadContext failed".into()));
        }

        Ok(context)
    }
}

/// Open a thread handle
pub fn open_thread_handle(tid: u32, access: u32) -> Result<HANDLE> {
    unsafe {
        OpenThread(
            windows::Win32::System::Threading::THREAD_ACCESS_RIGHTS(access),
            false,
            tid,
        )
        .map_err(|e| Error::Internal(format!("OpenThread failed: {}", e)))
    }
}

/// Convert Windows CONTEXT to our Registers struct
#[cfg(target_arch = "x86_64")]
pub fn context_to_registers(ctx: &CONTEXT) -> Registers {
    Registers {
        rax: ctx.Rax,
        rbx: ctx.Rbx,
        rcx: ctx.Rcx,
        rdx: ctx.Rdx,
        rsi: ctx.Rsi,
        rdi: ctx.Rdi,
        rbp: ctx.Rbp,
        rsp: ctx.Rsp,
        r8: ctx.R8,
        r9: ctx.R9,
        r10: ctx.R10,
        r11: ctx.R11,
        r12: ctx.R12,
        r13: ctx.R13,
        r14: ctx.R14,
        r15: ctx.R15,
        rip: ctx.Rip,
        rflags: ctx.EFlags as u64,
    }
}

/// Update Windows CONTEXT from our Registers struct
#[cfg(target_arch = "x86_64")]
pub fn registers_to_context(regs: &Registers, ctx: &mut CONTEXT) {
    ctx.Rax = regs.rax;
    ctx.Rbx = regs.rbx;
    ctx.Rcx = regs.rcx;
    ctx.Rdx = regs.rdx;
    ctx.Rsi = regs.rsi;
    ctx.Rdi = regs.rdi;
    ctx.Rbp = regs.rbp;
    ctx.Rsp = regs.rsp;
    ctx.R8 = regs.r8;
    ctx.R9 = regs.r9;
    ctx.R10 = regs.r10;
    ctx.R11 = regs.r11;
    ctx.R12 = regs.r12;
    ctx.R13 = regs.r13;
    ctx.R14 = regs.r14;
    ctx.R15 = regs.r15;
    ctx.Rip = regs.rip;
    ctx.EFlags = regs.rflags as u32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enumerate_threads() {
        let threads = enumerate_threads();
        assert!(threads.is_ok());
        let threads = threads.unwrap();
        // Current process should have at least one thread
        assert!(!threads.is_empty());
    }

    #[test]
    fn test_context_round_trip() {
        let regs = Registers {
            rax: 0x1111,
            rbx: 0x2222,
            rcx: 0x3333,
            rdx: 0x4444,
            rsi: 0x5555,
            rdi: 0x6666,
            rbp: 0x7777,
            rsp: 0x8888,
            r8: 0x9999,
            r9: 0xAAAA,
            r10: 0xBBBB,
            r11: 0xCCCC,
            r12: 0xDDDD,
            r13: 0xEEEE,
            r14: 0xFFFF,
            r15: 0x1234,
            rip: 0x5678,
            rflags: 0x246,
        };

        let mut ctx = CONTEXT::default();
        registers_to_context(&regs, &mut ctx);
        let regs2 = context_to_registers(&ctx);

        assert_eq!(regs.rax, regs2.rax);
        assert_eq!(regs.rbx, regs2.rbx);
        assert_eq!(regs.rip, regs2.rip);
    }
}
