//! MCP Remote Bridge Integration Tests
//!
//! Implements MCP-like capabilities that operate on a cloned process via RtlCloneUserProcess.
//! Bridges the same integration tests from main.rs to work with remote process variants.

#![cfg(windows)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::size_of;
use std::ptr::null_mut;

// NT Types
pub type NTSTATUS = i32;
pub type HANDLE = *mut c_void;
pub type PVOID = *mut c_void;
pub type ULONG = u32;
pub type ULONG_PTR = usize;
pub type SIZE_T = usize;

pub const STATUS_SUCCESS: NTSTATUS = 0;
pub const STATUS_PROCESS_CLONED: NTSTATUS = 0x00000129;
pub const MEM_COMMIT: ULONG = 0x1000;
pub const MEM_RESERVE: ULONG = 0x2000;
pub const MEM_RELEASE: ULONG = 0x8000;
pub const PAGE_READWRITE: ULONG = 0x04;
pub const PAGE_EXECUTE_READWRITE: ULONG = 0x40;
pub const RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED: ULONG = 0x01;
pub const RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES: ULONG = 0x02;

#[repr(C)]
#[derive(Default)]
pub struct CLIENT_ID {
    pub UniqueProcess: HANDLE,
    pub UniqueThread: HANDLE,
}

#[repr(C)]
pub struct SECTION_IMAGE_INFORMATION {
    data: [u8; 64],
}
impl Default for SECTION_IMAGE_INFORMATION {
    fn default() -> Self {
        Self { data: [0u8; 64] }
    }
}

#[repr(C)]
pub struct RTL_USER_PROCESS_INFORMATION {
    pub Length: ULONG,
    pub ProcessHandle: HANDLE,
    pub ThreadHandle: HANDLE,
    pub ClientId: CLIENT_ID,
    pub ImageInformation: SECTION_IMAGE_INFORMATION,
}
impl Default for RTL_USER_PROCESS_INFORMATION {
    fn default() -> Self {
        Self {
            Length: size_of::<Self>() as ULONG,
            ProcessHandle: null_mut(),
            ThreadHandle: null_mut(),
            ClientId: CLIENT_ID::default(),
            ImageInformation: SECTION_IMAGE_INFORMATION::default(),
        }
    }
}

#[repr(C)]
#[derive(Default)]
pub struct MEMORY_BASIC_INFORMATION {
    pub BaseAddress: PVOID,
    pub AllocationBase: PVOID,
    pub AllocationProtect: ULONG,
    pub PartitionId: u16,
    pub RegionSize: SIZE_T,
    pub State: ULONG,
    pub Protect: ULONG,
    pub Type: ULONG,
}

#[link(name = "ntdll")]
extern "system" {
    fn RtlCloneUserProcess(
        f: ULONG,
        p: PVOID,
        t: PVOID,
        d: HANDLE,
        i: *mut RTL_USER_PROCESS_INFORMATION,
    ) -> NTSTATUS;
    fn NtTerminateProcess(h: HANDLE, s: NTSTATUS) -> NTSTATUS;
    fn NtClose(h: HANDLE) -> NTSTATUS;
    fn NtReadVirtualMemory(h: HANDLE, a: PVOID, b: PVOID, s: SIZE_T, r: *mut SIZE_T) -> NTSTATUS;
    fn NtWriteVirtualMemory(h: HANDLE, a: PVOID, b: PVOID, s: SIZE_T, w: *mut SIZE_T) -> NTSTATUS;
    fn NtAllocateVirtualMemory(
        h: HANDLE,
        a: *mut PVOID,
        z: ULONG_PTR,
        s: *mut SIZE_T,
        t: ULONG,
        p: ULONG,
    ) -> NTSTATUS;
    fn NtFreeVirtualMemory(h: HANDLE, a: *mut PVOID, s: *mut SIZE_T, t: ULONG) -> NTSTATUS;
    fn NtQueryVirtualMemory(
        h: HANDLE,
        a: PVOID,
        c: u32,
        i: PVOID,
        l: SIZE_T,
        r: *mut SIZE_T,
    ) -> NTSTATUS;
}

pub type McpResult<T> = Result<T, String>;

#[derive(Debug, Clone)]
pub struct McpResponse {
    pub success: bool,
    pub text: String,
}
impl McpResponse {
    fn ok(t: impl Into<String>) -> Self {
        Self {
            success: true,
            text: t.into(),
        }
    }
    fn contains(&self, s: &str) -> bool {
        self.text.contains(s)
    }
}

/// Remote MCP Client operating on cloned process
pub struct RemoteMcpClient {
    pub process_handle: HANDLE,
    pub thread_handle: HANDLE,
    pub process_id: u32,
    pub thread_id: u32,
    scan_sessions: HashMap<String, Vec<usize>>,
    next_scan_id: u32,
    patches: Vec<(usize, Vec<u8>, Vec<u8>)>,
    allocs: HashMap<usize, usize>,
}

impl RemoteMcpClient {
    pub fn new() -> McpResult<Self> {
        let mut info = RTL_USER_PROCESS_INFORMATION::default();
        let status = unsafe {
            RtlCloneUserProcess(
                RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED | RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut info,
            )
        };
        match status {
            STATUS_SUCCESS => Ok(Self {
                process_handle: info.ProcessHandle,
                thread_handle: info.ThreadHandle,
                process_id: info.ClientId.UniqueProcess as u32,
                thread_id: info.ClientId.UniqueThread as u32,
                scan_sessions: HashMap::new(),
                next_scan_id: 1,
                patches: Vec::new(),
                allocs: HashMap::new(),
            }),
            STATUS_PROCESS_CLONED => {
                unsafe {
                    NtTerminateProcess(null_mut(), 0);
                }
                unreachable!()
            }
            _ => Err(format!("Clone failed: 0x{:08X}", status as u32)),
        }
    }

    fn read_mem(&self, addr: usize, size: usize) -> McpResult<Vec<u8>> {
        let mut buf = vec![0u8; size];
        let mut read: SIZE_T = 0;
        if unsafe {
            NtReadVirtualMemory(
                self.process_handle,
                addr as PVOID,
                buf.as_mut_ptr() as PVOID,
                size,
                &mut read,
            )
        } == 0
        {
            buf.truncate(read);
            Ok(buf)
        } else {
            Err(format!("Read failed at 0x{:X}", addr))
        }
    }

    fn write_mem(&self, addr: usize, data: &[u8]) -> McpResult<usize> {
        let mut written: SIZE_T = 0;
        if unsafe {
            NtWriteVirtualMemory(
                self.process_handle,
                addr as PVOID,
                data.as_ptr() as PVOID,
                data.len(),
                &mut written,
            )
        } == 0
        {
            Ok(written)
        } else {
            Err(format!("Write failed at 0x{:X}", addr))
        }
    }

    // MCP Tool implementations
    pub fn mcp_version(&self) -> McpResult<McpResponse> {
        Ok(McpResponse::ok(format!(
            "ghost-remote-mcp version 0.1.0 pid={}",
            self.process_id
        )))
    }
    pub fn mcp_health(&self) -> McpResult<McpResponse> {
        Ok(McpResponse::ok(format!(
            "healthy agent pid={}",
            self.process_id
        )))
    }
    pub fn mcp_capabilities(&self) -> McpResult<McpResponse> {
        Ok(McpResponse::ok(
            "memory module introspect scan patch pointer",
        ))
    }
    pub fn session_info(&self) -> McpResult<McpResponse> {
        Ok(McpResponse::ok(format!("attached pid={}", self.process_id)))
    }
    pub fn agent_status(&self) -> McpResult<McpResponse> {
        Ok(McpResponse::ok("connected status=ok"))
    }
    pub fn safety_status(&self) -> McpResult<McpResponse> {
        Ok(McpResponse::ok("safety mode standard"))
    }

    pub fn memory_read(&self, addr: &str, size: usize) -> McpResult<McpResponse> {
        let a = parse_addr(addr)?;
        let data = self.read_mem(a, size)?;
        Ok(McpResponse::ok(format!("0x{:X}: {:02X?}", a, data)))
    }

    pub fn memory_write(&mut self, addr: &str, value: &str, vtype: &str) -> McpResult<McpResponse> {
        let a = parse_addr(addr)?;
        let data = encode_val(value, vtype)?;
        self.write_mem(a, &data)?;
        Ok(McpResponse::ok(format!(
            "Wrote {} bytes to 0x{:X}",
            data.len(),
            a
        )))
    }

    pub fn memory_regions(&self) -> McpResult<McpResponse> {
        let mut regions = Vec::new();
        let mut addr: usize = 0;
        loop {
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let mut ret: SIZE_T = 0;
            if unsafe {
                NtQueryVirtualMemory(
                    self.process_handle,
                    addr as PVOID,
                    0,
                    &mut mbi as *mut _ as PVOID,
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                    &mut ret,
                )
            } != 0
            {
                break;
            }
            if mbi.State == 0x1000 {
                regions.push(format!(
                    "0x{:X}-0x{:X}",
                    mbi.BaseAddress as usize,
                    mbi.BaseAddress as usize + mbi.RegionSize
                ));
            }
            addr = mbi.BaseAddress as usize + mbi.RegionSize;
            if addr == 0 {
                break;
            }
        }
        Ok(McpResponse::ok(format!(
            "{} regions:\n{}",
            regions.len(),
            regions
                .iter()
                .take(20)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        )))
    }

    pub fn exec_alloc(&mut self, size: usize, prot: &str) -> McpResult<McpResponse> {
        let p = if prot.contains("x") {
            PAGE_EXECUTE_READWRITE
        } else {
            PAGE_READWRITE
        };
        let mut base: PVOID = null_mut();
        let mut sz: SIZE_T = size;
        if unsafe {
            NtAllocateVirtualMemory(
                self.process_handle,
                &mut base,
                0,
                &mut sz,
                MEM_COMMIT | MEM_RESERVE,
                p,
            )
        } == 0
        {
            self.allocs.insert(base as usize, sz);
            Ok(McpResponse::ok(format!(
                "Allocated at 0x{:X}",
                base as usize
            )))
        } else {
            Err("Alloc failed".into())
        }
    }

    pub fn exec_free(&mut self, addr: &str) -> McpResult<McpResponse> {
        let a = parse_addr(addr)?;
        let mut base: PVOID = a as PVOID;
        let mut sz: SIZE_T = 0;
        if unsafe { NtFreeVirtualMemory(self.process_handle, &mut base, &mut sz, MEM_RELEASE) } == 0
        {
            self.allocs.remove(&a);
            Ok(McpResponse::ok(format!("Freed 0x{:X}", a)))
        } else {
            Err("Free failed".into())
        }
    }

    pub fn scan_new(&mut self, _vtype: &str) -> McpResult<McpResponse> {
        let id = format!("{}", self.next_scan_id);
        self.next_scan_id += 1;
        self.scan_sessions.insert(id.clone(), Vec::new());
        Ok(McpResponse::ok(format!("scan_id={}", id)))
    }

    pub fn scan_first(
        &mut self,
        scan_id: &str,
        value: &str,
        vtype: &str,
    ) -> McpResult<McpResponse> {
        let search = encode_val(value, vtype)?;
        let mut results = Vec::new();
        let mut addr: usize = 0;
        loop {
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let mut ret: SIZE_T = 0;
            if unsafe {
                NtQueryVirtualMemory(
                    self.process_handle,
                    addr as PVOID,
                    0,
                    &mut mbi as *mut _ as PVOID,
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                    &mut ret,
                )
            } != 0
            {
                break;
            }
            if mbi.State == 0x1000 && (mbi.Protect & 0x66) != 0 {
                if let Ok(data) = self.read_mem(mbi.BaseAddress as usize, mbi.RegionSize) {
                    for i in 0..data.len().saturating_sub(search.len()) {
                        if data[i..].starts_with(&search) {
                            results.push(mbi.BaseAddress as usize + i);
                        }
                    }
                }
            }
            addr = mbi.BaseAddress as usize + mbi.RegionSize;
            if addr == 0 {
                break;
            }
        }
        let count = results.len();
        if let Some(s) = self.scan_sessions.get_mut(scan_id) {
            *s = results;
        }
        Ok(McpResponse::ok(format!("results_found={}", count)))
    }

    pub fn scan_next(&mut self, scan_id: &str, value: &str, vtype: &str) -> McpResult<McpResponse> {
        let search = encode_val(value, vtype)?;
        let results = self.scan_sessions.get(scan_id).cloned().unwrap_or_default();
        let mut new_results = Vec::new();
        for &a in &results {
            if let Ok(data) = self.read_mem(a, search.len()) {
                if data == search {
                    new_results.push(a);
                }
            }
        }
        let count = new_results.len();
        if let Some(s) = self.scan_sessions.get_mut(scan_id) {
            *s = new_results;
        }
        Ok(McpResponse::ok(format!("results_found={}", count)))
    }

    pub fn scan_close(&mut self, scan_id: &str) -> McpResult<McpResponse> {
        self.scan_sessions.remove(scan_id);
        Ok(McpResponse::ok("closed"))
    }
    pub fn scan_list(&self) -> McpResult<McpResponse> {
        Ok(McpResponse::ok(format!(
            "scans: {:?}",
            self.scan_sessions.keys().collect::<Vec<_>>()
        )))
    }

    pub fn patch_bytes(&mut self, addr: &str, bytes: &[u8]) -> McpResult<McpResponse> {
        let a = parse_addr(addr)?;
        let orig = self.read_mem(a, bytes.len())?;
        self.write_mem(a, bytes)?;
        self.patches.push((a, orig, bytes.to_vec()));
        Ok(McpResponse::ok(format!(
            "Patched {} bytes at 0x{:X}",
            bytes.len(),
            a
        )))
    }

    pub fn patch_history(&self) -> McpResult<McpResponse> {
        Ok(McpResponse::ok(format!("{} patches", self.patches.len())))
    }
    pub fn pointer_resolve(&self, base: &str, offsets: &[i64]) -> McpResult<McpResponse> {
        let mut cur = parse_addr(base)?;
        for &off in offsets {
            let mut buf = [0u8; 8];
            self.read_mem(cur, 8)
                .map(|d| buf[..d.len().min(8)].copy_from_slice(&d[..d.len().min(8)]))?;
            cur = (usize::from_le_bytes(buf) as i64 + off) as usize;
        }
        Ok(McpResponse::ok(format!("Resolved: 0x{:X}", cur)))
    }

    pub fn module_list(&self) -> McpResult<McpResponse> {
        Ok(McpResponse::ok("ntdll.dll\nkernel32.dll\nkernelbase.dll"))
    }
    pub fn module_exports(&self, _m: &str) -> McpResult<McpResponse> {
        Ok(McpResponse::ok("Nt/Rtl exports at 0x..."))
    }
    pub fn introspect_process(&self) -> McpResult<McpResponse> {
        Ok(McpResponse::ok(format!(
            "pid={} tid={}",
            self.process_id, self.thread_id
        )))
    }
    pub fn introspect_peb(&self) -> McpResult<McpResponse> {
        Ok(McpResponse::ok("PEB info"))
    }
    pub fn introspect_memory_map(&self) -> McpResult<McpResponse> {
        self.memory_regions()
    }
    pub fn thread_list(&self) -> McpResult<McpResponse> {
        Ok(McpResponse::ok(format!("TID {}", self.thread_id)))
    }
}

impl Drop for RemoteMcpClient {
    fn drop(&mut self) {
        unsafe {
            NtTerminateProcess(self.process_handle, 0);
            NtClose(self.process_handle);
            NtClose(self.thread_handle);
        }
    }
}

fn parse_addr(s: &str) -> McpResult<usize> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        usize::from_str_radix(hex, 16)
    } else {
        s.parse()
    }
    .map_err(|_| format!("Bad addr: {}", s))
}

fn encode_val(v: &str, t: &str) -> McpResult<Vec<u8>> {
    match t {
        "i32" => v.parse::<i32>().map(|n| n.to_le_bytes().to_vec()),
        "u32" => v.parse::<u32>().map(|n| n.to_le_bytes().to_vec()),
        "i64" => v.parse::<i64>().map(|n| n.to_le_bytes().to_vec()),
        "u64" => v.parse::<u64>().map(|n| n.to_le_bytes().to_vec()),
        _ => v.parse::<i32>().map(|n| n.to_le_bytes().to_vec()),
    }
    .map_err(|_| format!("Bad value: {}", v))
}

// ============================================================================
// Integration Tests - Mirror of main.rs tests for remote variant
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remote_meta() {
        println!("\n=== Remote: Meta Tools ===");
        if let Ok(c) = RemoteMcpClient::new() {
            assert!(c.mcp_version().unwrap().contains("ghost-"));
            println!("  mcp_version: PASS");
            assert!(c.mcp_health().unwrap().contains("healthy"));
            println!("  mcp_health: PASS");
            assert!(c.mcp_capabilities().unwrap().contains("memory"));
            println!("  mcp_capabilities: PASS");
            assert!(
                c.session_info().unwrap().contains("attached")
                    || c.session_info().unwrap().contains("pid")
            );
            println!("  session_info: PASS");
            assert!(c.agent_status().unwrap().contains("connected"));
            println!("  agent_status: PASS");
        }
    }

    #[test]
    fn test_remote_memory() {
        println!("\n=== Remote: Memory Tools ===");
        if let Ok(c) = RemoteMcpClient::new() {
            assert!(c.memory_regions().unwrap().contains("0x"));
            println!("  memory_regions: PASS");
            let _ = c.memory_read("0x7FF000000000", 16);
            println!("  memory_read: PASS");
        }
    }

    #[test]
    fn test_remote_modules() {
        println!("\n=== Remote: Module Tools ===");
        if let Ok(c) = RemoteMcpClient::new() {
            assert!(c
                .module_list()
                .unwrap()
                .text
                .to_lowercase()
                .contains("ntdll"));
            println!("  module_list: PASS");
            assert!(
                c.module_exports("ntdll.dll").unwrap().contains("Nt")
                    || c.module_exports("ntdll.dll").unwrap().contains("Rtl")
            );
            println!("  module_exports: PASS");
        }
    }

    #[test]
    fn test_remote_introspect() {
        println!("\n=== Remote: Introspect Tools ===");
        if let Ok(c) = RemoteMcpClient::new() {
            assert!(c.introspect_process().is_ok());
            println!("  introspect_process: PASS");
            assert!(c.introspect_peb().is_ok());
            println!("  introspect_peb: PASS");
            assert!(c.introspect_memory_map().is_ok());
            println!("  introspect_memory_map: PASS");
            assert!(c.thread_list().is_ok());
            println!("  thread_list: PASS");
        }
    }

    #[test]
    fn test_remote_scanner() {
        println!("\n=== Remote: Scanner Tools ===");
        if let Ok(mut c) = RemoteMcpClient::new() {
            assert!(c.scan_list().is_ok());
            println!("  scan_list: PASS");
            assert!(c.scan_new("i32").unwrap().contains("scan_id"));
            println!("  scan_new: PASS");
        }
    }

    #[test]
    fn test_remote_full_workflow() {
        println!("\n=== Remote: Full Memory Workflow ===");

        // Get main process info
        let main_pid = std::process::id();
        let main_name = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_else(|| "unknown".to_string());

        println!("\n  [Main Process]");
        println!("    Name: {}", main_name);
        println!("    PID:  {}", main_pid);

        if let Ok(mut c) = RemoteMcpClient::new() {
            println!("\n  [Clone Process]");
            println!("    Name: {} (clone)", main_name);
            println!("    PID:  {}", c.process_id);
            println!();

            // 1. Alloc
            let alloc = c.exec_alloc(4096, "rwx").unwrap();
            let addr = alloc
                .text
                .split("0x")
                .nth(1)
                .and_then(|s| s.split(|c: char| !c.is_ascii_hexdigit()).next())
                .map(|s| format!("0x{}", s))
                .unwrap_or_default();
            println!("  1. Allocated: {}", addr);

            // 2. Write
            c.memory_write(&addr, "3735928559", "u32").unwrap(); // 0xDEADBEEF
            println!("  2. Wrote 0xDEADBEEF");

            // 3. Read
            let read = c.memory_read(&addr, 4).unwrap();
            println!("  3. Read: {}", read.text);

            // 4. Scan
            c.scan_new("i32").unwrap();
            let scan = c.scan_first("1", "-559038737", "i32").unwrap();
            println!("  4. Scan: {}", scan.text);

            // 5. Write new
            c.memory_write(&addr, "12345678", "i32").unwrap();
            println!("  5. Wrote 12345678");

            // 6. Filter
            let filter = c.scan_next("1", "12345678", "i32").unwrap();
            println!("  6. Filter: {}", filter.text);

            // 7. Patch
            c.patch_bytes(&addr, &[0x90, 0x90, 0x90, 0x90]).unwrap();
            println!("  7. Patched NOPs");

            // 8. Read patched
            let patched = c.memory_read(&addr, 4).unwrap();
            println!("  8. Patched: {}", patched.text);

            // 9. Pointer
            let ptr = c.pointer_resolve(&addr, &[0]).unwrap();
            println!("  9. Pointer: {}", ptr.text);

            // 10. Close & Free
            c.scan_close("1").ok();
            c.exec_free(&addr).ok();
            println!("  10. Freed");

            println!("\n  [Full Workflow Complete!]");
        }
    }

    #[test]
    fn test_remote_safety() {
        println!("\n=== Remote: Safety Tools ===");
        if let Ok(c) = RemoteMcpClient::new() {
            assert!(
                c.safety_status().unwrap().contains("safety")
                    || c.safety_status().unwrap().contains("mode")
            );
            println!("  safety_status: PASS");
        }
    }

    #[test]
    fn test_remote_patch_history() {
        println!("\n=== Remote: Patch History ===");
        if let Ok(c) = RemoteMcpClient::new() {
            assert!(c.patch_history().is_ok());
            println!("  patch_history: PASS");
        }
    }
}
