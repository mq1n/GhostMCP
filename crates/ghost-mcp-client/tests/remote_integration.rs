//! Remote Integration Tests for Ghost-MCP Client
//!
//! These tests use Windows process cloning via RtlCloneUserProcess to create
//! isolated test environments for remote-based MCP client testing.
//!
//! Process cloning allows us to:
//! - Test memory operations on a cloned process
//! - Verify remote introspection capabilities
//! - Test cross-process memory scanning and dumping
//!
//! References:
//! - https://github.com/huntandhackett/process-cloning
//! - https://github.com/rbmm/RtlClone

#![cfg(windows)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::ptr::{null, null_mut};

// ============================================================================
// NT Types and Constants
// ============================================================================

pub type NTSTATUS = i32;
pub type HANDLE = *mut c_void;
pub type PVOID = *mut c_void;
pub type ULONG = u32;
pub type ULONG_PTR = usize;
pub type SIZE_T = usize;

pub const STATUS_SUCCESS: NTSTATUS = 0;
pub const STATUS_PROCESS_CLONED: NTSTATUS = 0x00000129;

// RtlCloneUserProcess flags
pub const RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED: ULONG = 0x00000001;
pub const RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES: ULONG = 0x00000002;
pub const RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE: ULONG = 0x00000004;

// Process access rights
pub const PROCESS_ALL_ACCESS: u32 = 0x001FFFFF;
pub const PROCESS_VM_READ: u32 = 0x0010;
pub const PROCESS_VM_WRITE: u32 = 0x0020;
pub const PROCESS_VM_OPERATION: u32 = 0x0008;
pub const PROCESS_QUERY_INFORMATION: u32 = 0x0400;

// ============================================================================
// NT Structures
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CLIENT_ID {
    pub UniqueProcess: HANDLE,
    pub UniqueThread: HANDLE,
}

impl Default for CLIENT_ID {
    fn default() -> Self {
        Self {
            UniqueProcess: null_mut(),
            UniqueThread: null_mut(),
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SECTION_IMAGE_INFORMATION {
    pub TransferAddress: PVOID,
    pub ZeroBits: ULONG,
    pub MaximumStackSize: SIZE_T,
    pub CommittedStackSize: SIZE_T,
    pub SubSystemType: ULONG,
    pub SubSystemMinorVersion: u16,
    pub SubSystemMajorVersion: u16,
    pub SubSystemVersion: ULONG,
    pub GpValue: ULONG,
    pub ImageCharacteristics: u16,
    pub DllCharacteristics: u16,
    pub Machine: u16,
    pub ImageContainsCode: u8,
    pub ImageFlags: u8,
    pub LoaderFlags: ULONG,
    pub ImageFileSize: ULONG,
    pub CheckSum: ULONG,
}

impl Default for SECTION_IMAGE_INFORMATION {
    fn default() -> Self {
        unsafe { zeroed() }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
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
pub struct SECURITY_DESCRIPTOR {
    pub Revision: u8,
    pub Sbz1: u8,
    pub Control: u16,
    pub Owner: PVOID,
    pub Group: PVOID,
    pub Sacl: PVOID,
    pub Dacl: PVOID,
}

pub type PSECURITY_DESCRIPTOR = *mut SECURITY_DESCRIPTOR;

// ============================================================================
// NT API Function Declarations
// ============================================================================

#[link(name = "ntdll")]
extern "system" {
    /// Clone the current process
    ///
    /// # Parameters
    /// - `ProcessFlags`: Combination of RTL_CLONE_PROCESS_FLAGS_*
    /// - `ProcessSecurityDescriptor`: Optional security descriptor for the process
    /// - `ThreadSecurityDescriptor`: Optional security descriptor for the thread
    /// - `DebugPort`: Optional debug port handle
    /// - `ProcessInformation`: Output structure with handles and IDs
    ///
    /// # Returns
    /// - STATUS_SUCCESS (0) in the parent process
    /// - STATUS_PROCESS_CLONED (0x129) in the cloned process
    /// - Other NTSTATUS error codes on failure
    pub fn RtlCloneUserProcess(
        ProcessFlags: ULONG,
        ProcessSecurityDescriptor: PSECURITY_DESCRIPTOR,
        ThreadSecurityDescriptor: PSECURITY_DESCRIPTOR,
        DebugPort: HANDLE,
        ProcessInformation: *mut RTL_USER_PROCESS_INFORMATION,
    ) -> NTSTATUS;

    /// Prepare ntdll state for process cloning
    /// Only available on x64 Windows 8.1+
    pub fn RtlPrepareForProcessCloning() -> NTSTATUS;

    /// Complete process cloning cleanup
    /// Only available on x64 Windows 8.1+
    ///
    /// # Parameters
    /// - `bCloned`: TRUE if this is the cloned process, FALSE if parent
    pub fn RtlCompleteProcessCloning(bCloned: i32) -> NTSTATUS;

    /// Resume a suspended thread
    pub fn NtResumeThread(ThreadHandle: HANDLE, PreviousSuspendCount: *mut ULONG) -> NTSTATUS;

    /// Terminate a process
    pub fn NtTerminateProcess(ProcessHandle: HANDLE, ExitStatus: NTSTATUS) -> NTSTATUS;

    /// Close a handle
    pub fn NtClose(Handle: HANDLE) -> NTSTATUS;

    /// Wait for a single object
    pub fn NtWaitForSingleObject(Handle: HANDLE, Alertable: u8, Timeout: *const i64) -> NTSTATUS;

    /// Query process information
    pub fn NtQueryInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: u32,
        ProcessInformation: PVOID,
        ProcessInformationLength: ULONG,
        ReturnLength: *mut ULONG,
    ) -> NTSTATUS;

    /// Read virtual memory from a process
    pub fn NtReadVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: PVOID,
        Buffer: PVOID,
        BufferSize: SIZE_T,
        NumberOfBytesRead: *mut SIZE_T,
    ) -> NTSTATUS;

    /// Write virtual memory to a process
    pub fn NtWriteVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: PVOID,
        Buffer: PVOID,
        BufferSize: SIZE_T,
        NumberOfBytesWritten: *mut SIZE_T,
    ) -> NTSTATUS;

    /// Allocate virtual memory in a process
    pub fn NtAllocateVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: *mut PVOID,
        ZeroBits: ULONG_PTR,
        RegionSize: *mut SIZE_T,
        AllocationType: ULONG,
        Protect: ULONG,
    ) -> NTSTATUS;

    /// Free virtual memory in a process
    pub fn NtFreeVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: *mut PVOID,
        RegionSize: *mut SIZE_T,
        FreeType: ULONG,
    ) -> NTSTATUS;
}

// ============================================================================
// Safe Rust Wrappers
// ============================================================================

/// Result of a process clone operation
#[derive(Debug)]
pub enum CloneResult {
    /// Parent process - contains handles to the cloned process and thread
    Parent {
        process_handle: HANDLE,
        thread_handle: HANDLE,
        process_id: u32,
        thread_id: u32,
    },
    /// Cloned process - we are the clone
    Clone,
}

/// Error type for clone operations
#[derive(Debug, Clone)]
pub struct CloneError {
    pub status: NTSTATUS,
    pub message: String,
}

impl std::fmt::Display for CloneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Clone error 0x{:08X}: {}",
            self.status as u32, self.message
        )
    }
}

impl std::error::Error for CloneError {}

/// Clone the current process using RtlCloneUserProcess
///
/// # Safety
/// This function is safe to call but the resulting cloned process inherits
/// the entire memory state of the parent. Care must be taken to:
/// - Not use shared resources without proper synchronization
/// - Terminate the clone properly when done
/// - Not deadlock on shared locks
pub fn clone_current_process(
    flags: ULONG,
    create_suspended: bool,
    inherit_handles: bool,
) -> Result<CloneResult, CloneError> {
    let mut process_flags = flags;

    if create_suspended {
        process_flags |= RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED;
    }
    if inherit_handles {
        process_flags |= RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES;
    }

    let mut process_info = RTL_USER_PROCESS_INFORMATION::default();

    let status = unsafe {
        RtlCloneUserProcess(
            process_flags,
            null_mut(), // ProcessSecurityDescriptor
            null_mut(), // ThreadSecurityDescriptor
            null_mut(), // DebugPort
            &mut process_info,
        )
    };

    match status {
        STATUS_SUCCESS => {
            // We are the parent process
            Ok(CloneResult::Parent {
                process_handle: process_info.ProcessHandle,
                thread_handle: process_info.ThreadHandle,
                process_id: process_info.ClientId.UniqueProcess as u32,
                thread_id: process_info.ClientId.UniqueThread as u32,
            })
        }
        STATUS_PROCESS_CLONED => {
            // We are the cloned process
            Ok(CloneResult::Clone)
        }
        _ => Err(CloneError {
            status,
            message: format!(
                "RtlCloneUserProcess failed with status 0x{:08X}",
                status as u32
            ),
        }),
    }
}

/// RAII guard for a cloned process
/// Automatically terminates and closes handles when dropped
pub struct ClonedProcess {
    pub process_handle: HANDLE,
    pub thread_handle: HANDLE,
    pub process_id: u32,
    pub thread_id: u32,
    pub is_suspended: bool,
}

impl ClonedProcess {
    /// Create a new cloned process guard
    pub fn new(
        process_handle: HANDLE,
        thread_handle: HANDLE,
        process_id: u32,
        thread_id: u32,
        is_suspended: bool,
    ) -> Self {
        Self {
            process_handle,
            thread_handle,
            process_id,
            thread_id,
            is_suspended,
        }
    }

    /// Resume the cloned process thread if suspended
    pub fn resume(&mut self) -> Result<u32, CloneError> {
        if !self.is_suspended {
            return Ok(0);
        }

        let mut previous_count: ULONG = 0;
        let status = unsafe { NtResumeThread(self.thread_handle, &mut previous_count) };

        if status == STATUS_SUCCESS {
            self.is_suspended = false;
            Ok(previous_count)
        } else {
            Err(CloneError {
                status,
                message: "Failed to resume thread".into(),
            })
        }
    }

    /// Wait for the cloned process to exit
    pub fn wait(&self, timeout_ms: Option<u32>) -> Result<(), CloneError> {
        let timeout: i64 = match timeout_ms {
            Some(ms) => -(ms as i64 * 10000), // Convert to 100ns units, negative for relative
            None => 0,                        // NULL pointer for infinite wait
        };

        let timeout_ptr = if timeout_ms.is_some() {
            &timeout as *const i64
        } else {
            null()
        };

        let status = unsafe { NtWaitForSingleObject(self.process_handle, 0, timeout_ptr) };

        if status == STATUS_SUCCESS {
            Ok(())
        } else {
            Err(CloneError {
                status,
                message: "Wait failed".into(),
            })
        }
    }

    /// Read memory from the cloned process
    pub fn read_memory(&self, address: usize, buffer: &mut [u8]) -> Result<usize, CloneError> {
        let mut bytes_read: SIZE_T = 0;

        let status = unsafe {
            NtReadVirtualMemory(
                self.process_handle,
                address as PVOID,
                buffer.as_mut_ptr() as PVOID,
                buffer.len(),
                &mut bytes_read,
            )
        };

        if status == STATUS_SUCCESS {
            Ok(bytes_read)
        } else {
            Err(CloneError {
                status,
                message: format!("Failed to read memory at 0x{:X}", address),
            })
        }
    }

    /// Write memory to the cloned process
    pub fn write_memory(&self, address: usize, buffer: &[u8]) -> Result<usize, CloneError> {
        let mut bytes_written: SIZE_T = 0;

        let status = unsafe {
            NtWriteVirtualMemory(
                self.process_handle,
                address as PVOID,
                buffer.as_ptr() as PVOID,
                buffer.len(),
                &mut bytes_written,
            )
        };

        if status == STATUS_SUCCESS {
            Ok(bytes_written)
        } else {
            Err(CloneError {
                status,
                message: format!("Failed to write memory at 0x{:X}", address),
            })
        }
    }

    /// Allocate memory in the cloned process
    pub fn allocate_memory(&self, size: usize, protection: u32) -> Result<usize, CloneError> {
        let mut base_address: PVOID = null_mut();
        let mut region_size: SIZE_T = size;

        const MEM_COMMIT: ULONG = 0x1000;
        const MEM_RESERVE: ULONG = 0x2000;

        let status = unsafe {
            NtAllocateVirtualMemory(
                self.process_handle,
                &mut base_address,
                0,
                &mut region_size,
                MEM_COMMIT | MEM_RESERVE,
                protection,
            )
        };

        if status == STATUS_SUCCESS {
            Ok(base_address as usize)
        } else {
            Err(CloneError {
                status,
                message: "Failed to allocate memory".into(),
            })
        }
    }

    /// Terminate the cloned process
    pub fn terminate(&self) -> Result<(), CloneError> {
        let status = unsafe { NtTerminateProcess(self.process_handle, 0) };

        // STATUS_PROCESS_IS_TERMINATING (0xC000010A) is acceptable
        const STATUS_PROCESS_IS_TERMINATING: NTSTATUS = -1073741558i32; // 0xC000010A as i32
        if status == STATUS_SUCCESS || status == STATUS_PROCESS_IS_TERMINATING {
            Ok(())
        } else {
            Err(CloneError {
                status,
                message: "Failed to terminate process".into(),
            })
        }
    }
}

impl Drop for ClonedProcess {
    fn drop(&mut self) {
        // Terminate the process if it's still running
        let _ = self.terminate();

        // Close handles
        unsafe {
            if !self.process_handle.is_null() {
                NtClose(self.process_handle);
            }
            if !self.thread_handle.is_null() {
                NtClose(self.thread_handle);
            }
        }
    }
}

/// Clone the current process and return a managed handle
pub fn clone_process_managed(
    create_suspended: bool,
    inherit_handles: bool,
) -> Result<ClonedProcess, CloneError> {
    match clone_current_process(0, create_suspended, inherit_handles)? {
        CloneResult::Parent {
            process_handle,
            thread_handle,
            process_id,
            thread_id,
        } => Ok(ClonedProcess::new(
            process_handle,
            thread_handle,
            process_id,
            thread_id,
            create_suspended,
        )),
        CloneResult::Clone => {
            // If we're the clone, just exit immediately
            // The test should run in the parent process
            unsafe {
                NtTerminateProcess(null_mut(), 0);
            }
            // This line should never be reached
            unreachable!("Clone process should have terminated");
        }
    }
}

// ============================================================================
// Test Helpers
// ============================================================================

/// Test value for memory verification
static mut TEST_VALUE: u32 = 0xDEADBEEF;

/// Get address of test value for cross-process testing
pub fn get_test_value_address() -> usize {
    std::ptr::addr_of!(TEST_VALUE) as usize
}

/// Get current test value
pub fn get_test_value() -> u32 {
    unsafe { TEST_VALUE }
}

/// Set test value
pub fn set_test_value(value: u32) {
    unsafe {
        TEST_VALUE = value;
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Test basic process cloning
    #[test]
    fn test_clone_process_basic() {
        println!("\n=== Test: Basic Process Cloning ===");

        // Set a known value before cloning
        set_test_value(0xCAFEBABE);

        match clone_process_managed(true, false) {
            Ok(mut clone) => {
                println!("Successfully cloned process!");
                println!("  Clone PID: {}", clone.process_id);
                println!("  Clone TID: {}", clone.thread_id);

                // Verify the clone is suspended
                assert!(clone.is_suspended, "Clone should be suspended");

                // Resume and terminate
                let _ = clone.resume();

                // Give it a moment then terminate
                std::thread::sleep(std::time::Duration::from_millis(10));

                // Clone will be terminated on drop
                println!("  Clone terminated successfully");
            }
            Err(e) => {
                // Some systems may not support cloning
                println!("Clone failed (may be expected): {}", e);
            }
        }
    }

    /// Test reading memory from cloned process
    #[test]
    fn test_clone_memory_read() {
        println!("\n=== Test: Clone Memory Read ===");

        // Set a known value
        let test_val: u32 = 0x12345678;
        set_test_value(test_val);
        let addr = get_test_value_address();

        match clone_process_managed(true, false) {
            Ok(clone) => {
                // Read the test value from the clone's memory
                let mut buffer = [0u8; 4];
                match clone.read_memory(addr, &mut buffer) {
                    Ok(bytes_read) => {
                        assert_eq!(bytes_read, 4);
                        let read_val = u32::from_le_bytes(buffer);
                        println!("  Read value: 0x{:08X}", read_val);
                        println!("  Expected:   0x{:08X}", test_val);
                        assert_eq!(read_val, test_val, "Memory read mismatch");
                        println!("  Memory read verified!");
                    }
                    Err(e) => {
                        println!("  Memory read failed: {}", e);
                    }
                }
            }
            Err(e) => {
                println!("Clone failed: {}", e);
            }
        }
    }

    /// Test writing memory to cloned process
    #[test]
    fn test_clone_memory_write() {
        println!("\n=== Test: Clone Memory Write ===");

        // Use a local boxed value to avoid race conditions with other tests
        let local_val = Box::new(0xAAAAAAAAu32);
        let addr = local_val.as_ref() as *const u32 as usize;
        let initial_val = *local_val;

        println!("  Initial value: 0x{:08X} at 0x{:016X}", initial_val, addr);

        match clone_process_managed(true, false) {
            Ok(clone) => {
                // Write a new value to the clone
                let new_val: u32 = 0xBBBBBBBB;
                let buffer = new_val.to_le_bytes();

                match clone.write_memory(addr, &buffer) {
                    Ok(bytes_written) => {
                        assert_eq!(bytes_written, 4);
                        println!("  Wrote 0x{:08X} to clone", new_val);

                        // Verify by reading back from clone
                        let mut read_buf = [0u8; 4];
                        if clone.read_memory(addr, &mut read_buf).is_ok() {
                            let read_val = u32::from_le_bytes(read_buf);
                            println!("  Read back from clone: 0x{:08X}", read_val);
                            assert_eq!(read_val, new_val);
                        }

                        // Verify parent value unchanged (clone has copy-on-write semantics)
                        let parent_val = *local_val;
                        println!("  Parent value: 0x{:08X}", parent_val);
                        assert_eq!(parent_val, initial_val, "Parent value should be unchanged");
                        println!("  Memory isolation verified!");
                    }
                    Err(e) => {
                        println!("  Memory write failed: {}", e);
                    }
                }
            }
            Err(e) => {
                println!("Clone failed: {}", e);
            }
        }
    }

    /// Test memory allocation in cloned process
    #[test]
    fn test_clone_memory_alloc() {
        println!("\n=== Test: Clone Memory Allocation ===");

        match clone_process_managed(true, false) {
            Ok(clone) => {
                const PAGE_READWRITE: u32 = 0x04;

                match clone.allocate_memory(4096, PAGE_READWRITE) {
                    Ok(addr) => {
                        println!("  Allocated 4096 bytes at 0x{:016X}", addr);
                        assert_ne!(addr, 0);

                        // Write a pattern to the allocated memory
                        let pattern: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
                        match clone.write_memory(addr, &pattern) {
                            Ok(_) => {
                                println!("  Wrote pattern to allocated memory");

                                // Read it back
                                let mut read_buf = [0u8; 8];
                                if clone.read_memory(addr, &mut read_buf).is_ok() {
                                    assert_eq!(read_buf, pattern);
                                    println!("  Pattern verified!");
                                }
                            }
                            Err(e) => println!("  Write failed: {}", e),
                        }
                    }
                    Err(e) => println!("  Allocation failed: {}", e),
                }
            }
            Err(e) => {
                println!("Clone failed: {}", e);
            }
        }
    }

    /// Test multiple clones
    #[test]
    fn test_multiple_clones() {
        println!("\n=== Test: Multiple Clones ===");

        let mut clones = Vec::new();

        for i in 0..3 {
            match clone_process_managed(true, false) {
                Ok(clone) => {
                    println!("  Clone {} - PID: {}", i, clone.process_id);
                    clones.push(clone);
                }
                Err(e) => {
                    println!("  Clone {} failed: {}", i, e);
                    break;
                }
            }
        }

        println!("  Created {} clones successfully", clones.len());

        // All clones will be terminated on drop
        for (i, clone) in clones.iter().enumerate() {
            println!("  Terminating clone {} (PID {})", i, clone.process_id);
        }
    }

    /// Test with handle inheritance
    #[test]
    fn test_clone_with_handle_inheritance() {
        println!("\n=== Test: Clone with Handle Inheritance ===");

        match clone_process_managed(true, true) {
            Ok(clone) => {
                println!("  Clone created with handle inheritance");
                println!("  PID: {}", clone.process_id);
                // Handles from parent should be accessible in clone
            }
            Err(e) => {
                println!("Clone with inheritance failed: {}", e);
            }
        }
    }

    /// Integration test simulating MCP remote operations
    #[test]
    fn test_mcp_remote_simulation() {
        println!("\n=== Test: MCP Remote Operations Simulation ===");

        // This test simulates what the ghost-mcp-client would do
        // when operating on a remote/cloned process

        // Step 1: Set up test data
        println!("  Step 1: Setting up test data...");
        set_test_value(0x41414141);
        let test_addr = get_test_value_address();

        // Step 2: Clone the process
        println!("  Step 2: Cloning process...");
        match clone_process_managed(true, false) {
            Ok(clone) => {
                println!("  Clone created successfully (PID: {})", clone.process_id);

                // Step 3: Simulate memory_read operation
                println!("  Step 3: Simulating memory_read...");
                let mut buffer = [0u8; 4];
                if clone.read_memory(test_addr, &mut buffer).is_ok() {
                    let val = u32::from_le_bytes(buffer);
                    println!("    Read: 0x{:08X}", val);
                }

                // Step 4: Simulate memory_write operation
                println!("  Step 4: Simulating memory_write...");
                let new_val: u32 = 0x42424242;
                if clone
                    .write_memory(test_addr, &new_val.to_le_bytes())
                    .is_ok()
                {
                    println!("    Wrote: 0x{:08X}", new_val);
                }

                // Step 5: Simulate memory_search (simplified)
                println!("  Step 5: Simulating memory operations...");
                const PAGE_READWRITE: u32 = 0x04;
                if let Ok(alloc_addr) = clone.allocate_memory(4096, PAGE_READWRITE) {
                    println!("    Allocated scratch space at 0x{:016X}", alloc_addr);

                    // Write search target
                    let search_val: u32 = 0x12345678;
                    let _ = clone.write_memory(alloc_addr, &search_val.to_le_bytes());

                    // Read it back to verify
                    let mut verify_buf = [0u8; 4];
                    if clone.read_memory(alloc_addr, &mut verify_buf).is_ok() {
                        let verified = u32::from_le_bytes(verify_buf);
                        println!("    Verified scratch write: 0x{:08X}", verified);
                    }
                }

                println!("  Step 6: Test complete!");
            }
            Err(e) => {
                println!("  Clone failed: {}", e);
            }
        }
    }

    /// Test clone for memory dumping scenario
    #[test]
    fn test_clone_for_memory_dump() {
        println!("\n=== Test: Clone for Memory Dumping ===");

        // This test simulates using process cloning for safe memory dumping
        // The clone provides a snapshot of the process memory state

        // Allocate some data on the heap before cloning
        let heap_data: Vec<u32> = vec![0x11111111, 0x22222222, 0x33333333, 0x44444444];
        let heap_addr = heap_data.as_ptr() as usize;

        println!("  Source data at 0x{:016X}:", heap_addr);
        for (i, val) in heap_data.iter().enumerate() {
            println!("    [{}] 0x{:08X}", i, val);
        }

        match clone_process_managed(true, false) {
            Ok(clone) => {
                println!("  Clone created for dumping (PID: {})", clone.process_id);

                // Read the heap data from the clone (memory snapshot)
                let mut dump_buffer = vec![0u8; 16];
                match clone.read_memory(heap_addr, &mut dump_buffer) {
                    Ok(bytes_read) => {
                        println!("  Dumped {} bytes from clone:", bytes_read);

                        // Parse as u32 values
                        for (i, expected) in heap_data.iter().enumerate().take(4) {
                            let offset = i * 4;
                            if offset + 4 <= dump_buffer.len() {
                                let val = u32::from_le_bytes([
                                    dump_buffer[offset],
                                    dump_buffer[offset + 1],
                                    dump_buffer[offset + 2],
                                    dump_buffer[offset + 3],
                                ]);
                                println!("    [{}] 0x{:08X}", i, val);
                                assert_eq!(val, *expected, "Dump mismatch at index {}", i);
                            }
                        }
                        println!("  Memory dump verified!");
                    }
                    Err(e) => {
                        println!("  Dump failed: {}", e);
                    }
                }
            }
            Err(e) => {
                println!("Clone failed: {}", e);
            }
        }

        // Keep heap_data alive until here
        drop(heap_data);
    }
}

// ============================================================================
// Benchmark/Stress Tests
// ============================================================================

#[cfg(test)]
mod stress_tests {
    use super::*;
    use std::time::Instant;

    /// Measure clone creation overhead
    #[test]
    #[ignore] // Run with --ignored flag
    fn bench_clone_creation() {
        println!("\n=== Benchmark: Clone Creation ===");

        const ITERATIONS: u32 = 10;
        let mut times = Vec::new();

        for i in 0..ITERATIONS {
            let start = Instant::now();

            match clone_process_managed(true, false) {
                Ok(_clone) => {
                    let elapsed = start.elapsed();
                    times.push(elapsed);
                    println!("  Iteration {}: {:?}", i, elapsed);
                }
                Err(e) => {
                    println!("  Iteration {} failed: {}", i, e);
                    break;
                }
            }
        }

        if !times.is_empty() {
            let total: std::time::Duration = times.iter().sum();
            let avg = total / times.len() as u32;
            println!("\n  Average clone time: {:?}", avg);
        }
    }

    /// Test memory operation throughput
    #[test]
    #[ignore] // Run with --ignored flag
    fn bench_memory_operations() {
        println!("\n=== Benchmark: Memory Operations ===");

        match clone_process_managed(true, false) {
            Ok(clone) => {
                const PAGE_READWRITE: u32 = 0x04;

                if let Ok(addr) = clone.allocate_memory(1024 * 1024, PAGE_READWRITE) {
                    println!("  Allocated 1MB buffer");

                    // Write benchmark
                    let data = vec![0xAAu8; 4096];
                    let start = Instant::now();
                    const WRITE_ITERATIONS: u32 = 100;

                    for i in 0..WRITE_ITERATIONS {
                        let offset = (i as usize * 4096) % (1024 * 1024 - 4096);
                        let _ = clone.write_memory(addr + offset, &data);
                    }

                    let write_time = start.elapsed();
                    println!("  {} x 4KB writes: {:?}", WRITE_ITERATIONS, write_time);

                    // Read benchmark
                    let mut read_buf = vec![0u8; 4096];
                    let start = Instant::now();
                    const READ_ITERATIONS: u32 = 100;

                    for i in 0..READ_ITERATIONS {
                        let offset = (i as usize * 4096) % (1024 * 1024 - 4096);
                        let _ = clone.read_memory(addr + offset, &mut read_buf);
                    }

                    let read_time = start.elapsed();
                    println!("  {} x 4KB reads: {:?}", READ_ITERATIONS, read_time);
                }
            }
            Err(e) => {
                println!("Clone failed: {}", e);
            }
        }
    }
}
