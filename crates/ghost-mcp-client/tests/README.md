# Ghost-MCP Client Integration Tests

## Remote Integration Tests

The `remote_integration.rs` test file implements integration tests for MCP client operations using Windows process cloning via the `RtlCloneUserProcess` NT API.

### Overview

Process cloning creates an exact copy of the current process's address space, providing:
- **Isolated test environments** - Changes to the clone don't affect the parent
- **Memory snapshot testing** - Test memory operations on a consistent snapshot
- **Safe experimentation** - Clone can be terminated without affecting the test process

### RtlCloneUserProcess API

The tests implement direct FFI bindings to the undocumented Windows NT APIs:

```rust
// Core cloning function
fn RtlCloneUserProcess(
    ProcessFlags: ULONG,
    ProcessSecurityDescriptor: PSECURITY_DESCRIPTOR,
    ThreadSecurityDescriptor: PSECURITY_DESCRIPTOR,
    DebugPort: HANDLE,
    ProcessInformation: *mut RTL_USER_PROCESS_INFORMATION,
) -> NTSTATUS;

// Helper functions (Windows 8.1+ x64)
fn RtlPrepareForProcessCloning() -> NTSTATUS;
fn RtlCompleteProcessCloning(bCloned: i32) -> NTSTATUS;
```

#### Clone Flags

| Flag | Value | Description |
|------|-------|-------------|
| `RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED` | 0x01 | Create clone with suspended main thread |
| `RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES` | 0x02 | Clone inherits parent's handles |
| `RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE` | 0x04 | Skip ntdll state synchronization |

#### Return Values

| Status | Value | Meaning |
|--------|-------|---------|
| `STATUS_SUCCESS` | 0x00000000 | In parent process after successful clone |
| `STATUS_PROCESS_CLONED` | 0x00000129 | In cloned process |

### Test Categories

#### Basic Tests
- `test_clone_process_basic` - Basic clone creation and termination
- `test_clone_with_handle_inheritance` - Clone with handle inheritance

#### Memory Operations
- `test_clone_memory_read` - Read memory from cloned process
- `test_clone_memory_write` - Write memory with isolation verification
- `test_clone_memory_alloc` - Allocate memory in clone

#### Advanced Tests
- `test_multiple_clones` - Create multiple concurrent clones
- `test_mcp_remote_simulation` - Full MCP workflow simulation
- `test_clone_for_memory_dump` - Memory dumping scenario

#### Benchmark Tests (ignored by default)
- `bench_clone_creation` - Measure clone creation overhead
- `bench_memory_operations` - Memory operation throughput

### Running Tests

```bash
# Run all tests
cargo test -p ghost-mcp-client --test remote_integration

# Run with output
cargo test -p ghost-mcp-client --test remote_integration -- --nocapture

# Run benchmarks (ignored by default)
cargo test -p ghost-mcp-client --test remote_integration -- --ignored --nocapture

# Run specific test
cargo test -p ghost-mcp-client --test remote_integration test_clone_memory_read
```

### Safe Rust Wrappers

The test module provides safe wrappers around the NT APIs:

```rust
// Clone the current process
let clone = clone_process_managed(create_suspended, inherit_handles)?;

// Read memory from clone
clone.read_memory(address, &mut buffer)?;

// Write memory to clone
clone.write_memory(address, &data)?;

// Allocate memory in clone
let addr = clone.allocate_memory(size, PAGE_READWRITE)?;

// Clone is automatically terminated on drop
```

### Technical Notes

1. **Copy-on-Write**: Clone shares memory pages until modified, then gets private copies
2. **Thread Cloning**: Only the calling thread is cloned, not all process threads
3. **Handle Table**: Clone gets a copy of the handle table (if inheritance enabled)
4. **Memory Isolation**: Writes to clone memory don't affect parent process

### References

- [Process Cloning Guide](https://github.com/huntandhackett/process-cloning) - Comprehensive documentation
- [RtlClone](https://github.com/rbmm/RtlClone) - Implementation examples
- [PHNT Headers](https://github.com/processhacker/phnt) - NT type definitions

### Platform Support

- **OS**: Windows 8.1+ (x64 only for `RtlPrepareForProcessCloning`)
- **Architecture**: x64 (tested), ARM64 (untested)
- **Note**: x86/WoW64 has known issues with process cloning (FS segment bug)
