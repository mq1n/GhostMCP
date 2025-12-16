//! Process & System Introspection types
//!
//! Types for comprehensive system introspection including:
//! - Process management and PEB access
//! - Thread management and TEB access
//! - Module load/unload monitoring
//! - Handle enumeration and management
//! - Window enumeration and manipulation
//! - Section and token management

use serde::{Deserialize, Serialize};

// ============================================================================
// Process Management Types
// ============================================================================

/// Extended process information with PEB access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessDetails {
    /// Process ID
    pub pid: u32,
    /// Process name
    pub name: String,
    /// Parent process ID
    pub parent_pid: Option<u32>,
    /// Full executable path
    pub path: Option<String>,
    /// Command line arguments
    pub command_line: Option<String>,
    /// Current working directory
    pub working_directory: Option<String>,
    /// Environment variables (key-value pairs)
    pub environment: Vec<(String, String)>,
    /// Architecture (x86, x64)
    pub arch: String,
    /// Whether the process is 64-bit
    pub is_64bit: bool,
    /// Process creation time (Unix timestamp)
    pub creation_time: Option<u64>,
    /// Session ID
    pub session_id: u32,
    /// Number of threads
    pub thread_count: u32,
    /// Number of handles
    pub handle_count: u32,
    /// PEB address
    pub peb_address: Option<usize>,
    /// Image base address
    pub image_base: Option<usize>,
    /// Process priority class
    pub priority_class: Option<u32>,
    /// Is being debugged
    pub being_debugged: bool,
}

/// Process Environment Block (PEB) information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PebInfo {
    /// PEB address
    pub address: usize,
    /// BeingDebugged flag
    pub being_debugged: bool,
    /// Image base address
    pub image_base: usize,
    /// Ldr (loader data) address
    pub ldr_address: usize,
    /// Process parameters address
    pub process_parameters: usize,
    /// NtGlobalFlag value
    pub nt_global_flag: u32,
    /// Heap address
    pub process_heap: usize,
    /// Fast PEB lock address
    pub fast_peb_lock: usize,
    /// Number of processors
    pub number_of_processors: u32,
    /// Session ID
    pub session_id: u32,
    /// OSMajorVersion
    pub os_major_version: u32,
    /// OSMinorVersion
    pub os_minor_version: u32,
    /// OSBuildNumber
    pub os_build_number: u16,
}

/// Process memory map entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMemoryMapEntry {
    /// Base address
    pub base_address: usize,
    /// Region size
    pub size: usize,
    /// Protection flags (as string, e.g., "RWX")
    pub protection: String,
    /// State (commit, reserve, free)
    pub state: RegionState,
    /// Type (image, mapped, private)
    pub memory_type: RegionType,
    /// Associated module name (if any)
    pub module_name: Option<String>,
}

/// Memory region state (for process memory map)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegionState {
    Commit,
    Reserve,
    Free,
}

/// Memory region type (for process memory map)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegionType {
    Image,
    Mapped,
    Private,
    Unknown,
}

// ============================================================================
// Thread Management Types
// ============================================================================

/// Extended thread information with TEB access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadDetails {
    /// Thread ID
    pub tid: u32,
    /// Owner process ID
    pub pid: u32,
    /// Thread state
    pub state: ThreadExecutionState,
    /// Wait reason (if waiting)
    pub wait_reason: Option<String>,
    /// Thread priority
    pub priority: i32,
    /// Base priority
    pub base_priority: i32,
    /// Thread start address
    pub start_address: Option<usize>,
    /// TEB address
    pub teb_address: Option<usize>,
    /// Thread creation time
    pub creation_time: Option<u64>,
    /// Kernel time (100-nanosecond units)
    pub kernel_time: u64,
    /// User time (100-nanosecond units)
    pub user_time: u64,
    /// Suspend count
    pub suspend_count: u32,
    /// Is main thread
    pub is_main_thread: bool,
}

/// Thread execution state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ThreadExecutionState {
    Initialized,
    Ready,
    Running,
    Standby,
    Terminated,
    Waiting,
    Transition,
    #[default]
    Unknown,
}

/// Thread Environment Block (TEB) information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TebInfo {
    /// TEB address
    pub address: usize,
    /// Thread ID
    pub tid: u32,
    /// Process ID
    pub pid: u32,
    /// Stack base
    pub stack_base: usize,
    /// Stack limit
    pub stack_limit: usize,
    /// TLS slots address
    pub tls_slots: usize,
    /// PEB address
    pub peb_address: usize,
    /// Last error value
    pub last_error: u32,
    /// Exception list (SEH chain head)
    pub exception_list: usize,
    /// Fiber data
    pub fiber_data: Option<usize>,
    /// Current locale
    pub current_locale: u32,
}

/// Thread Local Storage slot information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsSlot {
    /// Slot index
    pub index: u32,
    /// Slot value (pointer)
    pub value: usize,
    /// Module that allocated this slot (if known)
    pub module: Option<String>,
}

// ============================================================================
// Module Management Types
// ============================================================================

/// Extended module information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleDetails {
    /// Module name
    pub name: String,
    /// Full path
    pub path: String,
    /// Base address
    pub base: usize,
    /// Size in memory
    pub size: usize,
    /// Entry point address
    pub entry_point: Option<usize>,
    /// Load count (reference count)
    pub load_count: Option<u32>,
    /// TLS index (if module uses TLS)
    pub tls_index: Option<u32>,
    /// Is the main executable
    pub is_main_module: bool,
    /// Load time (Unix timestamp)
    pub load_time: Option<u64>,
    /// File version (if available)
    pub file_version: Option<String>,
    /// Product version (if available)
    pub product_version: Option<String>,
    /// Company name
    pub company_name: Option<String>,
    /// File description
    pub file_description: Option<String>,
    /// PE checksum
    pub checksum: Option<u32>,
    /// PE timestamp
    pub timestamp: Option<u32>,
}

/// Module load event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleLoadEvent {
    /// Module name
    pub name: String,
    /// Full path
    pub path: String,
    /// Base address
    pub base: usize,
    /// Size
    pub size: usize,
    /// Is load (true) or unload (false)
    pub is_load: bool,
    /// Timestamp when event occurred
    pub timestamp: u64,
}

// ============================================================================
// Handle Management Types
// ============================================================================

/// Handle information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleInfo {
    /// Handle value
    pub handle: usize,
    /// Handle type
    pub handle_type: HandleType,
    /// Type name (string representation)
    pub type_name: String,
    /// Object name (e.g., file path, registry key)
    pub object_name: Option<String>,
    /// Access mask
    pub access_mask: u32,
    /// Handle attributes
    pub attributes: u32,
    /// Reference count (if available)
    pub reference_count: Option<u32>,
}

/// Handle types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum HandleType {
    File,
    Directory,
    Key,
    Event,
    Mutant,
    Semaphore,
    Thread,
    Process,
    Token,
    Section,
    Port,
    Timer,
    IoCompletion,
    Job,
    Desktop,
    WindowStation,
    SymbolicLink,
    #[default]
    Unknown,
}

impl HandleType {
    /// Parse handle type from string representation
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "file" => Self::File,
            "directory" => Self::Directory,
            "key" => Self::Key,
            "event" => Self::Event,
            "mutant" | "mutex" => Self::Mutant,
            "semaphore" => Self::Semaphore,
            "thread" => Self::Thread,
            "process" => Self::Process,
            "token" => Self::Token,
            "section" => Self::Section,
            "port" | "alpcport" => Self::Port,
            "timer" => Self::Timer,
            "iocompletion" => Self::IoCompletion,
            "job" => Self::Job,
            "desktop" => Self::Desktop,
            "windowstation" => Self::WindowStation,
            "symboliclink" => Self::SymbolicLink,
            _ => Self::Unknown,
        }
    }
}

/// Handle filter for enumeration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HandleFilter {
    /// Filter by handle type
    pub handle_type: Option<HandleType>,
    /// Filter by type name (substring match)
    pub type_name_contains: Option<String>,
    /// Filter by object name (substring match)
    pub object_name_contains: Option<String>,
}

/// Handle leak detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleLeakInfo {
    /// Handle value
    pub handle: usize,
    /// Handle type
    pub type_name: String,
    /// Object name
    pub object_name: Option<String>,
    /// Stack trace at allocation (if available)
    pub allocation_stack: Option<Vec<usize>>,
    /// Age in seconds
    pub age_seconds: u64,
}

// ============================================================================
// Window Management Types
// ============================================================================

/// Window information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowInfo {
    /// Window handle (HWND)
    pub hwnd: usize,
    /// Window title/text
    pub title: String,
    /// Window class name
    pub class_name: String,
    /// Owner process ID
    pub pid: u32,
    /// Owner thread ID
    pub tid: u32,
    /// Parent window handle
    pub parent: Option<usize>,
    /// Window rectangle (left, top, right, bottom)
    pub rect: WindowRect,
    /// Client area rectangle
    pub client_rect: WindowRect,
    /// Window style
    pub style: u32,
    /// Extended window style
    pub ex_style: u32,
    /// Is visible
    pub visible: bool,
    /// Is enabled
    pub enabled: bool,
    /// Is minimized
    pub minimized: bool,
    /// Is maximized
    pub maximized: bool,
    /// Is top-level window
    pub is_top_level: bool,
    /// Child window count
    pub child_count: u32,
}

/// Window rectangle
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WindowRect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

impl WindowRect {
    pub fn width(&self) -> i32 {
        self.right - self.left
    }

    pub fn height(&self) -> i32 {
        self.bottom - self.top
    }
}

/// Window filter for enumeration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WindowFilter {
    /// Filter by process ID
    pub pid: Option<u32>,
    /// Filter by thread ID
    pub tid: Option<u32>,
    /// Filter by class name (substring match)
    pub class_name_contains: Option<String>,
    /// Filter by title (substring match)
    pub title_contains: Option<String>,
    /// Only visible windows
    pub visible_only: bool,
    /// Only top-level windows
    pub top_level_only: bool,
}

/// Window message for interception
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowMessage {
    /// Window handle
    pub hwnd: usize,
    /// Message ID
    pub message: u32,
    /// Message name (if known)
    pub message_name: Option<String>,
    /// wParam
    pub wparam: usize,
    /// lParam
    pub lparam: isize,
    /// Timestamp
    pub timestamp: u64,
}

// ============================================================================
// Section Management Types
// ============================================================================

/// Memory section information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    /// Section name (e.g., .text, .data)
    pub name: String,
    /// Virtual address (RVA from module base)
    pub virtual_address: usize,
    /// Virtual size
    pub virtual_size: usize,
    /// Raw data offset in file
    pub raw_offset: usize,
    /// Raw data size
    pub raw_size: usize,
    /// Section characteristics
    pub characteristics: u32,
    /// Is executable
    pub executable: bool,
    /// Is writable
    pub writable: bool,
    /// Is readable
    pub readable: bool,
    /// Contains code
    pub contains_code: bool,
    /// Contains initialized data
    pub contains_initialized_data: bool,
    /// Contains uninitialized data
    pub contains_uninitialized_data: bool,
}

/// Mapped section information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappedSectionInfo {
    /// Base address
    pub base_address: usize,
    /// Size
    pub size: usize,
    /// Section handle (if applicable)
    pub section_handle: Option<usize>,
    /// Backing file path (if file-backed)
    pub file_path: Option<String>,
    /// Protection
    pub protection: String,
    /// Is shared
    pub is_shared: bool,
}

// ============================================================================
// Token Management Types
// ============================================================================

/// Token information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    /// Token handle
    pub handle: usize,
    /// Token type (primary or impersonation)
    pub token_type: TokenType,
    /// Impersonation level (if impersonation token)
    pub impersonation_level: Option<ImpersonationLevel>,
    /// User SID
    pub user_sid: String,
    /// User name
    pub user_name: Option<String>,
    /// User domain
    pub user_domain: Option<String>,
    /// Session ID
    pub session_id: u32,
    /// Integrity level
    pub integrity_level: IntegrityLevel,
    /// Is elevated
    pub is_elevated: bool,
    /// Is restricted
    pub is_restricted: bool,
    /// Privileges
    pub privileges: Vec<TokenPrivilege>,
    /// Groups
    pub groups: Vec<TokenGroup>,
}

/// Token type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenType {
    Primary,
    Impersonation,
}

/// Impersonation level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImpersonationLevel {
    Anonymous,
    Identification,
    Impersonation,
    Delegation,
}

/// Integrity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum IntegrityLevel {
    Untrusted,
    Low,
    Medium,
    MediumPlus,
    High,
    System,
    Protected,
    #[default]
    Unknown,
}

/// Token privilege
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPrivilege {
    /// Privilege name
    pub name: String,
    /// LUID value
    pub luid: u64,
    /// Is enabled
    pub enabled: bool,
    /// Is enabled by default
    pub enabled_by_default: bool,
    /// Is removed
    pub removed: bool,
}

/// Token group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenGroup {
    /// Group SID
    pub sid: String,
    /// Group name
    pub name: Option<String>,
    /// Group domain
    pub domain: Option<String>,
    /// Attributes
    pub attributes: u32,
    /// Is enabled
    pub enabled: bool,
    /// Is mandatory
    pub mandatory: bool,
    /// Is owner
    pub owner: bool,
    /// Is deny-only
    pub deny_only: bool,
}

/// Privilege manipulation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegeRequest {
    /// Privilege name
    pub name: String,
    /// Enable (true) or disable (false)
    pub enable: bool,
}

// ============================================================================
// Event Monitoring Types
// ============================================================================

/// Process event (creation/termination)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    /// Event type
    pub event_type: ProcessEventType,
    /// Process ID
    pub pid: u32,
    /// Process name
    pub name: String,
    /// Parent process ID
    pub parent_pid: Option<u32>,
    /// Exit code (for termination)
    pub exit_code: Option<u32>,
    /// Timestamp
    pub timestamp: u64,
}

/// Process event type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessEventType {
    Created,
    Terminated,
}

/// Thread event (creation/termination)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadEvent {
    /// Event type
    pub event_type: ThreadEventType,
    /// Thread ID
    pub tid: u32,
    /// Owner process ID
    pub pid: u32,
    /// Start address (for creation)
    pub start_address: Option<usize>,
    /// Exit code (for termination)
    pub exit_code: Option<u32>,
    /// Timestamp
    pub timestamp: u64,
}

/// Thread event type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreadEventType {
    Created,
    Terminated,
}

// ============================================================================
// Introspection Result Types
// ============================================================================

/// Result of environment variable lookup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentVariable {
    /// Variable name
    pub name: String,
    /// Variable value
    pub value: String,
}

/// Working directory manipulation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkingDirectoryResult {
    /// Previous working directory
    pub previous: String,
    /// New working directory
    pub current: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_type_parse() {
        assert_eq!(HandleType::parse("File"), HandleType::File);
        assert_eq!(HandleType::parse("PROCESS"), HandleType::Process);
        assert_eq!(HandleType::parse("mutex"), HandleType::Mutant);
        assert_eq!(HandleType::parse("unknown_type"), HandleType::Unknown);
    }

    #[test]
    fn test_window_rect() {
        let rect = WindowRect {
            left: 100,
            top: 200,
            right: 500,
            bottom: 600,
        };
        assert_eq!(rect.width(), 400);
        assert_eq!(rect.height(), 400);
    }

    #[test]
    fn test_thread_execution_state_default() {
        assert_eq!(
            ThreadExecutionState::default(),
            ThreadExecutionState::Unknown
        );
    }

    #[test]
    fn test_integrity_level_default() {
        assert_eq!(IntegrityLevel::default(), IntegrityLevel::Unknown);
    }

    #[test]
    fn test_process_details_serialization() {
        let details = ProcessDetails {
            pid: 1234,
            name: "test.exe".to_string(),
            parent_pid: Some(100),
            path: Some("C:\\test.exe".to_string()),
            command_line: Some("test.exe --arg".to_string()),
            working_directory: Some("C:\\".to_string()),
            environment: vec![("PATH".to_string(), "C:\\Windows".to_string())],
            arch: "x64".to_string(),
            is_64bit: true,
            creation_time: Some(1234567890),
            session_id: 1,
            thread_count: 10,
            handle_count: 100,
            peb_address: Some(0x7FFE0000),
            image_base: Some(0x140000000),
            priority_class: Some(32),
            being_debugged: false,
        };
        let json = serde_json::to_string(&details).unwrap();
        let parsed: ProcessDetails = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.pid, 1234);
        assert!(parsed.is_64bit);
    }

    #[test]
    fn test_handle_filter_default() {
        let filter = HandleFilter::default();
        assert!(filter.handle_type.is_none());
        assert!(filter.type_name_contains.is_none());
        assert!(filter.object_name_contains.is_none());
    }

    #[test]
    fn test_window_filter_default() {
        let filter = WindowFilter::default();
        assert!(!filter.visible_only);
        assert!(!filter.top_level_only);
    }
}
