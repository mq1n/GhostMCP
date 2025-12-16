//! Process control implementation helpers

use ghost_common::Module;

/// Get current process ID
pub fn current_pid() -> u32 {
    unsafe { windows::Win32::System::Threading::GetCurrentProcessId() }
}

/// Get current thread ID
pub fn current_tid() -> u32 {
    unsafe { windows::Win32::System::Threading::GetCurrentThreadId() }
}

/// Get module name from path
pub fn module_name_from_path(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path)
        .to_string()
}

/// Check if module name matches (case-insensitive)
pub fn module_name_matches(module: &Module, name: &str) -> bool {
    module.name.eq_ignore_ascii_case(name)
        || module.path.eq_ignore_ascii_case(name)
        || module_name_from_path(&module.path).eq_ignore_ascii_case(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_pid_nonzero() {
        let pid = current_pid();
        assert!(pid > 0);
    }

    #[test]
    fn test_current_tid_nonzero() {
        let tid = current_tid();
        assert!(tid > 0);
    }

    #[test]
    fn test_module_name_from_path_windows() {
        assert_eq!(
            module_name_from_path("C:\\Windows\\System32\\kernel32.dll"),
            "kernel32.dll"
        );
    }

    #[test]
    fn test_module_name_from_path_simple() {
        assert_eq!(module_name_from_path("test.dll"), "test.dll");
    }

    #[test]
    fn test_module_name_from_path_unix_style() {
        assert_eq!(module_name_from_path("/usr/lib/test.so"), "test.so");
    }

    #[test]
    fn test_module_name_matches_by_name() {
        let module = Module {
            name: "kernel32.dll".to_string(),
            path: "C:\\Windows\\System32\\kernel32.dll".to_string(),
            base: 0x7FF800000000,
            size: 0x100000,
        };
        assert!(module_name_matches(&module, "kernel32.dll"));
        assert!(module_name_matches(&module, "KERNEL32.DLL"));
        assert!(module_name_matches(&module, "Kernel32.dll"));
    }

    #[test]
    fn test_module_name_matches_by_path() {
        let module = Module {
            name: "kernel32.dll".to_string(),
            path: "C:\\Windows\\System32\\kernel32.dll".to_string(),
            base: 0x7FF800000000,
            size: 0x100000,
        };
        assert!(module_name_matches(
            &module,
            "C:\\Windows\\System32\\kernel32.dll"
        ));
    }

    #[test]
    fn test_module_name_matches_no_match() {
        let module = Module {
            name: "kernel32.dll".to_string(),
            path: "C:\\Windows\\System32\\kernel32.dll".to_string(),
            base: 0x7FF800000000,
            size: 0x100000,
        };
        assert!(!module_name_matches(&module, "ntdll.dll"));
        assert!(!module_name_matches(&module, "user32.dll"));
    }
}
