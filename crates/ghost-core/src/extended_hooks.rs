//! Extended Hooking Methods
//!
//! Comprehensive hooking support including:
//! - Inline hooks (trampoline, mid-function, hot-patch, INT3)
//! - IAT/EAT hooks
//! - VEH/PAGE_GUARD hooks
//! - Syscall hooks
//! - Shellcode generation and injection
//! - ROP gadget finder
//! - Hook chain management

use crate::hooks::{
    generate_abs_jump, generate_rel_jump, next_hook_id, X64_ABS_JMP_SIZE, X64_REL_JMP_SIZE,
};
use ghost_common::types::{
    EatEntry, EatHookRequest, ExtendedHookType, HookChain, HookFilter, HookId, HookInfo,
    HookResult, HookRollbackEntry, HookState, HookSummary, HookTransaction, IatEntry,
    IatHookRequest, InlineHookRequest, PageGuardHook, SyscallHookRequest, VehHookRequest,
};
use ghost_common::{Error, Result};
use iced_x86::{Decoder, DecoderOptions, Encoder};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::RwLock;
use tracing::{debug, info, warn};

#[cfg(target_os = "windows")]
use windows::Win32::System::Diagnostics::Debug::FlushInstructionCache;
#[cfg(target_os = "windows")]
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
#[cfg(target_os = "windows")]
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualProtect, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READWRITE, PAGE_GUARD, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::GetCurrentProcess;

const TRAMPOLINE_ALLOC_SIZE: usize = 64;
const HOT_PATCH_PROLOGUE: [u8; 2] = [0x8B, 0xFF];
const INT3_OPCODE: u8 = 0xCC;

static TRANSACTION_COUNTER: AtomicU32 = AtomicU32::new(1);

/// Relocates instructions from source to destination, fixing RIP-relative addressing
struct TrampolineRelocator {
    source_addr: u64,
    dest_addr: u64,
}

impl TrampolineRelocator {
    fn new(source_addr: u64, dest_addr: u64) -> Self {
        Self {
            source_addr,
            dest_addr,
        }
    }

    /// Relocate instructions from source to destination buffer
    /// Returns the total size of relocated instructions
    fn relocate(&mut self, source_bytes: &[u8], dest: *mut u8) -> Result<usize> {
        let mut decoder =
            Decoder::with_ip(64, source_bytes, self.source_addr, DecoderOptions::NONE);
        let mut total_size = 0usize;
        let mut dest_offset = 0usize;

        for instr in &mut decoder {
            if instr.is_invalid() {
                break;
            }

            // Calculate the new IP for this instruction at destination
            let new_ip = self.dest_addr + dest_offset as u64;

            // Create encoder for this instruction
            let mut encoder = Encoder::new(64);

            // Try to encode the instruction at the new address
            // The encoder will automatically fix RIP-relative operands
            let encoded_result = encoder.encode(&instr, new_ip);

            match encoded_result {
                Ok(_) => {
                    let encoded_bytes = encoder.take_buffer();
                    let encoded_len = encoded_bytes.len();

                    // Copy encoded instruction to destination
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            encoded_bytes.as_ptr(),
                            dest.add(dest_offset),
                            encoded_len,
                        );
                    }

                    dest_offset += encoded_len;
                    total_size = dest_offset;
                }
                Err(_) => {
                    // If encoding fails, try to copy the original bytes
                    // This handles instructions that can't be relocated
                    let instr_len = instr.len();
                    let start = (instr.ip() - self.source_addr) as usize;

                    if start + instr_len <= source_bytes.len() {
                        unsafe {
                            std::ptr::copy_nonoverlapping(
                                source_bytes.as_ptr().add(start),
                                dest.add(dest_offset),
                                instr_len,
                            );
                        }
                        dest_offset += instr_len;
                        total_size = dest_offset;
                    } else {
                        return Err(Error::Internal(format!(
                            "Failed to relocate instruction at 0x{:X}",
                            instr.ip()
                        )));
                    }
                }
            }

            // Stop if we've processed enough bytes
            if (instr.ip() - self.source_addr) as usize + instr.len() >= source_bytes.len() {
                break;
            }
        }

        if total_size == 0 {
            return Err(Error::Internal("No instructions relocated".into()));
        }

        Ok(total_size)
    }
}

static HOOK_MANAGER: once_cell::sync::Lazy<RwLock<ExtendedHookManager>> =
    once_cell::sync::Lazy::new(|| RwLock::new(ExtendedHookManager::new()));

struct HookEntry {
    info: HookInfo,
    trampoline_memory: Option<usize>,
}

/// Extended Hook Manager - manages all hook types
pub struct ExtendedHookManager {
    hooks: HashMap<HookId, HookEntry>,
    hooks_by_address: HashMap<u64, Vec<HookId>>,
    iat_hooks: HashMap<String, HookId>,
    eat_hooks: HashMap<String, HookId>,
    page_guard_hooks: HashMap<u64, PageGuardHook>,
    transactions: HashMap<u32, HookTransaction>,
    veh_handler: Option<usize>,
    int3_targets: HashMap<u64, HookId>,
    initialized: bool,
}

impl Default for ExtendedHookManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtendedHookManager {
    pub fn new() -> Self {
        Self {
            hooks: HashMap::new(),
            hooks_by_address: HashMap::new(),
            iat_hooks: HashMap::new(),
            eat_hooks: HashMap::new(),
            page_guard_hooks: HashMap::new(),
            transactions: HashMap::new(),
            veh_handler: None,
            int3_targets: HashMap::new(),
            initialized: false,
        }
    }

    pub fn initialize(&mut self) -> Result<()> {
        if self.initialized {
            return Ok(());
        }
        info!("Initializing extended hook manager");
        #[cfg(target_os = "windows")]
        self.register_veh_handler()?;
        self.initialized = true;
        Ok(())
    }

    pub fn shutdown(&mut self) -> Result<()> {
        if !self.initialized {
            return Ok(());
        }
        info!("Shutting down extended hook manager");
        let hook_ids: Vec<HookId> = self.hooks.keys().copied().collect();
        for id in hook_ids {
            if let Err(e) = self.remove_hook(id) {
                warn!("Failed to remove hook {:?}: {}", id, e);
            }
        }
        #[cfg(target_os = "windows")]
        self.unregister_veh_handler();
        self.initialized = false;
        Ok(())
    }

    // ========================================================================
    // Inline Hooks
    // ========================================================================

    #[cfg(target_os = "windows")]
    pub fn install_inline_hook(&mut self, request: InlineHookRequest) -> Result<HookResult> {
        if !self.initialized {
            return Err(Error::Internal("Hook manager not initialized".into()));
        }

        let target = request.target_address as usize;
        let callback = request.callback_address as usize;

        debug!("Installing inline hook at {:#x} -> {:#x}", target, callback);

        let hook_type = request.hook_type.unwrap_or_else(|| {
            if self.has_hot_patch_prologue(target) {
                ExtendedHookType::InlineHotPatch
            } else {
                ExtendedHookType::InlineTrampoline
            }
        });

        let original_bytes = self.read_memory(target, self.get_hook_size(hook_type))?;
        let trampoline = self.allocate_trampoline(target, &original_bytes)?;

        let hook_id = HookId(next_hook_id());
        let hook_info = HookInfo {
            id: hook_id,
            hook_type,
            target_address: target as u64,
            callback_address: callback as u64,
            trampoline_address: Some(trampoline as u64),
            original_bytes: original_bytes.clone(),
            state: if request.enable {
                HookState::Enabled
            } else {
                HookState::Disabled
            },
            module_name: None,
            function_name: None,
            hit_count: 0,
            installed_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            chain_index: self.get_chain_index(target as u64),
        };

        if request.enable {
            self.write_hook_jump(target, callback, hook_type)?;
        }

        let entry = HookEntry {
            info: hook_info.clone(),
            trampoline_memory: Some(trampoline),
        };

        self.hooks.insert(hook_id, entry);
        self.hooks_by_address
            .entry(target as u64)
            .or_default()
            .push(hook_id);

        info!(
            "Installed {:?} hook {} at {:#x}",
            hook_type, hook_id, target
        );

        Ok(HookResult {
            success: true,
            hook_id: Some(hook_id),
            hook_info: Some(hook_info),
            error: None,
        })
    }

    #[cfg(not(target_os = "windows"))]
    pub fn install_inline_hook(&mut self, _request: InlineHookRequest) -> Result<HookResult> {
        Err(Error::NotImplemented(
            "Inline hooks only supported on Windows".into(),
        ))
    }

    #[cfg(target_os = "windows")]
    pub fn install_int3_hook(&mut self, target: u64, callback: u64) -> Result<HookResult> {
        if !self.initialized {
            return Err(Error::Internal("Hook manager not initialized".into()));
        }

        let target_addr = target as usize;
        debug!("Installing INT3 hook at {:#x}", target_addr);

        let original_bytes = self.read_memory(target_addr, 1)?;

        let hook_id = HookId(next_hook_id());
        let hook_info = HookInfo {
            id: hook_id,
            hook_type: ExtendedHookType::InlineInt3,
            target_address: target,
            callback_address: callback,
            trampoline_address: None,
            original_bytes: original_bytes.clone(),
            state: HookState::Enabled,
            module_name: None,
            function_name: None,
            hit_count: 0,
            installed_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            chain_index: 0,
        };

        self.write_memory(target_addr, &[INT3_OPCODE])?;
        self.int3_targets.insert(target, hook_id);

        let entry = HookEntry {
            info: hook_info.clone(),
            trampoline_memory: None,
        };
        self.hooks.insert(hook_id, entry);

        info!("Installed INT3 hook {} at {:#x}", hook_id, target);

        Ok(HookResult {
            success: true,
            hook_id: Some(hook_id),
            hook_info: Some(hook_info),
            error: None,
        })
    }

    #[cfg(not(target_os = "windows"))]
    pub fn install_int3_hook(&mut self, _target: u64, _callback: u64) -> Result<HookResult> {
        Err(Error::NotImplemented(
            "INT3 hooks only supported on Windows".into(),
        ))
    }

    // ========================================================================
    // IAT/EAT Hooks
    // ========================================================================

    #[cfg(target_os = "windows")]
    pub fn install_iat_hook(&mut self, request: IatHookRequest) -> Result<HookResult> {
        if !self.initialized {
            return Err(Error::Internal("Hook manager not initialized".into()));
        }

        debug!(
            "Installing IAT hook on {}!{}",
            request.module_name, request.function_name
        );

        let iat_entry = self.find_iat_entry(
            &request.module_name,
            &request.import_module,
            &request.function_name,
        )?;
        let hook_key = format!(
            "{}!{}!{}",
            request.module_name, request.import_module, request.function_name
        );

        if self.iat_hooks.contains_key(&hook_key) {
            return Err(Error::Internal(format!(
                "IAT entry {} already hooked",
                hook_key
            )));
        }

        let original_addr = self.read_pointer(iat_entry.iat_slot_address as usize)?;

        let hook_id = HookId(next_hook_id());
        let hook_info = HookInfo {
            id: hook_id,
            hook_type: ExtendedHookType::IatHook,
            target_address: iat_entry.iat_slot_address,
            callback_address: request.callback_address,
            trampoline_address: Some(original_addr as u64),
            original_bytes: (original_addr as u64).to_le_bytes().to_vec(),
            state: if request.enable {
                HookState::Enabled
            } else {
                HookState::Disabled
            },
            module_name: Some(request.module_name.clone()),
            function_name: Some(request.function_name.clone()),
            hit_count: 0,
            installed_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            chain_index: 0,
        };

        if request.enable {
            self.write_pointer(
                iat_entry.iat_slot_address as usize,
                request.callback_address as usize,
            )?;
        }

        let entry = HookEntry {
            info: hook_info.clone(),
            trampoline_memory: None,
        };

        self.hooks.insert(hook_id, entry);
        self.iat_hooks.insert(hook_key.clone(), hook_id);

        info!("Installed IAT hook {} on {}", hook_id, hook_key);

        Ok(HookResult {
            success: true,
            hook_id: Some(hook_id),
            hook_info: Some(hook_info),
            error: None,
        })
    }

    #[cfg(not(target_os = "windows"))]
    pub fn install_iat_hook(&mut self, _request: IatHookRequest) -> Result<HookResult> {
        Err(Error::NotImplemented(
            "IAT hooks only supported on Windows".into(),
        ))
    }

    #[cfg(target_os = "windows")]
    pub fn install_eat_hook(&mut self, request: EatHookRequest) -> Result<HookResult> {
        if !self.initialized {
            return Err(Error::Internal("Hook manager not initialized".into()));
        }

        debug!(
            "Installing EAT hook on {}!{}",
            request.module_name, request.function_name
        );

        let eat_entry = self.find_eat_entry(&request.module_name, &request.function_name)?;
        let hook_key = format!("{}!{}", request.module_name, request.function_name);

        if self.eat_hooks.contains_key(&hook_key) {
            return Err(Error::Internal(format!(
                "EAT entry {} already hooked",
                hook_key
            )));
        }

        let module_base = self.get_module_base(&request.module_name)?;

        let hook_id = HookId(next_hook_id());
        let hook_info = HookInfo {
            id: hook_id,
            hook_type: ExtendedHookType::EatHook,
            target_address: eat_entry.eat_slot_address,
            callback_address: request.callback_address,
            trampoline_address: Some(eat_entry.function_address),
            original_bytes: eat_entry.rva.to_le_bytes().to_vec(),
            state: if request.enable {
                HookState::Enabled
            } else {
                HookState::Disabled
            },
            module_name: Some(request.module_name.clone()),
            function_name: Some(request.function_name.clone()),
            hit_count: 0,
            installed_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            chain_index: 0,
        };

        if request.enable {
            let new_rva = (request.callback_address as i64 - module_base as i64) as u32;
            self.write_dword(eat_entry.eat_slot_address as usize, new_rva)?;
        }

        let entry = HookEntry {
            info: hook_info.clone(),
            trampoline_memory: None,
        };

        self.hooks.insert(hook_id, entry);
        self.eat_hooks.insert(hook_key.clone(), hook_id);

        info!("Installed EAT hook {} on {}", hook_id, hook_key);

        Ok(HookResult {
            success: true,
            hook_id: Some(hook_id),
            hook_info: Some(hook_info),
            error: None,
        })
    }

    #[cfg(not(target_os = "windows"))]
    pub fn install_eat_hook(&mut self, _request: EatHookRequest) -> Result<HookResult> {
        Err(Error::NotImplemented(
            "EAT hooks only supported on Windows".into(),
        ))
    }

    // ========================================================================
    // VEH/PAGE_GUARD Hooks
    // ========================================================================

    #[cfg(target_os = "windows")]
    pub fn install_veh_hook(&mut self, request: VehHookRequest) -> Result<HookResult> {
        if !self.initialized {
            return Err(Error::Internal("Hook manager not initialized".into()));
        }

        let base = request.target_address as usize;
        let size = request.size as usize;

        debug!(
            "Installing VEH/PAGE_GUARD hook at {:#x} size {}",
            base, size
        );

        let page_size = 0x1000usize;
        let page_base = base & !(page_size - 1);
        let page_end = (base + size + page_size - 1) & !(page_size - 1);
        let page_count = (page_end - page_base) / page_size;

        let mut original_protect = PAGE_PROTECTION_FLAGS(0);
        unsafe {
            VirtualProtect(
                page_base as *const std::ffi::c_void,
                page_count * page_size,
                PAGE_READWRITE | PAGE_GUARD,
                &mut original_protect,
            )
            .map_err(|e| Error::Internal(format!("VirtualProtect failed: {}", e)))?;
        }

        let hook_id = HookId(next_hook_id());
        let hook_info = HookInfo {
            id: hook_id,
            hook_type: ExtendedHookType::VehPageGuard,
            target_address: request.target_address,
            callback_address: request.callback_address,
            trampoline_address: None,
            original_bytes: vec![],
            state: HookState::Enabled,
            module_name: None,
            function_name: None,
            hit_count: 0,
            installed_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            chain_index: 0,
        };

        let pg_hook = PageGuardHook {
            hook_id,
            base_address: page_base as u64,
            size: (page_count * page_size) as u64,
            original_protection: original_protect.0,
            trigger_on_execute: request.on_execute,
            trigger_on_read: request.on_read,
            trigger_on_write: request.on_write,
            callback_address: request.callback_address,
            hit_count: 0,
        };

        self.page_guard_hooks.insert(page_base as u64, pg_hook);

        let entry = HookEntry {
            info: hook_info.clone(),
            trampoline_memory: None,
        };
        self.hooks.insert(hook_id, entry);

        info!("Installed VEH/PAGE_GUARD hook {} at {:#x}", hook_id, base);

        Ok(HookResult {
            success: true,
            hook_id: Some(hook_id),
            hook_info: Some(hook_info),
            error: None,
        })
    }

    #[cfg(not(target_os = "windows"))]
    pub fn install_veh_hook(&mut self, _request: VehHookRequest) -> Result<HookResult> {
        Err(Error::NotImplemented(
            "VEH hooks only supported on Windows".into(),
        ))
    }

    // ========================================================================
    // Syscall Hooks
    // ========================================================================

    #[cfg(target_os = "windows")]
    pub fn install_syscall_hook(&mut self, request: SyscallHookRequest) -> Result<HookResult> {
        if !self.initialized {
            return Err(Error::Internal("Hook manager not initialized".into()));
        }

        let function_name = request
            .function_name
            .clone()
            .unwrap_or_else(|| format!("NtSyscall{}", request.syscall_number));

        debug!("Installing syscall hook on {}", function_name);

        let stub_addr = self.find_syscall_stub(&function_name)?;

        let inline_request = InlineHookRequest {
            target_address: stub_addr,
            callback_address: request.callback_address,
            hook_type: Some(ExtendedHookType::Syscall),
            offset: None,
            enable: true,
        };

        let mut result = self.install_inline_hook(inline_request)?;

        if let Some(ref mut info) = result.hook_info {
            info.hook_type = ExtendedHookType::Syscall;
            info.function_name = Some(function_name);
            info.module_name = Some("ntdll.dll".to_string());
        }

        Ok(result)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn install_syscall_hook(&mut self, _request: SyscallHookRequest) -> Result<HookResult> {
        Err(Error::NotImplemented(
            "Syscall hooks only supported on Windows".into(),
        ))
    }

    // ========================================================================
    // Hook Management
    // ========================================================================

    pub fn remove_hook(&mut self, hook_id: HookId) -> Result<()> {
        let entry = self
            .hooks
            .remove(&hook_id)
            .ok_or_else(|| Error::Internal(format!("Hook {} not found", hook_id)))?;

        debug!(
            "Removing hook {} at {:#x}",
            hook_id, entry.info.target_address
        );

        #[cfg(target_os = "windows")]
        match entry.info.hook_type {
            ExtendedHookType::InlineTrampoline
            | ExtendedHookType::InlineMidFunction
            | ExtendedHookType::InlineRelativePatch
            | ExtendedHookType::InlineHotPatch
            | ExtendedHookType::Syscall => {
                self.write_memory(
                    entry.info.target_address as usize,
                    &entry.info.original_bytes,
                )?;
                if let Some(tramp) = entry.trampoline_memory {
                    unsafe {
                        VirtualFree(tramp as *mut std::ffi::c_void, 0, MEM_RELEASE).ok();
                    }
                }
            }
            ExtendedHookType::InlineInt3 => {
                self.write_memory(
                    entry.info.target_address as usize,
                    &entry.info.original_bytes,
                )?;
                self.int3_targets.remove(&entry.info.target_address);
            }
            ExtendedHookType::IatHook => {
                if let Some(tramp) = entry.info.trampoline_address {
                    self.write_pointer(entry.info.target_address as usize, tramp as usize)?;
                }
                if let (Some(module), Some(func)) =
                    (&entry.info.module_name, &entry.info.function_name)
                {
                    self.iat_hooks.remove(&format!("{}!{}", module, func));
                }
            }
            ExtendedHookType::EatHook => {
                if entry.info.original_bytes.len() >= 4 {
                    let original_rva =
                        u32::from_le_bytes(entry.info.original_bytes[..4].try_into().unwrap());
                    self.write_dword(entry.info.target_address as usize, original_rva)?;
                }
                if let (Some(module), Some(func)) =
                    (&entry.info.module_name, &entry.info.function_name)
                {
                    self.eat_hooks.remove(&format!("{}!{}", module, func));
                }
            }
            ExtendedHookType::VehPageGuard => {
                if let Some(pg_hook) = self.page_guard_hooks.remove(&entry.info.target_address) {
                    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
                    unsafe {
                        VirtualProtect(
                            pg_hook.base_address as *const std::ffi::c_void,
                            pg_hook.size as usize,
                            PAGE_PROTECTION_FLAGS(pg_hook.original_protection),
                            &mut old_protect,
                        )
                        .ok();
                    }
                }
            }
            _ => warn!("Unhandled hook type removal: {:?}", entry.info.hook_type),
        }

        if let Some(hooks) = self.hooks_by_address.get_mut(&entry.info.target_address) {
            hooks.retain(|&id| id != hook_id);
        }

        info!("Removed hook {}", hook_id);
        Ok(())
    }

    pub fn enable_hook(&mut self, hook_id: HookId) -> Result<()> {
        // Extract info needed for operations
        let (target, callback, hook_type, current_state) = {
            let entry = self
                .hooks
                .get(&hook_id)
                .ok_or_else(|| Error::Internal(format!("Hook {} not found", hook_id)))?;
            (
                entry.info.target_address,
                entry.info.callback_address,
                entry.info.hook_type,
                entry.info.state,
            )
        };

        if current_state == HookState::Enabled {
            return Ok(());
        }

        #[cfg(target_os = "windows")]
        match hook_type {
            ExtendedHookType::InlineTrampoline
            | ExtendedHookType::InlineMidFunction
            | ExtendedHookType::InlineRelativePatch => {
                self.write_hook_jump(target as usize, callback as usize, hook_type)?;
            }
            ExtendedHookType::InlineInt3 => {
                self.write_memory(target as usize, &[INT3_OPCODE])?;
            }
            ExtendedHookType::IatHook => {
                self.write_pointer(target as usize, callback as usize)?;
            }
            _ => {}
        }

        // Update state
        if let Some(entry) = self.hooks.get_mut(&hook_id) {
            entry.info.state = HookState::Enabled;
        }
        Ok(())
    }

    pub fn disable_hook(&mut self, hook_id: HookId) -> Result<()> {
        // Extract info needed for operations
        let (target, hook_type, original_bytes, trampoline, current_state) = {
            let entry = self
                .hooks
                .get(&hook_id)
                .ok_or_else(|| Error::Internal(format!("Hook {} not found", hook_id)))?;
            (
                entry.info.target_address,
                entry.info.hook_type,
                entry.info.original_bytes.clone(),
                entry.info.trampoline_address,
                entry.info.state,
            )
        };

        if current_state == HookState::Disabled {
            return Ok(());
        }

        #[cfg(target_os = "windows")]
        match hook_type {
            ExtendedHookType::InlineTrampoline
            | ExtendedHookType::InlineMidFunction
            | ExtendedHookType::InlineRelativePatch
            | ExtendedHookType::InlineInt3 => {
                self.write_memory(target as usize, &original_bytes)?;
            }
            ExtendedHookType::IatHook => {
                if let Some(tramp) = trampoline {
                    self.write_pointer(target as usize, tramp as usize)?;
                }
            }
            _ => {}
        }

        // Update state
        if let Some(entry) = self.hooks.get_mut(&hook_id) {
            entry.info.state = HookState::Disabled;
        }
        Ok(())
    }

    pub fn get_hook(&self, hook_id: HookId) -> Option<HookInfo> {
        self.hooks.get(&hook_id).map(|e| e.info.clone())
    }

    pub fn list_hooks(&self, filter: Option<HookFilter>) -> Vec<HookInfo> {
        self.hooks
            .values()
            .filter(|e| {
                if let Some(ref f) = filter {
                    if let Some(ref ht) = f.hook_type {
                        if &e.info.hook_type != ht {
                            return false;
                        }
                    }
                    if let Some(ref m) = f.module {
                        if e.info.module_name.as_ref() != Some(m) {
                            return false;
                        }
                    }
                    if let Some(ref s) = f.state {
                        if &e.info.state != s {
                            return false;
                        }
                    }
                    if let Some((start, end)) = f.address_range {
                        if e.info.target_address < start || e.info.target_address > end {
                            return false;
                        }
                    }
                }
                true
            })
            .map(|e| e.info.clone())
            .collect()
    }

    pub fn get_summary(&self) -> HookSummary {
        let mut by_type: HashMap<String, u32> = HashMap::new();
        let mut by_module: HashMap<String, u32> = HashMap::new();
        let mut active_count = 0u32;
        let mut disabled_count = 0u32;
        let mut total_hits = 0u64;

        for entry in self.hooks.values() {
            *by_type
                .entry(format!("{:?}", entry.info.hook_type))
                .or_default() += 1;
            if let Some(ref module) = entry.info.module_name {
                *by_module.entry(module.clone()).or_default() += 1;
            }
            match entry.info.state {
                HookState::Enabled => active_count += 1,
                HookState::Disabled => disabled_count += 1,
                _ => {}
            }
            total_hits += entry.info.hit_count;
        }

        HookSummary {
            total_hooks: self.hooks.len() as u32,
            by_type,
            by_module,
            active_count,
            disabled_count,
            total_hits,
        }
    }

    pub fn get_hook_chain(&self, address: u64) -> Option<HookChain> {
        self.hooks_by_address.get(&address).map(|ids| HookChain {
            target_address: address,
            hooks: ids.clone(),
            original_address: self
                .hooks
                .get(ids.first().unwrap())
                .and_then(|e| e.info.trampoline_address)
                .unwrap_or(address),
        })
    }

    // ========================================================================
    // Transactions
    // ========================================================================

    pub fn begin_transaction(&mut self) -> u32 {
        let id = TRANSACTION_COUNTER.fetch_add(1, Ordering::SeqCst);
        let transaction = HookTransaction {
            id,
            hooks_to_install: vec![],
            hooks_to_remove: vec![],
            committed: false,
            rollback_data: vec![],
        };
        self.transactions.insert(id, transaction);
        debug!("Started hook transaction {}", id);
        id
    }

    pub fn transaction_add_hook(&mut self, tx_id: u32, request: InlineHookRequest) -> Result<()> {
        let tx = self
            .transactions
            .get_mut(&tx_id)
            .ok_or_else(|| Error::Internal(format!("Transaction {} not found", tx_id)))?;
        if tx.committed {
            return Err(Error::Internal("Transaction already committed".into()));
        }
        tx.hooks_to_install.push(request);
        Ok(())
    }

    pub fn transaction_remove_hook(&mut self, tx_id: u32, hook_id: HookId) -> Result<()> {
        let tx = self
            .transactions
            .get_mut(&tx_id)
            .ok_or_else(|| Error::Internal(format!("Transaction {} not found", tx_id)))?;
        if tx.committed {
            return Err(Error::Internal("Transaction already committed".into()));
        }
        tx.hooks_to_remove.push(hook_id);
        Ok(())
    }

    pub fn commit_transaction(&mut self, tx_id: u32) -> Result<Vec<HookResult>> {
        let tx = self
            .transactions
            .remove(&tx_id)
            .ok_or_else(|| Error::Internal(format!("Transaction {} not found", tx_id)))?;

        if tx.committed {
            return Err(Error::Internal("Transaction already committed".into()));
        }

        let mut results = vec![];
        let mut rollback_data = vec![];

        for request in tx.hooks_to_install {
            match self.install_inline_hook(request) {
                Ok(result) => {
                    if let Some(ref info) = result.hook_info {
                        rollback_data.push(HookRollbackEntry {
                            hook_id: info.id,
                            address: info.target_address,
                            original_bytes: info.original_bytes.clone(),
                        });
                    }
                    results.push(result);
                }
                Err(e) => {
                    for entry in rollback_data {
                        let _ = self.remove_hook(entry.hook_id);
                    }
                    return Err(e);
                }
            }
        }

        for hook_id in tx.hooks_to_remove {
            if let Err(e) = self.remove_hook(hook_id) {
                warn!("Failed to remove hook in transaction: {}", e);
            }
        }

        info!("Committed transaction {}", tx_id);
        Ok(results)
    }

    pub fn rollback_transaction(&mut self, tx_id: u32) -> Result<()> {
        self.transactions
            .remove(&tx_id)
            .ok_or_else(|| Error::Internal(format!("Transaction {} not found", tx_id)))?;
        debug!("Rolled back transaction {}", tx_id);
        Ok(())
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    #[cfg(target_os = "windows")]
    fn register_veh_handler(&mut self) -> Result<()> {
        use windows::Win32::System::Diagnostics::Debug::AddVectoredExceptionHandler;
        unsafe {
            let handler = AddVectoredExceptionHandler(1, Some(veh_handler_callback));
            if handler.is_null() {
                return Err(Error::Internal("Failed to register VEH handler".into()));
            }
            self.veh_handler = Some(handler as usize);
        }
        debug!("Registered VEH handler");
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn unregister_veh_handler(&mut self) {
        use windows::Win32::System::Diagnostics::Debug::RemoveVectoredExceptionHandler;
        if let Some(handler) = self.veh_handler.take() {
            unsafe {
                RemoveVectoredExceptionHandler(handler as *mut std::ffi::c_void);
            }
            debug!("Unregistered VEH handler");
        }
    }

    fn has_hot_patch_prologue(&self, addr: usize) -> bool {
        self.read_memory(addr, 2)
            .map(|b| b == HOT_PATCH_PROLOGUE)
            .unwrap_or(false)
    }

    fn get_hook_size(&self, hook_type: ExtendedHookType) -> usize {
        match hook_type {
            ExtendedHookType::InlineTrampoline => X64_ABS_JMP_SIZE,
            ExtendedHookType::InlineRelativePatch => X64_REL_JMP_SIZE,
            ExtendedHookType::InlineHotPatch => 7,
            ExtendedHookType::InlineInt3 => 1,
            _ => X64_ABS_JMP_SIZE,
        }
    }

    fn get_chain_index(&self, address: u64) -> u32 {
        self.hooks_by_address
            .get(&address)
            .map(|v| v.len() as u32)
            .unwrap_or(0)
    }

    #[cfg(target_os = "windows")]
    fn read_memory(&self, addr: usize, size: usize) -> Result<Vec<u8>> {
        let slice = unsafe { std::slice::from_raw_parts(addr as *const u8, size) };
        Ok(slice.to_vec())
    }

    #[cfg(not(target_os = "windows"))]
    fn read_memory(&self, _addr: usize, _size: usize) -> Result<Vec<u8>> {
        Err(Error::NotImplemented("Memory read not supported".into()))
    }

    #[cfg(target_os = "windows")]
    fn write_memory(&self, addr: usize, data: &[u8]) -> Result<()> {
        unsafe {
            let mut old_protect = PAGE_PROTECTION_FLAGS(0);
            VirtualProtect(
                addr as *const std::ffi::c_void,
                data.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            )
            .map_err(|e| Error::Internal(format!("VirtualProtect failed: {}", e)))?;
            std::ptr::copy_nonoverlapping(data.as_ptr(), addr as *mut u8, data.len());
            VirtualProtect(
                addr as *const std::ffi::c_void,
                data.len(),
                old_protect,
                &mut old_protect,
            )
            .ok();
            FlushInstructionCache(
                GetCurrentProcess(),
                Some(addr as *const std::ffi::c_void),
                data.len(),
            )
            .ok();
        }
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn write_memory(&self, _addr: usize, _data: &[u8]) -> Result<()> {
        Err(Error::NotImplemented("Memory write not supported".into()))
    }

    #[cfg(target_os = "windows")]
    fn read_pointer(&self, addr: usize) -> Result<usize> {
        unsafe { Ok(*(addr as *const usize)) }
    }

    #[cfg(not(target_os = "windows"))]
    fn read_pointer(&self, _addr: usize) -> Result<usize> {
        Err(Error::NotImplemented("Pointer read not supported".into()))
    }

    #[cfg(target_os = "windows")]
    fn write_pointer(&self, addr: usize, value: usize) -> Result<()> {
        unsafe {
            let mut old_protect = PAGE_PROTECTION_FLAGS(0);
            VirtualProtect(
                addr as *const std::ffi::c_void,
                std::mem::size_of::<usize>(),
                PAGE_READWRITE,
                &mut old_protect,
            )
            .map_err(|e| Error::Internal(format!("VirtualProtect failed: {}", e)))?;
            *(addr as *mut usize) = value;
            VirtualProtect(
                addr as *const std::ffi::c_void,
                std::mem::size_of::<usize>(),
                old_protect,
                &mut old_protect,
            )
            .ok();
        }
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn write_pointer(&self, _addr: usize, _value: usize) -> Result<()> {
        Err(Error::NotImplemented("Pointer write not supported".into()))
    }

    #[cfg(target_os = "windows")]
    fn write_dword(&self, addr: usize, value: u32) -> Result<()> {
        unsafe {
            let mut old_protect = PAGE_PROTECTION_FLAGS(0);
            VirtualProtect(
                addr as *const std::ffi::c_void,
                4,
                PAGE_READWRITE,
                &mut old_protect,
            )
            .map_err(|e| Error::Internal(format!("VirtualProtect failed: {}", e)))?;
            *(addr as *mut u32) = value;
            VirtualProtect(
                addr as *const std::ffi::c_void,
                4,
                old_protect,
                &mut old_protect,
            )
            .ok();
        }
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn write_dword(&self, _addr: usize, _value: u32) -> Result<()> {
        Err(Error::NotImplemented("DWORD write not supported".into()))
    }

    fn allocate_trampoline(&self, target: usize, original_bytes: &[u8]) -> Result<usize> {
        // Calculate size needed for trampoline
        // TRAMPOLINE_ALLOC_SIZE is 64 bytes which is usually enough.

        let tramp_addr = self.allocate_near(target, TRAMPOLINE_ALLOC_SIZE)?;

        // Relocate instructions to the trampoline buffer
        // This handles RIP-relative addressing
        let mut relocator = TrampolineRelocator::new(target as u64, tramp_addr as u64);
        // Map Result to ghost_common::Result explicitly if needed, but Error conversion should handle it?
        // ghost_common::Error matches.
        let relocated_size = relocator.relocate(original_bytes, tramp_addr as *mut u8)?;

        // Write absolute jump back to the rest of the target function
        let return_addr = target + original_bytes.len();
        let jump_bytes = generate_abs_jump(return_addr);

        if relocated_size + jump_bytes.len() > TRAMPOLINE_ALLOC_SIZE {
            unsafe {
                VirtualFree(tramp_addr as *mut std::ffi::c_void, 0, MEM_RELEASE).ok();
            }
            return Err(Error::Internal(
                "Trampoline buffer too small for relocated instructions".into(),
            ));
        }

        unsafe {
            std::ptr::copy_nonoverlapping(
                jump_bytes.as_ptr(),
                (tramp_addr + relocated_size) as *mut u8,
                jump_bytes.len(),
            );
        }

        Ok(tramp_addr)
    }

    #[cfg(not(target_os = "windows"))]
    fn allocate_trampoline(&self, _target: usize, _original_bytes: &[u8]) -> Result<usize> {
        Err(Error::NotImplemented(
            "Trampoline allocation not supported".into(),
        ))
    }

    #[cfg(target_os = "windows")]
    fn allocate_near(&self, target: usize, size: usize) -> Result<usize> {
        let step = 0x10000; // 64KB
        let max_dist = 0x7FFF0000; // ~2GB

        // Try allocating within +/- 2GB of target
        for i in 1..1024 {
            // Try up to ~64MB distance with increasing steps or just loop
            // Actually, simple linear search from target
            let dist = i * step;
            if dist > max_dist {
                break;
            }

            // Try below
            if let Some(addr) = target.checked_sub(dist) {
                unsafe {
                    let mem = VirtualAlloc(
                        Some(addr as *const std::ffi::c_void),
                        size,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE,
                    );
                    if !mem.is_null() {
                        return Ok(mem as usize);
                    }
                }
            }
            // Try above
            if let Some(addr) = target.checked_add(dist) {
                unsafe {
                    let mem = VirtualAlloc(
                        Some(addr as *const std::ffi::c_void),
                        size,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE,
                    );
                    if !mem.is_null() {
                        return Ok(mem as usize);
                    }
                }
            }
        }

        // Fallback to anywhere
        unsafe {
            let mem = VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if !mem.is_null() {
                return Ok(mem as usize);
            }
        }

        Err(Error::Internal(
            "Failed to allocate trampoline memory".into(),
        ))
    }

    #[cfg(target_os = "windows")]
    fn write_hook_jump(
        &self,
        target: usize,
        callback: usize,
        hook_type: ExtendedHookType,
    ) -> Result<()> {
        match hook_type {
            ExtendedHookType::InlineRelativePatch => {
                if let Some(rel_jmp) = generate_rel_jump(target, callback) {
                    self.write_memory(target, &rel_jmp)?;
                } else {
                    return Err(Error::Internal("Target too far for relative jump".into()));
                }
            }
            _ => {
                let abs_jmp = generate_abs_jump(callback);
                self.write_memory(target, &abs_jmp)?;
            }
        }
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn write_hook_jump(
        &self,
        _target: usize,
        _callback: usize,
        _hook_type: ExtendedHookType,
    ) -> Result<()> {
        Err(Error::NotImplemented(
            "Hook jump write not supported".into(),
        ))
    }

    #[cfg(target_os = "windows")]
    fn get_module_base(&self, module_name: &str) -> Result<usize> {
        let wide: Vec<u16> = module_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        unsafe {
            let handle = GetModuleHandleW(windows::core::PCWSTR(wide.as_ptr()))
                .map_err(|e| Error::ModuleNotFound(format!("{}: {}", module_name, e)))?;
            Ok(handle.0 as usize)
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn get_module_base(&self, _module_name: &str) -> Result<usize> {
        Err(Error::NotImplemented(
            "Module base resolution not supported".into(),
        ))
    }

    #[cfg(target_os = "windows")]
    fn find_iat_entry(
        &self,
        module_name: &str,
        import_dll: &str,
        function_name: &str,
    ) -> Result<IatEntry> {
        let entries = self.enumerate_iat(module_name)?;
        entries
            .into_iter()
            .find(|e| {
                e.import_dll.eq_ignore_ascii_case(import_dll)
                    && e.function_name.eq_ignore_ascii_case(function_name)
            })
            .ok_or_else(|| {
                Error::SymbolNotFound(format!(
                    "{}!{} from {}",
                    module_name, function_name, import_dll
                ))
            })
    }

    #[cfg(not(target_os = "windows"))]
    fn find_iat_entry(
        &self,
        _module_name: &str,
        _import_dll: &str,
        _function_name: &str,
    ) -> Result<IatEntry> {
        Err(Error::NotImplemented("IAT lookup not supported".into()))
    }

    #[cfg(target_os = "windows")]
    fn find_eat_entry(&self, module_name: &str, function_name: &str) -> Result<EatEntry> {
        let entries = self.enumerate_eat(module_name)?;
        entries
            .into_iter()
            .find(|e| e.function_name.eq_ignore_ascii_case(function_name))
            .ok_or_else(|| Error::SymbolNotFound(format!("{}!{}", module_name, function_name)))
    }

    #[cfg(not(target_os = "windows"))]
    fn find_eat_entry(&self, _module_name: &str, _function_name: &str) -> Result<EatEntry> {
        Err(Error::NotImplemented("EAT lookup not supported".into()))
    }

    #[cfg(target_os = "windows")]
    fn find_syscall_stub(&self, function_name: &str) -> Result<u64> {
        use std::ffi::CString;
        use windows::Win32::System::LibraryLoader::GetProcAddress;

        let ntdll_base = self.get_module_base("ntdll.dll")?;
        let func_name = CString::new(function_name)
            .map_err(|_| Error::Internal("Invalid function name".into()))?;

        unsafe {
            let proc = GetProcAddress(
                windows::Win32::Foundation::HMODULE(ntdll_base as *mut _),
                windows::core::PCSTR(func_name.as_ptr() as *const u8),
            );
            proc.map(|p| p as usize as u64)
                .ok_or_else(|| Error::SymbolNotFound(format!("ntdll!{}", function_name)))
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn find_syscall_stub(&self, _function_name: &str) -> Result<u64> {
        Err(Error::NotImplemented(
            "Syscall stub lookup not supported".into(),
        ))
    }

    #[cfg(target_os = "windows")]
    pub fn enumerate_iat(&self, module_name: &str) -> Result<Vec<IatEntry>> {
        let module_base = self.get_module_base(module_name)?;
        let mut entries = vec![];

        unsafe {
            let dos_header = module_base as *const u8;
            if *(dos_header as *const u16) != 0x5A4D {
                return Err(Error::Internal("Invalid DOS header".into()));
            }

            let e_lfanew = *((module_base + 0x3C) as *const i32);
            let nt_headers = module_base + e_lfanew as usize;

            let import_dir_rva = *((nt_headers + 0x90) as *const u32);
            if import_dir_rva == 0 {
                return Ok(entries);
            }

            let mut import_desc = module_base + import_dir_rva as usize;

            loop {
                let name_rva = *((import_desc + 12) as *const u32);
                if name_rva == 0 {
                    break;
                }

                let dll_name =
                    std::ffi::CStr::from_ptr((module_base + name_rva as usize) as *const i8)
                        .to_string_lossy()
                        .to_string();

                let first_thunk = *((import_desc + 16) as *const u32);
                let orig_first_thunk = *((import_desc) as *const u32);
                let orig_thunk_base = if orig_first_thunk != 0 {
                    orig_first_thunk
                } else {
                    first_thunk
                };

                let mut thunk_idx = 0usize;
                loop {
                    let thunk_addr = module_base + first_thunk as usize + thunk_idx * 8;
                    let orig_thunk_addr = module_base + orig_thunk_base as usize + thunk_idx * 8;

                    let thunk_val = *(thunk_addr as *const u64);
                    if thunk_val == 0 {
                        break;
                    }

                    let orig_thunk_val = *(orig_thunk_addr as *const u64);

                    let (func_name, ordinal) = if (orig_thunk_val & 0x8000000000000000) != 0 {
                        (
                            format!("Ordinal_{}", orig_thunk_val & 0xFFFF),
                            Some((orig_thunk_val & 0xFFFF) as u16),
                        )
                    } else {
                        let hint_name = module_base + (orig_thunk_val & 0x7FFFFFFF) as usize;
                        let name = std::ffi::CStr::from_ptr((hint_name + 2) as *const i8)
                            .to_string_lossy()
                            .to_string();
                        (name, None)
                    };

                    entries.push(IatEntry {
                        module_name: module_name.to_string(),
                        import_dll: dll_name.clone(),
                        function_name: func_name,
                        ordinal,
                        iat_slot_address: thunk_addr as u64,
                        current_address: thunk_val,
                        original_address: None,
                        is_hooked: false,
                    });

                    thunk_idx += 1;
                }
                import_desc += 20;
            }
        }
        Ok(entries)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn enumerate_iat(&self, _module_name: &str) -> Result<Vec<IatEntry>> {
        Err(Error::NotImplemented(
            "IAT enumeration not supported".into(),
        ))
    }

    #[cfg(target_os = "windows")]
    pub fn enumerate_eat(&self, module_name: &str) -> Result<Vec<EatEntry>> {
        let module_base = self.get_module_base(module_name)?;
        let mut entries = vec![];

        unsafe {
            let dos_header = module_base as *const u8;
            if *(dos_header as *const u16) != 0x5A4D {
                return Err(Error::Internal("Invalid DOS header".into()));
            }

            let e_lfanew = *((module_base + 0x3C) as *const i32);
            let nt_headers = module_base + e_lfanew as usize;

            let export_dir_rva = *((nt_headers + 0x88) as *const u32);
            let export_dir_size = *((nt_headers + 0x8C) as *const u32);
            if export_dir_rva == 0 {
                return Ok(entries);
            }

            let export_dir = module_base + export_dir_rva as usize;
            let num_names = *((export_dir + 24) as *const u32);
            let addr_of_funcs = module_base + *((export_dir + 28) as *const u32) as usize;
            let addr_of_names = module_base + *((export_dir + 32) as *const u32) as usize;
            let addr_of_ords = module_base + *((export_dir + 36) as *const u32) as usize;
            let base = *((export_dir + 16) as *const u32);

            for i in 0..num_names as usize {
                let name_rva = *((addr_of_names + i * 4) as *const u32);
                let func_name =
                    std::ffi::CStr::from_ptr((module_base + name_rva as usize) as *const i8)
                        .to_string_lossy()
                        .to_string();

                let ordinal_index = *((addr_of_ords + i * 2) as *const u16) as usize;
                let func_rva = *((addr_of_funcs + ordinal_index * 4) as *const u32);
                let func_addr = module_base + func_rva as usize;

                let export_start = module_base + export_dir_rva as usize;
                let export_end = export_start + export_dir_size as usize;
                let is_forwarded = func_addr >= export_start && func_addr < export_end;

                entries.push(EatEntry {
                    module_name: module_name.to_string(),
                    function_name: func_name,
                    ordinal: (base + ordinal_index as u32) as u16,
                    eat_slot_address: (addr_of_funcs + ordinal_index * 4) as u64,
                    rva: func_rva,
                    function_address: func_addr as u64,
                    is_forwarded,
                    forwarder: None,
                    is_hooked: false,
                });
            }
        }
        Ok(entries)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn enumerate_eat(&self, _module_name: &str) -> Result<Vec<EatEntry>> {
        Err(Error::NotImplemented(
            "EAT enumeration not supported".into(),
        ))
    }
}

// VEH handler callback for INT3 and PAGE_GUARD hooks
#[cfg(target_os = "windows")]
unsafe extern "system" fn veh_handler_callback(
    exception_info: *mut windows::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS,
) -> i32 {
    use windows::Win32::Foundation::EXCEPTION_BREAKPOINT;
    use windows::Win32::System::Diagnostics::Debug::EXCEPTION_CONTINUE_SEARCH;

    if exception_info.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let record = (*exception_info).ExceptionRecord;
    if record.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let code = (*record).ExceptionCode;

    // Handle INT3 breakpoints
    if code == EXCEPTION_BREAKPOINT {
        // For now, just continue search - full implementation would dispatch to hook callbacks
        return EXCEPTION_CONTINUE_SEARCH;
    }

    EXCEPTION_CONTINUE_SEARCH
}

// ============================================================================
// Public API Functions
// ============================================================================

/// Get the global hook manager instance
pub fn get_hook_manager() -> &'static RwLock<ExtendedHookManager> {
    &HOOK_MANAGER
}

/// Initialize the hook manager
pub fn initialize() -> Result<()> {
    HOOK_MANAGER
        .write()
        .map_err(|_| Error::Internal("Failed to acquire hook manager lock".into()))?
        .initialize()
}

/// Shutdown the hook manager
pub fn shutdown() -> Result<()> {
    HOOK_MANAGER
        .write()
        .map_err(|_| Error::Internal("Failed to acquire hook manager lock".into()))?
        .shutdown()
}

// ============================================================================
// Shellcode Support
// ============================================================================

pub mod shellcode {
    use ghost_common::types::{
        GadgetType, RopGadget, RopGadgetRequest, RopGadgetResult, ShellcodeArch, ShellcodeEncoder,
        ShellcodeInjectRequest, ShellcodeInjectResult, ShellcodeRequest, ShellcodeResult,
        ShellcodeTemplate,
    };
    use ghost_common::{Error, Result};
    use tracing::{debug, info};

    #[cfg(target_os = "windows")]
    use windows::Win32::System::Memory::{
        VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    };
    #[cfg(target_os = "windows")]
    use windows::Win32::System::Threading::{CreateThread, WaitForSingleObject, INFINITE};

    /// Generate shellcode from a template
    pub fn generate(request: ShellcodeRequest) -> Result<ShellcodeResult> {
        debug!(
            "Generating {:?} shellcode for {:?}",
            request.template, request.arch
        );

        let shellcode = match request.template {
            ShellcodeTemplate::NopSled => {
                let count = request.params.nop_count.unwrap_or(16) as usize;
                vec![0x90u8; count]
            }
            ShellcodeTemplate::InfiniteLoop => {
                match request.arch {
                    ShellcodeArch::X64 => vec![0xEB, 0xFE], // jmp $
                    ShellcodeArch::X86 => vec![0xEB, 0xFE],
                }
            }
            ShellcodeTemplate::ExitThread => match request.arch {
                ShellcodeArch::X64 => generate_exit_thread_x64(),
                ShellcodeArch::X86 => generate_exit_thread_x86(),
            },
            ShellcodeTemplate::CallFunction => {
                let addr = request.params.function_address.ok_or_else(|| {
                    Error::Internal("function_address required for CallFunction template".into())
                })?;
                match request.arch {
                    ShellcodeArch::X64 => {
                        generate_call_function_x64(addr, &request.params.arguments)
                    }
                    ShellcodeArch::X86 => {
                        generate_call_function_x86(addr, &request.params.arguments)
                    }
                }
            }
            ShellcodeTemplate::Custom => request.params.custom_bytes.clone().unwrap_or_default(),
            _ => {
                return Err(Error::NotImplemented(format!(
                    "Shellcode template {:?} not yet implemented",
                    request.template
                )));
            }
        };

        let final_shellcode = if request.encode {
            encode_shellcode(&shellcode, request.encoder, &request.bad_chars)?
        } else {
            shellcode
        };

        Ok(ShellcodeResult {
            success: true,
            shellcode: final_shellcode.clone(),
            size: final_shellcode.len(),
            entry_offset: 0,
            is_pic: true,
            encoder: if request.encode {
                request.encoder
            } else {
                None
            },
            decoder_size: None,
            error: None,
        })
    }

    /// Inject and optionally execute shellcode
    #[cfg(target_os = "windows")]
    pub fn inject(request: ShellcodeInjectRequest) -> Result<ShellcodeInjectResult> {
        debug!("Injecting {} bytes of shellcode", request.shellcode.len());

        let addr = if let Some(target) = request.target_address {
            target as usize
        } else {
            // Allocate new memory
            unsafe {
                let mem = VirtualAlloc(
                    Some(std::ptr::null()),
                    request.shellcode.len(),
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                );
                if mem.is_null() {
                    return Err(Error::Internal(
                        "Failed to allocate memory for shellcode".into(),
                    ));
                }
                mem as usize
            }
        };

        // Write shellcode
        unsafe {
            std::ptr::copy_nonoverlapping(
                request.shellcode.as_ptr(),
                addr as *mut u8,
                request.shellcode.len(),
            );
        }

        let mut thread_id = None;
        let mut return_value = None;

        if request.execute {
            unsafe {
                let start_routine: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
                    std::mem::transmute(addr);
                let handle = CreateThread(
                    None,
                    0,
                    Some(start_routine),
                    None,
                    windows::Win32::System::Threading::THREAD_CREATE_RUN_IMMEDIATELY,
                    None,
                )
                .map_err(|e| Error::Internal(format!("CreateThread failed: {}", e)))?;

                thread_id = Some(windows::Win32::System::Threading::GetThreadId(handle));

                if request.wait {
                    let timeout = request.timeout_ms.unwrap_or(INFINITE);
                    WaitForSingleObject(handle, timeout);
                    // Get exit code
                    let mut exit_code = 0u32;
                    windows::Win32::System::Threading::GetExitCodeThread(handle, &mut exit_code)
                        .ok();
                    return_value = Some(exit_code as u64);
                }

                windows::Win32::Foundation::CloseHandle(handle).ok();
            }
        }

        info!("Injected shellcode at {:#x}", addr);

        Ok(ShellcodeInjectResult {
            success: true,
            address: addr as u64,
            thread_id,
            return_value,
            error: None,
        })
    }

    #[cfg(not(target_os = "windows"))]
    pub fn inject(_request: ShellcodeInjectRequest) -> Result<ShellcodeInjectResult> {
        Err(Error::NotImplemented(
            "Shellcode injection only supported on Windows".into(),
        ))
    }

    /// Find ROP gadgets in loaded modules
    #[cfg(target_os = "windows")]
    pub fn find_rop_gadgets(request: RopGadgetRequest) -> Result<RopGadgetResult> {
        use super::get_hook_manager;

        debug!("Searching for ROP gadgets");

        let manager = get_hook_manager()
            .read()
            .map_err(|_| Error::Internal("Failed to acquire hook manager lock".into()))?;

        let mut gadgets = Vec::new();
        let modules_to_search: Vec<String> = if request.modules.is_empty() {
            // Search ntdll and kernel32 by default
            vec!["ntdll.dll".to_string(), "kernel32.dll".to_string()]
        } else {
            request.modules.clone()
        };

        for module_name in &modules_to_search {
            if let Ok(_module_base) = manager.get_module_base(module_name) {
                // Simple gadget search - look for RET instructions and work backwards
                if let Ok(eat_entries) = manager.enumerate_eat(module_name) {
                    for entry in eat_entries.iter().take(100) {
                        let addr = entry.function_address as usize;
                        // Scan for RET (0xC3) in function
                        for offset in 0..64 {
                            let check_addr = addr + offset;
                            if let Ok(bytes) = manager.read_memory(check_addr, 1) {
                                if bytes[0] == 0xC3 {
                                    // Found RET, extract gadget
                                    let gadget_start =
                                        if offset >= request.max_instructions as usize * 4 {
                                            check_addr - request.max_instructions as usize * 4
                                        } else {
                                            addr
                                        };

                                    if let Ok(gadget_bytes) = manager
                                        .read_memory(gadget_start, check_addr - gadget_start + 1)
                                    {
                                        // Check for bad chars
                                        if !gadget_bytes
                                            .iter()
                                            .any(|b| request.bad_chars.contains(b))
                                        {
                                            gadgets.push(RopGadget {
                                                address: gadget_start as u64,
                                                module: module_name.clone(),
                                                bytes: gadget_bytes.clone(),
                                                disasm: format!("gadget at {:#x}", gadget_start),
                                                gadget_type: GadgetType::Ret,
                                                registers_modified: vec![],
                                                stack_delta: 0,
                                            });

                                            if gadgets.len() >= request.max_results as usize {
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if gadgets.len() >= request.max_results as usize {
                            break;
                        }
                    }
                }
            }
        }

        let total = gadgets.len() as u32;

        Ok(RopGadgetResult {
            success: true,
            gadgets,
            total_found: total,
            modules_searched: modules_to_search,
            error: None,
        })
    }

    #[cfg(not(target_os = "windows"))]
    pub fn find_rop_gadgets(_request: RopGadgetRequest) -> Result<RopGadgetResult> {
        Err(Error::NotImplemented(
            "ROP gadget search only supported on Windows".into(),
        ))
    }

    // Helper functions for shellcode generation
    fn generate_exit_thread_x64() -> Vec<u8> {
        // mov ecx, 0; call ExitThread (simplified - real impl would resolve dynamically)
        vec![0x31, 0xC9, 0xC3] // xor ecx, ecx; ret (placeholder)
    }

    fn generate_exit_thread_x86() -> Vec<u8> {
        vec![0x31, 0xC0, 0xC3] // xor eax, eax; ret (placeholder)
    }

    fn generate_call_function_x64(addr: u64, args: &[u64]) -> Vec<u8> {
        let mut code = Vec::new();

        // Set up arguments in registers (Windows x64 calling convention)
        // RCX, RDX, R8, R9 for first 4 args
        if !args.is_empty() {
            code.extend_from_slice(&[0x48, 0xB9]); // mov rcx, imm64
            code.extend_from_slice(&args[0].to_le_bytes());
        }
        if args.len() > 1 {
            code.extend_from_slice(&[0x48, 0xBA]); // mov rdx, imm64
            code.extend_from_slice(&args[1].to_le_bytes());
        }
        if args.len() > 2 {
            code.extend_from_slice(&[0x49, 0xB8]); // mov r8, imm64
            code.extend_from_slice(&args[2].to_le_bytes());
        }
        if args.len() > 3 {
            code.extend_from_slice(&[0x49, 0xB9]); // mov r9, imm64
            code.extend_from_slice(&args[3].to_le_bytes());
        }

        // mov rax, addr; call rax
        code.extend_from_slice(&[0x48, 0xB8]); // mov rax, imm64
        code.extend_from_slice(&addr.to_le_bytes());
        code.extend_from_slice(&[0xFF, 0xD0]); // call rax
        code.extend_from_slice(&[0xC3]); // ret

        code
    }

    fn generate_call_function_x86(addr: u64, args: &[u64]) -> Vec<u8> {
        let mut code = Vec::new();

        // Push args in reverse order (cdecl)
        for arg in args.iter().rev() {
            code.push(0x68); // push imm32
            code.extend_from_slice(&(*arg as u32).to_le_bytes());
        }

        // mov eax, addr; call eax
        code.push(0xB8); // mov eax, imm32
        code.extend_from_slice(&(addr as u32).to_le_bytes());
        code.extend_from_slice(&[0xFF, 0xD0]); // call eax

        // Clean up stack
        if !args.is_empty() {
            code.extend_from_slice(&[0x83, 0xC4, (args.len() * 4) as u8]); // add esp, N
        }

        code.push(0xC3); // ret

        code
    }

    fn encode_shellcode(
        shellcode: &[u8],
        encoder: Option<ShellcodeEncoder>,
        _bad_chars: &[u8],
    ) -> Result<Vec<u8>> {
        match encoder {
            Some(ShellcodeEncoder::XorSingle) => {
                // XOR with key 0x41
                let key = 0x41u8;
                let encoded: Vec<u8> = shellcode.iter().map(|b| b ^ key).collect();

                // Prepend decoder stub
                let mut result = vec![
                    0x48, 0x31, 0xC9, // xor rcx, rcx
                    0x48, 0x81, 0xC1, // add rcx, len
                ];
                result.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
                result.extend_from_slice(&[
                    0x48, 0x8D, 0x35, 0x0A, 0x00, 0x00, 0x00, // lea rsi, [rip+10]
                    0x80, 0x36, key, // xor byte [rsi], key
                    0x48, 0xFF, 0xC6, // inc rsi
                    0xE2, 0xF8, // loop -8
                ]);
                result.extend(encoded);

                Ok(result)
            }
            _ => Ok(shellcode.to_vec()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::types::{
        ExtendedHookType, GadgetType, HookState, ShellcodeArch, ShellcodeEncoder, ShellcodeParams,
        ShellcodeRequest, ShellcodeTemplate,
    };

    #[test]
    fn test_hook_manager_creation() {
        let manager = ExtendedHookManager::new();
        assert!(!manager.initialized);
        assert!(manager.hooks.is_empty());
        assert!(manager.iat_hooks.is_empty());
        assert!(manager.eat_hooks.is_empty());
    }

    #[test]
    fn test_hook_id_display() {
        let id = HookId(42);
        assert_eq!(format!("{}", id), "hook_42");
    }

    #[test]
    fn test_extended_hook_type_display() {
        assert_eq!(
            format!("{}", ExtendedHookType::InlineTrampoline),
            "Inline Trampoline"
        );
        assert_eq!(format!("{}", ExtendedHookType::IatHook), "IAT Hook");
        assert_eq!(format!("{}", ExtendedHookType::EatHook), "EAT Hook");
        assert_eq!(
            format!("{}", ExtendedHookType::VehPageGuard),
            "VEH/PAGE_GUARD"
        );
        assert_eq!(format!("{}", ExtendedHookType::Syscall), "Syscall");
    }

    #[test]
    fn test_hook_state_serialization() {
        let enabled = HookState::Enabled;
        let disabled = HookState::Disabled;
        assert_ne!(enabled, disabled);
    }

    #[test]
    fn test_shellcode_params_default() {
        let params = ShellcodeParams::default();
        assert!(params.function_address.is_none());
        assert!(params.arguments.is_empty());
        assert!(params.string_param.is_none());
        assert!(params.nop_count.is_none());
    }

    #[test]
    fn test_shellcode_generate_nop_sled() {
        let request = ShellcodeRequest {
            template: ShellcodeTemplate::NopSled,
            arch: ShellcodeArch::X64,
            params: ShellcodeParams {
                nop_count: Some(10),
                ..Default::default()
            },
            encode: false,
            encoder: None,
            bad_chars: vec![],
        };

        let result = shellcode::generate(request).unwrap();
        assert!(result.success);
        assert_eq!(result.size, 10);
        assert!(result.shellcode.iter().all(|&b| b == 0x90));
    }

    #[test]
    fn test_shellcode_generate_infinite_loop() {
        let request = ShellcodeRequest {
            template: ShellcodeTemplate::InfiniteLoop,
            arch: ShellcodeArch::X64,
            params: ShellcodeParams::default(),
            encode: false,
            encoder: None,
            bad_chars: vec![],
        };

        let result = shellcode::generate(request).unwrap();
        assert!(result.success);
        assert_eq!(result.shellcode, vec![0xEB, 0xFE]); // jmp $
    }

    #[test]
    fn test_shellcode_generate_call_function_x64() {
        let request = ShellcodeRequest {
            template: ShellcodeTemplate::CallFunction,
            arch: ShellcodeArch::X64,
            params: ShellcodeParams {
                function_address: Some(0x00007FF712345678),
                arguments: vec![1, 2],
                ..Default::default()
            },
            encode: false,
            encoder: None,
            bad_chars: vec![],
        };

        let result = shellcode::generate(request).unwrap();
        assert!(result.success);
        assert!(result.is_pic);
        // Should contain mov rcx, mov rdx, mov rax, call rax, ret
        assert!(result.shellcode.len() > 20);
    }

    #[test]
    fn test_shellcode_generate_call_function_x86() {
        let request = ShellcodeRequest {
            template: ShellcodeTemplate::CallFunction,
            arch: ShellcodeArch::X86,
            params: ShellcodeParams {
                function_address: Some(0x12345678),
                arguments: vec![1, 2, 3],
                ..Default::default()
            },
            encode: false,
            encoder: None,
            bad_chars: vec![],
        };

        let result = shellcode::generate(request).unwrap();
        assert!(result.success);
        // Should contain push instructions, mov eax, call eax, add esp, ret
        assert!(result.shellcode.len() > 10);
    }

    #[test]
    fn test_shellcode_xor_encoding() {
        let request = ShellcodeRequest {
            template: ShellcodeTemplate::NopSled,
            arch: ShellcodeArch::X64,
            params: ShellcodeParams {
                nop_count: Some(4),
                ..Default::default()
            },
            encode: true,
            encoder: Some(ShellcodeEncoder::XorSingle),
            bad_chars: vec![],
        };

        let result = shellcode::generate(request).unwrap();
        assert!(result.success);
        assert_eq!(result.encoder, Some(ShellcodeEncoder::XorSingle));
        // Encoded result should be larger due to decoder stub
        assert!(result.size > 4);
    }

    #[test]
    fn test_shellcode_custom_bytes() {
        let custom = vec![0x90, 0x90, 0xCC, 0xC3];
        let request = ShellcodeRequest {
            template: ShellcodeTemplate::Custom,
            arch: ShellcodeArch::X64,
            params: ShellcodeParams {
                custom_bytes: Some(custom.clone()),
                ..Default::default()
            },
            encode: false,
            encoder: None,
            bad_chars: vec![],
        };

        let result = shellcode::generate(request).unwrap();
        assert!(result.success);
        assert_eq!(result.shellcode, custom);
    }

    #[test]
    fn test_hook_filter_default() {
        let filter = HookFilter::default();
        assert!(filter.hook_type.is_none());
        assert!(filter.module.is_none());
        assert!(filter.state.is_none());
        assert!(filter.address_range.is_none());
    }

    #[test]
    fn test_inline_hook_request_creation() {
        let request = InlineHookRequest {
            target_address: 0x140001000,
            callback_address: 0x140002000,
            hook_type: Some(ExtendedHookType::InlineTrampoline),
            offset: None,
            enable: true,
        };

        assert_eq!(request.target_address, 0x140001000);
        assert_eq!(request.callback_address, 0x140002000);
        assert!(request.enable);
    }

    #[test]
    fn test_iat_hook_request_creation() {
        let request = IatHookRequest {
            module_name: "test.exe".to_string(),
            function_name: "MessageBoxW".to_string(),
            import_module: "user32.dll".to_string(),
            callback_address: 0x140003000,
            enable: true,
        };

        assert_eq!(request.module_name, "test.exe");
        assert_eq!(request.import_module, "user32.dll");
    }

    #[test]
    fn test_eat_hook_request_creation() {
        let request = EatHookRequest {
            module_name: "kernel32.dll".to_string(),
            function_name: "GetProcAddress".to_string(),
            callback_address: 0x140004000,
            enable: true,
        };

        assert_eq!(request.module_name, "kernel32.dll");
        assert_eq!(request.function_name, "GetProcAddress");
    }

    #[test]
    fn test_veh_hook_request_creation() {
        let request = VehHookRequest {
            target_address: 0x140005000,
            size: 0x1000,
            on_execute: true,
            on_read: false,
            on_write: true,
            callback_address: 0x140006000,
        };

        assert!(request.on_execute);
        assert!(!request.on_read);
        assert!(request.on_write);
    }

    #[test]
    fn test_transaction_counter_increments() {
        let id1 = TRANSACTION_COUNTER.fetch_add(1, Ordering::SeqCst);
        let id2 = TRANSACTION_COUNTER.fetch_add(1, Ordering::SeqCst);
        assert!(id2 > id1);
    }

    #[test]
    fn test_hook_summary_creation() {
        let summary = HookSummary {
            total_hooks: 5,
            by_type: std::collections::HashMap::new(),
            by_module: std::collections::HashMap::new(),
            active_count: 3,
            disabled_count: 2,
            total_hits: 100,
        };

        assert_eq!(summary.total_hooks, 5);
        assert_eq!(summary.active_count + summary.disabled_count, 5);
    }

    #[test]
    fn test_hook_chain_creation() {
        let chain = HookChain {
            target_address: 0x140001000,
            hooks: vec![HookId(1), HookId(2)],
            original_address: 0x140001000,
        };

        assert_eq!(chain.hooks.len(), 2);
    }

    #[test]
    fn test_rop_gadget_types() {
        assert_ne!(GadgetType::Ret, GadgetType::RetN);
        assert_ne!(GadgetType::JmpReg, GadgetType::CallReg);
    }

    #[test]
    fn test_shellcode_arch_variants() {
        assert_ne!(ShellcodeArch::X86, ShellcodeArch::X64);
    }

    #[test]
    fn test_manager_hook_listing_empty() {
        let manager = ExtendedHookManager::new();
        let hooks = manager.list_hooks(None);
        assert!(hooks.is_empty());
    }

    #[test]
    fn test_manager_get_summary_empty() {
        let manager = ExtendedHookManager::new();
        let summary = manager.get_summary();
        assert_eq!(summary.total_hooks, 0);
        assert_eq!(summary.active_count, 0);
        assert_eq!(summary.disabled_count, 0);
    }

    #[test]
    fn test_hook_info_creation() {
        let info = HookInfo {
            id: HookId(1),
            hook_type: ExtendedHookType::InlineTrampoline,
            target_address: 0x140001000,
            callback_address: 0x140002000,
            trampoline_address: Some(0x140003000),
            original_bytes: vec![0x48, 0x89, 0x5C, 0x24, 0x08],
            state: HookState::Enabled,
            module_name: Some("test.dll".to_string()),
            function_name: Some("TestFunc".to_string()),
            hit_count: 0,
            installed_at: 1234567890,
            chain_index: 0,
        };

        assert_eq!(info.id.0, 1);
        assert_eq!(info.original_bytes.len(), 5);
        assert!(info.trampoline_address.is_some());
    }
}
