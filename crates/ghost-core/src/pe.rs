//! PE parsing utilities for exports and imports extraction

use ghost_common::{Export, Import, Result};

/// Parse PE exports from module memory
pub fn parse_exports(base: usize) -> Result<Vec<Export>> {
    let mut exports = Vec::new();

    unsafe {
        let dos_header = base as *const DosHeader;
        if (*dos_header).e_magic != 0x5A4D {
            return Ok(exports); // Not a valid PE
        }

        let nt_headers = (base + (*dos_header).e_lfanew as usize) as *const NtHeaders64;
        if (*nt_headers).signature != 0x00004550 {
            return Ok(exports); // Invalid PE signature
        }

        // Get export directory
        let export_dir_entry = (*nt_headers).optional_header.data_directory[0];
        let export_dir_rva = export_dir_entry.virtual_address;
        let export_dir_size = export_dir_entry.size;
        if export_dir_rva == 0 {
            return Ok(exports); // No exports
        }

        let export_dir = (base + export_dir_rva as usize) as *const ExportDirectory;
        let num_functions = (*export_dir).number_of_functions;
        let num_names = (*export_dir).number_of_names;

        if num_names == 0 || num_functions == 0 {
            return Ok(exports);
        }

        let functions = (base + (*export_dir).address_of_functions as usize) as *const u32;
        let names = (base + (*export_dir).address_of_names as usize) as *const u32;
        let ordinals = (base + (*export_dir).address_of_name_ordinals as usize) as *const u16;

        // Export directory range for detecting forwarded exports
        let export_dir_start = export_dir_rva;
        let export_dir_end = export_dir_rva + export_dir_size;

        // Build export list from named exports
        for i in 0..num_names as usize {
            let name_rva = *names.add(i);
            let ordinal_index = *ordinals.add(i) as usize;

            if ordinal_index >= num_functions as usize {
                continue;
            }

            let func_rva = *functions.add(ordinal_index);
            let name_ptr = (base + name_rva as usize) as *const i8;

            let name = std::ffi::CStr::from_ptr(name_ptr)
                .to_string_lossy()
                .to_string();

            // Check if this is a forwarded export (RVA points within export directory)
            let address = if func_rva >= export_dir_start && func_rva < export_dir_end {
                // Forwarded export - for now, we still include it but with the forwarding address
                // The address points to a string like "NTDLL.RtlAllocateHeap"
                // We return 0 to indicate it's forwarded (caller can resolve via the target DLL)
                0
            } else {
                base + func_rva as usize
            };

            exports.push(Export {
                name,
                address,
                ordinal: ((*export_dir).base + ordinal_index as u32) as u16,
            });
        }
    }

    Ok(exports)
}

/// Parse PE imports from module memory
pub fn parse_imports(base: usize) -> Result<Vec<Import>> {
    let mut imports = Vec::new();

    unsafe {
        let dos_header = base as *const DosHeader;
        if (*dos_header).e_magic != 0x5A4D {
            return Ok(imports);
        }

        let nt_headers = (base + (*dos_header).e_lfanew as usize) as *const NtHeaders64;
        if (*nt_headers).signature != 0x00004550 {
            return Ok(imports);
        }

        // Get import directory
        let import_dir_rva = (*nt_headers).optional_header.data_directory[1].virtual_address;
        if import_dir_rva == 0 {
            return Ok(imports);
        }

        let mut import_desc = (base + import_dir_rva as usize) as *const ImportDescriptor;

        // Iterate through import descriptors
        while (*import_desc).name != 0 {
            let dll_name_ptr = (base + (*import_desc).name as usize) as *const i8;
            let dll_name = std::ffi::CStr::from_ptr(dll_name_ptr)
                .to_string_lossy()
                .to_string();

            // Get the IAT (Import Address Table)
            let mut thunk = if (*import_desc).original_first_thunk != 0 {
                (base + (*import_desc).original_first_thunk as usize) as *const u64
            } else {
                (base + (*import_desc).first_thunk as usize) as *const u64
            };

            let mut iat = (base + (*import_desc).first_thunk as usize) as *const u64;

            while *thunk != 0 {
                let thunk_data = *thunk;

                // Check if import by ordinal (high bit set)
                if thunk_data & 0x8000000000000000 != 0 {
                    let ordinal = (thunk_data & 0xFFFF) as u16;
                    imports.push(Import {
                        name: format!("Ordinal#{}", ordinal),
                        module: dll_name.clone(),
                        address: iat as usize,
                    });
                } else {
                    // Import by name
                    let hint_name = (base + thunk_data as usize) as *const ImportByName;
                    let func_name_ptr = (*hint_name).name.as_ptr() as *const i8;
                    let func_name = std::ffi::CStr::from_ptr(func_name_ptr)
                        .to_string_lossy()
                        .to_string();

                    imports.push(Import {
                        name: func_name,
                        module: dll_name.clone(),
                        address: iat as usize,
                    });
                }

                thunk = thunk.add(1);
                iat = iat.add(1);
            }

            import_desc = import_desc.add(1);
        }
    }

    Ok(imports)
}

// PE structures
#[repr(C)]
struct DosHeader {
    e_magic: u16,
    _padding: [u8; 58],
    e_lfanew: i32,
}

#[repr(C)]
struct NtHeaders64 {
    signature: u32,
    file_header: FileHeader,
    optional_header: OptionalHeader64,
}

#[repr(C)]
struct FileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C)]
struct OptionalHeader64 {
    magic: u16,                          // Offset 0
    major_linker_version: u8,            // Offset 2
    minor_linker_version: u8,            // Offset 3
    size_of_code: u32,                   // Offset 4
    size_of_initialized_data: u32,       // Offset 8
    size_of_uninitialized_data: u32,     // Offset 12
    address_of_entry_point: u32,         // Offset 16
    base_of_code: u32,                   // Offset 20
    image_base: u64,                     // Offset 24
    section_alignment: u32,              // Offset 32
    file_alignment: u32,                 // Offset 36
    major_os_version: u16,               // Offset 40
    minor_os_version: u16,               // Offset 42
    major_image_version: u16,            // Offset 44
    minor_image_version: u16,            // Offset 46
    major_subsystem_version: u16,        // Offset 48
    minor_subsystem_version: u16,        // Offset 50
    win32_version_value: u32,            // Offset 52
    size_of_image: u32,                  // Offset 56
    size_of_headers: u32,                // Offset 60
    check_sum: u32,                      // Offset 64
    subsystem: u16,                      // Offset 68
    dll_characteristics: u16,            // Offset 70
    size_of_stack_reserve: u64,          // Offset 72
    size_of_stack_commit: u64,           // Offset 80
    size_of_heap_reserve: u64,           // Offset 88
    size_of_heap_commit: u64,            // Offset 96
    loader_flags: u32,                   // Offset 104
    number_of_rva_and_sizes: u32,        // Offset 108
    data_directory: [DataDirectory; 16], // Offset 112
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DataDirectory {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
struct ExportDirectory {
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    name: u32,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
}

#[repr(C)]
struct ImportDescriptor {
    original_first_thunk: u32,
    time_date_stamp: u32,
    forwarder_chain: u32,
    name: u32,
    first_thunk: u32,
}

#[repr(C)]
struct ImportByName {
    hint: u16,
    name: [u8; 1], // Variable length
}
