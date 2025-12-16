//! PE reconstruction types

use serde::{Deserialize, Serialize};

/// Options for PE reconstruction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeReconstructOptions {
    /// Fix section alignment
    pub fix_alignment: bool,
    /// Rebuild import table
    pub rebuild_imports: bool,
    /// Rebuild relocation table
    pub rebuild_relocations: bool,
    /// Fix PE checksum
    pub fix_checksum: bool,
    /// Remove overlay data
    pub remove_overlay: bool,
    /// Unmap sections (convert RVA to file offsets)
    pub unmap_sections: bool,
    /// Output file path
    pub output_path: Option<String>,
}

impl Default for PeReconstructOptions {
    fn default() -> Self {
        Self {
            fix_alignment: true,
            rebuild_imports: true,
            rebuild_relocations: false,
            fix_checksum: true,
            remove_overlay: false,
            unmap_sections: true,
            output_path: None,
        }
    }
}

/// Import entry for reconstruction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructedImport {
    /// DLL name
    pub dll_name: String,
    /// Function name (or ordinal as string)
    pub function_name: String,
    /// Import Address Table (IAT) entry address
    pub iat_address: usize,
    /// Resolved address of the function
    pub resolved_address: usize,
    /// Whether this import was successfully resolved
    pub resolved: bool,
}

/// PE section information for reconstruction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructedSection {
    /// Section name
    pub name: String,
    /// Virtual address (RVA)
    pub virtual_address: u32,
    /// Virtual size
    pub virtual_size: u32,
    /// Raw data offset in file
    pub raw_offset: u32,
    /// Raw data size
    pub raw_size: u32,
    /// Section characteristics
    pub characteristics: u32,
}

/// Result of PE reconstruction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeReconstructResult {
    /// Whether reconstruction succeeded
    pub success: bool,
    /// Original module base address
    pub original_base: usize,
    /// Reconstructed PE size
    pub reconstructed_size: usize,
    /// Sections in the reconstructed PE
    pub sections: Vec<ReconstructedSection>,
    /// Resolved imports
    pub imports: Vec<ReconstructedImport>,
    /// Number of successfully resolved imports
    pub imports_resolved: u32,
    /// Number of failed import resolutions
    pub imports_failed: u32,
    /// Output file path (if saved)
    pub output_path: Option<String>,
    /// Reconstructed PE data (if not saved to file)
    pub data: Option<Vec<u8>>,
    /// Error message if failed
    pub error: Option<String>,
    /// Warnings during reconstruction
    pub warnings: Vec<String>,
}
