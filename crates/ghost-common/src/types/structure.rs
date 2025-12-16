//! Structure Analysis Types
//!
//! Types for defining, analyzing, and manipulating memory structures including
//! field definitions, nested structures, arrays, pointers, bitfields, and enums.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Unique identifier for a structure definition
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StructureId(pub u32);

impl std::fmt::Display for StructureId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "struct_{}", self.0)
    }
}

/// Unique identifier for an enum definition
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnumId(pub u32);

impl std::fmt::Display for EnumId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "enum_{}", self.0)
    }
}

// ============================================================================
// Field Types
// ============================================================================

/// Primitive data types for structure fields
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrimitiveType {
    /// Signed 8-bit integer
    I8,
    /// Unsigned 8-bit integer
    U8,
    /// Signed 16-bit integer
    I16,
    /// Unsigned 16-bit integer
    U16,
    /// Signed 32-bit integer
    I32,
    /// Unsigned 32-bit integer
    U32,
    /// Signed 64-bit integer
    I64,
    /// Unsigned 64-bit integer
    U64,
    /// 32-bit floating point
    F32,
    /// 64-bit floating point
    F64,
    /// Boolean (1 byte)
    Bool,
    /// Single character (1 byte)
    Char,
    /// Wide character (2 bytes)
    WChar,
    /// Pointer (4 or 8 bytes depending on arch)
    Pointer,
    /// Void (for pointer types)
    Void,
}

impl PrimitiveType {
    /// Get the size in bytes for this primitive type
    pub fn size(&self, is_64bit: bool) -> usize {
        match self {
            PrimitiveType::I8 | PrimitiveType::U8 | PrimitiveType::Bool | PrimitiveType::Char => 1,
            PrimitiveType::I16 | PrimitiveType::U16 | PrimitiveType::WChar => 2,
            PrimitiveType::I32 | PrimitiveType::U32 | PrimitiveType::F32 => 4,
            PrimitiveType::I64 | PrimitiveType::U64 | PrimitiveType::F64 => 8,
            PrimitiveType::Pointer | PrimitiveType::Void => {
                if is_64bit {
                    8
                } else {
                    4
                }
            }
        }
    }
}

/// Field type definition
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    /// Primitive type
    Primitive(PrimitiveType),
    /// Fixed-size array of another type
    Array {
        element_type: Box<FieldType>,
        count: usize,
    },
    /// Dynamic array (pointer + count from another field)
    DynamicArray {
        element_type: Box<FieldType>,
        count_field: String,
    },
    /// Pointer to another type (with optional auto-dereference)
    Pointer {
        pointee_type: Box<FieldType>,
        auto_deref: bool,
    },
    /// Nested structure (by ID)
    Struct(StructureId),
    /// Nested structure (inline definition)
    InlineStruct(Box<StructureDefinition>),
    /// Enum type (by ID)
    Enum(EnumId),
    /// Bitfield within integer
    Bitfield {
        base_type: PrimitiveType,
        bits: Vec<BitfieldBit>,
    },
    /// Fixed-size string (ASCII)
    FixedString(usize),
    /// Fixed-size wide string (Unicode)
    FixedWString(usize),
    /// Null-terminated string pointer
    StringPointer,
    /// Null-terminated wide string pointer
    WStringPointer,
    /// Raw bytes (unknown type)
    Bytes(usize),
    /// Padding bytes
    Padding(usize),
}

impl FieldType {
    /// Calculate the size of this field type
    pub fn size(
        &self,
        is_64bit: bool,
        structs: &HashMap<StructureId, StructureDefinition>,
    ) -> usize {
        match self {
            FieldType::Primitive(p) => p.size(is_64bit),
            FieldType::Array {
                element_type,
                count,
            } => element_type.size(is_64bit, structs) * count,
            FieldType::DynamicArray { .. } => {
                if is_64bit {
                    8
                } else {
                    4
                }
            } // Just the pointer
            FieldType::Pointer { .. } => {
                if is_64bit {
                    8
                } else {
                    4
                }
            }
            FieldType::Struct(id) => structs.get(id).map(|s| s.total_size).unwrap_or(0),
            FieldType::InlineStruct(s) => s.total_size,
            FieldType::Enum(_id) => 4, // Default enum size
            FieldType::Bitfield { base_type, .. } => base_type.size(is_64bit),
            FieldType::FixedString(len) => *len,
            FieldType::FixedWString(len) => len * 2,
            FieldType::StringPointer | FieldType::WStringPointer => {
                if is_64bit {
                    8
                } else {
                    4
                }
            }
            FieldType::Bytes(len) | FieldType::Padding(len) => *len,
        }
    }
}

/// A single bit or bit range in a bitfield
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitfieldBit {
    /// Name of the bit/flag
    pub name: String,
    /// Starting bit position (0-indexed from LSB)
    pub start_bit: u8,
    /// Number of bits (1 for single flag)
    pub bit_count: u8,
    /// Optional description
    pub description: Option<String>,
}

// ============================================================================
// Structure Definition
// ============================================================================

/// A field within a structure
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StructureField {
    /// Field name
    pub name: String,
    /// Field type
    pub field_type: FieldType,
    /// Offset from structure base
    pub offset: usize,
    /// Optional description/comment
    pub description: Option<String>,
    /// Whether this field was auto-detected
    pub auto_detected: bool,
    /// Confidence score for auto-detected fields (0.0 - 1.0)
    pub confidence: Option<f32>,
}

impl StructureField {
    /// Get the size of this field
    pub fn size(
        &self,
        is_64bit: bool,
        structs: &HashMap<StructureId, StructureDefinition>,
    ) -> usize {
        self.field_type.size(is_64bit, structs)
    }
}

/// Complete structure definition
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StructureDefinition {
    /// Unique identifier
    pub id: StructureId,
    /// Structure name
    pub name: String,
    /// Fields in order of offset
    pub fields: Vec<StructureField>,
    /// Total size of the structure
    pub total_size: usize,
    /// Alignment requirement
    pub alignment: usize,
    /// Optional description
    pub description: Option<String>,
    /// Whether this is for 64-bit architecture
    pub is_64bit: bool,
    /// Source (user-defined, imported, auto-detected)
    pub source: StructureSource,
    /// Tags for organization
    pub tags: Vec<String>,
    /// Creation timestamp
    pub created_at: u64,
    /// Last modified timestamp
    pub modified_at: u64,
}

/// Source of structure definition
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructureSource {
    /// User-defined
    UserDefined,
    /// Imported from header file
    Imported { filename: String },
    /// Auto-detected by heuristics
    AutoDetected,
    /// From debug symbols
    DebugSymbols,
}

// ============================================================================
// Enum Definition
// ============================================================================

/// An enum member
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumMember {
    /// Member name
    pub name: String,
    /// Value
    pub value: i64,
    /// Optional description
    pub description: Option<String>,
}

/// Complete enum definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumDefinition {
    /// Unique identifier
    pub id: EnumId,
    /// Enum name
    pub name: String,
    /// Underlying type size in bytes
    pub underlying_size: usize,
    /// Whether values are signed
    pub is_signed: bool,
    /// Enum members
    pub members: Vec<EnumMember>,
    /// Optional description
    pub description: Option<String>,
    /// Is this a flags enum (bitwise combinable)
    pub is_flags: bool,
}

// ============================================================================
// Structure Operations
// ============================================================================

/// Request to create a structure definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateStructureRequest {
    /// Structure name
    pub name: String,
    /// Fields to add
    pub fields: Vec<StructureFieldInput>,
    /// Whether this is for 64-bit
    pub is_64bit: bool,
    /// Optional description
    pub description: Option<String>,
    /// Tags for organization
    pub tags: Vec<String>,
}

/// Input for adding a field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructureFieldInput {
    /// Field name
    pub name: String,
    /// Field type (as string for parsing)
    pub field_type: String,
    /// Offset (None = auto-calculate)
    pub offset: Option<usize>,
    /// Description
    pub description: Option<String>,
}

/// Request to read structure data from memory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadStructureRequest {
    /// Structure ID to read
    pub structure_id: StructureId,
    /// Base address in memory
    pub address: u64,
    /// Depth for pointer dereferencing (0 = no deref)
    pub deref_depth: u32,
    /// Maximum string length to read
    pub max_string_length: usize,
}

/// A read field value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldValue {
    /// Field name
    pub name: String,
    /// Field offset
    pub offset: usize,
    /// Raw bytes
    pub raw_bytes: Vec<u8>,
    /// Interpreted value (as string for display)
    pub display_value: String,
    /// Numeric value (if applicable)
    pub numeric_value: Option<i64>,
    /// Floating point value (if applicable)
    pub float_value: Option<f64>,
    /// String value (if applicable)
    pub string_value: Option<String>,
    /// Pointer value and dereferenced data (if applicable)
    pub pointer_data: Option<PointerFieldData>,
    /// Array values (if applicable)
    pub array_values: Option<Vec<FieldValue>>,
    /// Nested structure (if applicable)
    pub nested_struct: Option<Box<StructureData>>,
    /// Bitfield values (if applicable)
    pub bitfield_values: Option<Vec<BitfieldValue>>,
    /// Enum member name (if applicable)
    pub enum_name: Option<String>,
}

/// Data for a pointer field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointerFieldData {
    /// The pointer value
    pub pointer_value: u64,
    /// Whether the pointer is valid
    pub is_valid: bool,
    /// Dereferenced data (if auto_deref and valid)
    pub dereferenced: Option<Box<FieldValue>>,
}

/// Value of a bitfield bit/range
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitfieldValue {
    /// Bit name
    pub name: String,
    /// Raw value
    pub value: u64,
    /// Is this flag set (for single bits)
    pub is_set: bool,
}

/// Complete structure data read from memory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructureData {
    /// Structure definition used
    pub structure_id: StructureId,
    /// Structure name
    pub structure_name: String,
    /// Base address read from
    pub address: u64,
    /// Total bytes read
    pub total_size: usize,
    /// Field values
    pub fields: Vec<FieldValue>,
    /// Raw bytes of entire structure
    pub raw_bytes: Vec<u8>,
}

/// Request to edit a field value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditFieldRequest {
    /// Base address of structure
    pub address: u64,
    /// Structure ID
    pub structure_id: StructureId,
    /// Field name to edit
    pub field_name: String,
    /// New value (as string, will be parsed)
    pub new_value: String,
}

/// Result of editing a field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditFieldResult {
    /// Whether edit succeeded
    pub success: bool,
    /// Previous value
    pub previous_value: Option<FieldValue>,
    /// New value
    pub new_value: Option<FieldValue>,
    /// Error message if failed
    pub error: Option<String>,
}

// ============================================================================
// Code Export
// ============================================================================

/// Target language for code export
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportLanguage {
    /// C header format
    C,
    /// Rust struct format
    Rust,
    /// C# struct format
    CSharp,
    /// Python ctypes format
    Python,
}

/// Request to export structure as code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportStructureRequest {
    /// Structure ID to export
    pub structure_id: StructureId,
    /// Target language
    pub language: ExportLanguage,
    /// Include field comments
    pub include_comments: bool,
    /// Include offset annotations
    pub include_offsets: bool,
    /// Pack attribute value (None = default)
    pub pack: Option<usize>,
}

/// Result of structure export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportStructureResult {
    /// Whether export succeeded
    pub success: bool,
    /// Generated code
    pub code: String,
    /// Language used
    pub language: ExportLanguage,
    /// Any warnings during export
    pub warnings: Vec<String>,
    /// Error message if failed
    pub error: Option<String>,
}

// ============================================================================
// Auto-Analysis (Heuristics)
// ============================================================================

/// Request to auto-analyze memory as a structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoAnalyzeRequest {
    /// Base address to analyze
    pub address: u64,
    /// Size to analyze
    pub size: usize,
    /// Minimum confidence threshold (0.0 - 1.0)
    pub min_confidence: f32,
    /// Enable pointer detection
    pub detect_pointers: bool,
    /// Enable string detection
    pub detect_strings: bool,
    /// Enable vtable detection
    pub detect_vtables: bool,
    /// Enable array detection
    pub detect_arrays: bool,
    /// Whether architecture is 64-bit
    pub is_64bit: bool,
}

/// A suggested field from auto-analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuggestedField {
    /// Suggested field name
    pub name: String,
    /// Detected type
    pub field_type: FieldType,
    /// Offset
    pub offset: usize,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Reason for detection
    pub reason: String,
    /// Sample value at this offset
    pub sample_value: String,
}

/// Result of auto-analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoAnalyzeResult {
    /// Whether analysis succeeded
    pub success: bool,
    /// Base address analyzed
    pub address: u64,
    /// Size analyzed
    pub size: usize,
    /// Suggested fields
    pub suggested_fields: Vec<SuggestedField>,
    /// Detected patterns
    pub patterns: Vec<DetectedPattern>,
    /// Suggested structure (if confident enough)
    pub suggested_structure: Option<StructureDefinition>,
    /// Error message if failed
    pub error: Option<String>,
}

/// A detected pattern in auto-analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedPattern {
    /// Pattern type
    pub pattern_type: StructurePatternType,
    /// Offset where detected
    pub offset: usize,
    /// Size of pattern
    pub size: usize,
    /// Confidence
    pub confidence: f32,
    /// Description
    pub description: String,
}

/// Types of patterns detected during auto-analysis
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructurePatternType {
    /// Pointer to valid memory
    ValidPointer,
    /// VTable pointer
    VTablePointer,
    /// ASCII string
    AsciiString,
    /// Unicode string
    UnicodeString,
    /// Floating point value
    FloatValue,
    /// Counter/size value
    CounterValue,
    /// Array of values
    Array,
    /// Null/zero padding
    Padding,
    /// Unknown data
    Unknown,
}

// ============================================================================
// Persistence
// ============================================================================

/// Request to save structure definitions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveStructuresRequest {
    /// Structure IDs to save (empty = all)
    pub structure_ids: Vec<StructureId>,
    /// Enum IDs to save (empty = all)
    pub enum_ids: Vec<EnumId>,
    /// Output filename
    pub filename: String,
    /// Include auto-detected structures
    pub include_auto_detected: bool,
}

/// Request to load structure definitions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadStructuresRequest {
    /// Input filename
    pub filename: String,
    /// Merge with existing (true) or replace (false)
    pub merge: bool,
}

/// Result of save/load operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructurePersistResult {
    /// Whether operation succeeded
    pub success: bool,
    /// Number of structures affected
    pub structure_count: usize,
    /// Number of enums affected
    pub enum_count: usize,
    /// Filename used
    pub filename: String,
    /// Error message if failed
    pub error: Option<String>,
}

/// Serialized structure database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructureDatabase {
    /// Version for compatibility
    pub version: u32,
    /// Structure definitions
    pub structures: Vec<StructureDefinition>,
    /// Enum definitions
    pub enums: Vec<EnumDefinition>,
    /// Metadata
    pub metadata: StructureDatabaseMetadata,
}

/// Metadata for structure database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructureDatabaseMetadata {
    /// Creation timestamp
    pub created_at: u64,
    /// Last modified timestamp
    pub modified_at: u64,
    /// Target architecture
    pub is_64bit: bool,
    /// Application/target name
    pub target_name: Option<String>,
    /// Notes
    pub notes: Option<String>,
}

// ============================================================================
// Structure Manager Result Types
// ============================================================================

/// Result of structure operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructureResult {
    /// Whether operation succeeded
    pub success: bool,
    /// Structure info (if applicable)
    pub structure: Option<StructureDefinition>,
    /// Error message if failed
    pub error: Option<String>,
}

/// List of structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructureListResult {
    /// Whether operation succeeded
    pub success: bool,
    /// Structures found
    pub structures: Vec<StructureDefinition>,
    /// Enums found
    pub enums: Vec<EnumDefinition>,
    /// Total count
    pub total_count: usize,
    /// Error message if failed
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_primitive_sizes_32bit() {
        assert_eq!(PrimitiveType::I8.size(false), 1);
        assert_eq!(PrimitiveType::U16.size(false), 2);
        assert_eq!(PrimitiveType::I32.size(false), 4);
        assert_eq!(PrimitiveType::F64.size(false), 8);
        assert_eq!(PrimitiveType::Pointer.size(false), 4);
    }

    #[test]
    fn test_primitive_sizes_64bit() {
        assert_eq!(PrimitiveType::Pointer.size(true), 8);
        assert_eq!(PrimitiveType::I32.size(true), 4);
    }

    #[test]
    fn test_structure_id_display() {
        let id = StructureId(42);
        assert_eq!(format!("{}", id), "struct_42");
    }

    #[test]
    fn test_enum_id_display() {
        let id = EnumId(7);
        assert_eq!(format!("{}", id), "enum_7");
    }

    #[test]
    fn test_field_type_size() {
        let structs = HashMap::new();
        let arr = FieldType::Array {
            element_type: Box::new(FieldType::Primitive(PrimitiveType::I32)),
            count: 10,
        };
        assert_eq!(arr.size(false, &structs), 40);
    }
}
