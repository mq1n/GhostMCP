//! Structure Analysis Core
//!
//! Provides structure definition, memory reading, field editing, auto-analysis,
//! code export, and persistence functionality.

use ghost_common::{
    AutoAnalyzeRequest, AutoAnalyzeResult, BitfieldValue, CreateStructureRequest, DetectedPattern,
    EditFieldRequest, EditFieldResult, EnumDefinition, EnumId, EnumMember, ExportLanguage,
    ExportStructureRequest, ExportStructureResult, FieldType, FieldValue, LoadStructuresRequest,
    PointerFieldData, PrimitiveType, ReadStructureRequest, SaveStructuresRequest, StructureData,
    StructureDatabase, StructureDatabaseMetadata, StructureDefinition, StructureField, StructureId,
    StructureListResult, StructurePatternType, StructurePersistResult, StructureResult,
    StructureSource, SuggestedField,
};
use std::collections::HashMap;
use std::fs;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, trace, warn};

/// Maximum structure size to prevent memory issues
const MAX_STRUCTURE_SIZE: usize = 1024 * 1024; // 1MB
/// Maximum number of fields per structure
const MAX_FIELDS_PER_STRUCTURE: usize = 1000;
/// Maximum auto-analyze size
const MAX_AUTO_ANALYZE_SIZE: usize = 64 * 1024; // 64KB

static NEXT_STRUCTURE_ID: AtomicU32 = AtomicU32::new(1);
static NEXT_ENUM_ID: AtomicU32 = AtomicU32::new(1);

/// Structure Analysis Manager
pub struct StructureManager {
    structures: HashMap<StructureId, StructureDefinition>,
    enums: HashMap<EnumId, EnumDefinition>,
    structure_names: HashMap<String, StructureId>,
    enum_names: HashMap<String, EnumId>,
    is_64bit: bool,
}

impl StructureManager {
    pub fn new(is_64bit: bool) -> Self {
        info!("Creating StructureManager (64-bit: {})", is_64bit);
        Self {
            structures: HashMap::new(),
            enums: HashMap::new(),
            structure_names: HashMap::new(),
            enum_names: HashMap::new(),
            is_64bit,
        }
    }

    fn next_structure_id() -> StructureId {
        StructureId(NEXT_STRUCTURE_ID.fetch_add(1, Ordering::SeqCst))
    }

    fn next_enum_id() -> EnumId {
        EnumId(NEXT_ENUM_ID.fetch_add(1, Ordering::SeqCst))
    }

    fn timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Create a new structure definition with validation
    pub fn create_structure(&mut self, request: CreateStructureRequest) -> StructureResult {
        info!(name = %request.name, fields = request.fields.len(), is_64bit = request.is_64bit, "Creating structure");

        // Validate structure name
        let name = request.name.trim();
        if name.is_empty() {
            warn!("Structure creation failed: empty name");
            return StructureResult {
                success: false,
                structure: None,
                error: Some("Structure name cannot be empty".into()),
            };
        }
        if name.len() > 256 {
            warn!(
                name_len = name.len(),
                "Structure creation failed: name too long"
            );
            return StructureResult {
                success: false,
                structure: None,
                error: Some("Structure name too long (max 256 chars)".into()),
            };
        }
        if self.structure_names.contains_key(name) {
            warn!(name = %name, "Structure creation failed: duplicate name");
            return StructureResult {
                success: false,
                structure: None,
                error: Some(format!("Structure '{}' already exists", name)),
            };
        }

        // Validate field count
        if request.fields.len() > MAX_FIELDS_PER_STRUCTURE {
            warn!(
                count = request.fields.len(),
                max = MAX_FIELDS_PER_STRUCTURE,
                "Too many fields"
            );
            return StructureResult {
                success: false,
                structure: None,
                error: Some(format!(
                    "Too many fields (max {})",
                    MAX_FIELDS_PER_STRUCTURE
                )),
            };
        }

        let id = Self::next_structure_id();
        let now = Self::timestamp();
        let mut fields = Vec::with_capacity(request.fields.len());
        let mut current_offset = 0usize;

        for (idx, input) in request.fields.iter().enumerate() {
            // Validate field name
            let field_name = input.name.trim();
            if field_name.is_empty() {
                warn!(index = idx, "Field has empty name");
                return StructureResult {
                    success: false,
                    structure: None,
                    error: Some(format!("Field {} has empty name", idx)),
                };
            }

            let field_type = match self.parse_field_type(&input.field_type) {
                Ok(ft) => ft,
                Err(e) => {
                    warn!(field = %field_name, type_str = %input.field_type, error = %e, "Failed to parse field type");
                    return StructureResult {
                        success: false,
                        structure: None,
                        error: Some(format!(
                            "Failed to parse type '{}' for field '{}': {}",
                            input.field_type, field_name, e
                        )),
                    };
                }
            };

            let offset = input.offset.unwrap_or(current_offset);
            let field_size = field_type.size(request.is_64bit, &self.structures);

            // Bounds check
            if offset
                .checked_add(field_size)
                .map(|s| s > MAX_STRUCTURE_SIZE)
                .unwrap_or(true)
            {
                warn!(field = %field_name, offset, size = field_size, "Field exceeds max structure size");
                return StructureResult {
                    success: false,
                    structure: None,
                    error: Some(format!(
                        "Field '{}' exceeds maximum structure size",
                        field_name
                    )),
                };
            }

            fields.push(StructureField {
                name: field_name.to_string(),
                field_type,
                offset,
                description: input.description.clone(),
                auto_detected: false,
                confidence: None,
            });
            current_offset = offset.saturating_add(field_size);
            trace!(field = %field_name, offset, size = field_size, "Added field");
        }

        fields.sort_by_key(|f| f.offset);
        let total_size = fields
            .last()
            .map(|f| {
                f.offset
                    .saturating_add(f.field_type.size(request.is_64bit, &self.structures))
            })
            .unwrap_or(0);

        let structure = StructureDefinition {
            id,
            name: name.to_string(),
            fields,
            total_size,
            alignment: if request.is_64bit { 8 } else { 4 },
            description: request.description,
            is_64bit: request.is_64bit,
            source: StructureSource::UserDefined,
            tags: request.tags,
            created_at: now,
            modified_at: now,
        };

        self.structure_names.insert(name.to_string(), id);
        self.structures.insert(id, structure.clone());
        info!(id = %id, name = %name, fields = structure.fields.len(), size = total_size, "Structure created successfully");
        StructureResult {
            success: true,
            structure: Some(structure),
            error: None,
        }
    }

    fn parse_field_type(&self, type_str: &str) -> Result<FieldType, String> {
        let type_str = type_str.trim();
        if let Some(inner) = type_str.strip_suffix('*') {
            let inner = inner.trim();
            let pointee = if inner.is_empty() || inner == "void" {
                Box::new(FieldType::Primitive(PrimitiveType::Void))
            } else {
                Box::new(self.parse_field_type(inner)?)
            };
            return Ok(FieldType::Pointer {
                pointee_type: pointee,
                auto_deref: false,
            });
        }
        // Check for bytes[N] and padding[N] before general array parsing
        if type_str.starts_with("bytes[") && type_str.ends_with(']') {
            let size: usize = type_str[6..type_str.len() - 1]
                .parse()
                .map_err(|_| "Invalid size")?;
            return Ok(FieldType::Bytes(size));
        }
        if type_str.starts_with("padding[") && type_str.ends_with(']') {
            let size: usize = type_str[8..type_str.len() - 1]
                .parse()
                .map_err(|_| "Invalid size")?;
            return Ok(FieldType::Padding(size));
        }
        if type_str.ends_with(']') {
            if let Some(bracket_pos) = type_str.rfind('[') {
                let inner = type_str[..bracket_pos].trim();
                let count: usize = type_str[bracket_pos + 1..type_str.len() - 1]
                    .parse()
                    .map_err(|_| "Invalid array count")?;
                return Ok(FieldType::Array {
                    element_type: Box::new(self.parse_field_type(inner)?),
                    count,
                });
            }
        }
        match type_str.to_lowercase().as_str() {
            "i8" | "int8" | "char" => Ok(FieldType::Primitive(PrimitiveType::I8)),
            "u8" | "uint8" | "byte" => Ok(FieldType::Primitive(PrimitiveType::U8)),
            "i16" | "int16" | "short" => Ok(FieldType::Primitive(PrimitiveType::I16)),
            "u16" | "uint16" | "word" => Ok(FieldType::Primitive(PrimitiveType::U16)),
            "i32" | "int32" | "int" | "dword" => Ok(FieldType::Primitive(PrimitiveType::I32)),
            "u32" | "uint32" | "uint" => Ok(FieldType::Primitive(PrimitiveType::U32)),
            "i64" | "int64" | "qword" => Ok(FieldType::Primitive(PrimitiveType::I64)),
            "u64" | "uint64" => Ok(FieldType::Primitive(PrimitiveType::U64)),
            "f32" | "float" => Ok(FieldType::Primitive(PrimitiveType::F32)),
            "f64" | "double" => Ok(FieldType::Primitive(PrimitiveType::F64)),
            "bool" => Ok(FieldType::Primitive(PrimitiveType::Bool)),
            "ptr" | "pointer" => Ok(FieldType::Primitive(PrimitiveType::Pointer)),
            "string" => Ok(FieldType::StringPointer),
            "wstring" => Ok(FieldType::WStringPointer),
            _ => self
                .structure_names
                .get(type_str)
                .map(|&id| FieldType::Struct(id))
                .ok_or_else(|| format!("Unknown type: {}", type_str)),
        }
    }

    pub fn get_structure(&self, id: StructureId) -> Option<&StructureDefinition> {
        self.structures.get(&id)
    }
    pub fn get_structure_by_name(&self, name: &str) -> Option<&StructureDefinition> {
        self.structure_names
            .get(name)
            .and_then(|id| self.structures.get(id))
    }

    pub fn delete_structure(&mut self, id: StructureId) -> StructureResult {
        if let Some(s) = self.structures.remove(&id) {
            self.structure_names.remove(&s.name);
            StructureResult {
                success: true,
                structure: Some(s),
                error: None,
            }
        } else {
            StructureResult {
                success: false,
                structure: None,
                error: Some(format!("Structure {} not found", id)),
            }
        }
    }

    pub fn list_structures(&self) -> StructureListResult {
        StructureListResult {
            success: true,
            structures: self.structures.values().cloned().collect(),
            enums: self.enums.values().cloned().collect(),
            total_count: self.structures.len() + self.enums.len(),
            error: None,
        }
    }

    pub fn create_enum(
        &mut self,
        name: String,
        underlying_size: usize,
        is_signed: bool,
        members: Vec<(String, i64, Option<String>)>,
        description: Option<String>,
        is_flags: bool,
    ) -> Result<EnumDefinition, String> {
        if self.enum_names.contains_key(&name) {
            return Err(format!("Enum '{}' exists", name));
        }
        let id = Self::next_enum_id();
        let enum_def = EnumDefinition {
            id,
            name: name.clone(),
            underlying_size,
            is_signed,
            is_flags,
            description,
            members: members
                .into_iter()
                .map(|(n, v, d)| EnumMember {
                    name: n,
                    value: v,
                    description: d,
                })
                .collect(),
        };
        self.enum_names.insert(name, id);
        self.enums.insert(id, enum_def.clone());
        Ok(enum_def)
    }

    /// Read structure data from memory with validation
    pub fn read_structure(
        &self,
        request: ReadStructureRequest,
        read_memory: impl Fn(u64, usize) -> Result<Vec<u8>, String>,
    ) -> Result<StructureData, String> {
        debug!(structure_id = %request.structure_id, address = %format!("{:#x}", request.address), "Reading structure from memory");

        let structure = self.structures.get(&request.structure_id).ok_or_else(|| {
            warn!(structure_id = %request.structure_id, "Structure not found");
            format!("Structure {} not found", request.structure_id)
        })?;

        // Validate read size
        if structure.total_size == 0 {
            warn!(structure_id = %request.structure_id, "Structure has zero size");
            return Err("Structure has zero size".into());
        }
        if structure.total_size > MAX_STRUCTURE_SIZE {
            warn!(
                size = structure.total_size,
                max = MAX_STRUCTURE_SIZE,
                "Structure too large to read"
            );
            return Err(format!(
                "Structure too large: {} bytes (max {})",
                structure.total_size, MAX_STRUCTURE_SIZE
            ));
        }

        let raw_bytes = read_memory(request.address, structure.total_size).map_err(|e| {
            error!(address = %format!("{:#x}", request.address), size = structure.total_size, error = %e, "Failed to read memory");
            e
        })?;

        let max_str_len = request.max_string_length.min(4096); // Cap string length
        let mut fields = Vec::with_capacity(structure.fields.len());
        for field in &structure.fields {
            match self.read_field_value(field, &raw_bytes, max_str_len, &read_memory) {
                Ok(fv) => fields.push(fv),
                Err(e) => {
                    warn!(field = %field.name, error = %e, "Failed to read field, using placeholder");
                    // Continue with other fields instead of failing entirely
                    fields.push(FieldValue {
                        name: field.name.clone(),
                        offset: field.offset,
                        raw_bytes: vec![],
                        display_value: format!("<error: {}>", e),
                        numeric_value: None,
                        float_value: None,
                        string_value: None,
                        pointer_data: None,
                        array_values: None,
                        nested_struct: None,
                        bitfield_values: None,
                        enum_name: None,
                    });
                }
            }
        }

        debug!(structure = %structure.name, fields_read = fields.len(), "Structure read complete");
        Ok(StructureData {
            structure_id: request.structure_id,
            structure_name: structure.name.clone(),
            address: request.address,
            total_size: structure.total_size,
            fields,
            raw_bytes,
        })
    }

    fn read_field_value(
        &self,
        field: &StructureField,
        bytes: &[u8],
        max_str_len: usize,
        read_mem: &impl Fn(u64, usize) -> Result<Vec<u8>, String>,
    ) -> Result<FieldValue, String> {
        let size = field.field_type.size(self.is_64bit, &self.structures);
        let end = field.offset + size;
        if end > bytes.len() {
            return Err(format!("Field {} out of bounds", field.name));
        }
        let raw = bytes[field.offset..end].to_vec();
        let (display, num, flt, str_val) =
            self.interpret_value(&field.field_type, &raw, max_str_len, read_mem)?;
        let ptr_data = self.read_pointer_data(&field.field_type, &raw, read_mem)?;
        let bits = self.read_bitfield_values(&field.field_type, &raw);
        let enum_name = self.resolve_enum_name(&field.field_type, num);
        Ok(FieldValue {
            name: field.name.clone(),
            offset: field.offset,
            raw_bytes: raw,
            display_value: display,
            numeric_value: num,
            float_value: flt,
            string_value: str_val,
            pointer_data: ptr_data,
            array_values: None,
            nested_struct: None,
            bitfield_values: bits,
            enum_name,
        })
    }

    #[allow(clippy::type_complexity)]
    fn interpret_value(
        &self,
        ft: &FieldType,
        bytes: &[u8],
        max_str: usize,
        read_mem: &impl Fn(u64, usize) -> Result<Vec<u8>, String>,
    ) -> Result<(String, Option<i64>, Option<f64>, Option<String>), String> {
        match ft {
            FieldType::Primitive(p) => self.interpret_primitive(p, bytes),
            FieldType::Pointer { .. } => {
                let p = self.read_ptr(bytes);
                Ok((format!("{:#x}", p), Some(p as i64), None, None))
            }
            FieldType::StringPointer => {
                let p = self.read_ptr(bytes);
                if p != 0 {
                    if let Ok(b) = read_mem(p, max_str) {
                        let s = read_cstring(&b);
                        return Ok((
                            format!("{:#x} -> \"{}\"", p, s),
                            Some(p as i64),
                            None,
                            Some(s),
                        ));
                    }
                }
                Ok((format!("{:#x}", p), Some(p as i64), None, None))
            }
            FieldType::FixedString(len) => {
                let s = read_cstring(&bytes[..(*len).min(bytes.len())]);
                Ok((format!("\"{}\"", s), None, None, Some(s)))
            }
            FieldType::Bytes(len) => {
                Ok((hex_str(&bytes[..(*len).min(bytes.len())]), None, None, None))
            }
            FieldType::Padding(len) => Ok((format!("<padding: {} bytes>", len), None, None, None)),
            _ => Ok((hex_str(bytes), None, None, None)),
        }
    }

    #[allow(clippy::type_complexity)]
    fn interpret_primitive(
        &self,
        p: &PrimitiveType,
        b: &[u8],
    ) -> Result<(String, Option<i64>, Option<f64>, Option<String>), String> {
        Ok(match p {
            PrimitiveType::I8 => {
                let v = b.first().map(|x| *x as i8).unwrap_or(0);
                (v.to_string(), Some(v as i64), None, None)
            }
            PrimitiveType::U8 => {
                let v = b.first().copied().unwrap_or(0);
                (v.to_string(), Some(v as i64), None, None)
            }
            PrimitiveType::I16 => {
                let v = i16::from_le_bytes(b[..2].try_into().unwrap_or([0; 2]));
                (v.to_string(), Some(v as i64), None, None)
            }
            PrimitiveType::U16 => {
                let v = u16::from_le_bytes(b[..2].try_into().unwrap_or([0; 2]));
                (v.to_string(), Some(v as i64), None, None)
            }
            PrimitiveType::I32 => {
                let v = i32::from_le_bytes(b[..4].try_into().unwrap_or([0; 4]));
                (v.to_string(), Some(v as i64), None, None)
            }
            PrimitiveType::U32 => {
                let v = u32::from_le_bytes(b[..4].try_into().unwrap_or([0; 4]));
                (v.to_string(), Some(v as i64), None, None)
            }
            PrimitiveType::I64 => {
                let v = i64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8]));
                (v.to_string(), Some(v), None, None)
            }
            PrimitiveType::U64 => {
                let v = u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8]));
                (v.to_string(), Some(v as i64), None, None)
            }
            PrimitiveType::F32 => {
                let v = f32::from_le_bytes(b[..4].try_into().unwrap_or([0; 4]));
                (format!("{:.6}", v), None, Some(v as f64), None)
            }
            PrimitiveType::F64 => {
                let v = f64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8]));
                (format!("{:.6}", v), None, Some(v), None)
            }
            PrimitiveType::Bool => {
                let v = b.first().map(|x| *x != 0).unwrap_or(false);
                (v.to_string(), Some(v as i64), None, None)
            }
            PrimitiveType::Char => {
                let c = b.first().map(|x| *x as char).unwrap_or('\0');
                (
                    format!("'{}'", c.escape_default()),
                    Some(c as i64),
                    None,
                    None,
                )
            }
            PrimitiveType::WChar => {
                let v = u16::from_le_bytes(b[..2].try_into().unwrap_or([0; 2]));
                let c = char::from_u32(v as u32).unwrap_or('\0');
                (
                    format!("'{}'", c.escape_default()),
                    Some(v as i64),
                    None,
                    None,
                )
            }
            PrimitiveType::Pointer | PrimitiveType::Void => {
                let p = self.read_ptr(b);
                (format!("{:#x}", p), Some(p as i64), None, None)
            }
        })
    }

    fn read_ptr(&self, b: &[u8]) -> u64 {
        if self.is_64bit {
            u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8]))
        } else {
            u32::from_le_bytes(b[..4].try_into().unwrap_or([0; 4])) as u64
        }
    }

    fn read_pointer_data(
        &self,
        ft: &FieldType,
        b: &[u8],
        read_mem: &impl Fn(u64, usize) -> Result<Vec<u8>, String>,
    ) -> Result<Option<PointerFieldData>, String> {
        if let FieldType::Pointer { .. } = ft {
            let p = self.read_ptr(b);
            let valid = p != 0 && read_mem(p, 1).is_ok();
            Ok(Some(PointerFieldData {
                pointer_value: p,
                is_valid: valid,
                dereferenced: None,
            }))
        } else {
            Ok(None)
        }
    }

    fn read_bitfield_values(&self, ft: &FieldType, b: &[u8]) -> Option<Vec<BitfieldValue>> {
        if let FieldType::Bitfield { base_type, bits } = ft {
            let raw = match base_type {
                PrimitiveType::U8 => b.first().copied().unwrap_or(0) as u64,
                PrimitiveType::U16 => {
                    u16::from_le_bytes(b[..2].try_into().unwrap_or([0; 2])) as u64
                }
                PrimitiveType::U32 => {
                    u32::from_le_bytes(b[..4].try_into().unwrap_or([0; 4])) as u64
                }
                PrimitiveType::U64 => u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8])),
                _ => return None,
            };
            Some(
                bits.iter()
                    .map(|bit| {
                        let mask = ((1u64 << bit.bit_count) - 1) << bit.start_bit;
                        let v = (raw & mask) >> bit.start_bit;
                        BitfieldValue {
                            name: bit.name.clone(),
                            value: v,
                            is_set: v != 0,
                        }
                    })
                    .collect(),
            )
        } else {
            None
        }
    }

    fn resolve_enum_name(&self, ft: &FieldType, num: Option<i64>) -> Option<String> {
        if let FieldType::Enum(id) = ft {
            if let Some(e) = self.enums.get(id) {
                if let Some(v) = num {
                    return e
                        .members
                        .iter()
                        .find(|m| m.value == v)
                        .map(|m| m.name.clone());
                }
            }
        }
        None
    }

    pub fn edit_field(
        &self,
        req: EditFieldRequest,
        _read_mem: impl Fn(u64, usize) -> Result<Vec<u8>, String>,
        write_mem: impl Fn(u64, &[u8]) -> Result<(), String>,
    ) -> EditFieldResult {
        let s = match self.structures.get(&req.structure_id) {
            Some(s) => s,
            None => {
                return EditFieldResult {
                    success: false,
                    previous_value: None,
                    new_value: None,
                    error: Some("Structure not found".into()),
                }
            }
        };
        let f = match s.fields.iter().find(|f| f.name == req.field_name) {
            Some(f) => f,
            None => {
                return EditFieldResult {
                    success: false,
                    previous_value: None,
                    new_value: None,
                    error: Some("Field not found".into()),
                }
            }
        };
        let addr = req.address + f.offset as u64;
        let new_bytes = match self.parse_value_bytes(&f.field_type, &req.new_value) {
            Ok(b) => b,
            Err(e) => {
                return EditFieldResult {
                    success: false,
                    previous_value: None,
                    new_value: None,
                    error: Some(e),
                }
            }
        };
        if let Err(e) = write_mem(addr, &new_bytes) {
            return EditFieldResult {
                success: false,
                previous_value: None,
                new_value: None,
                error: Some(e),
            };
        }
        EditFieldResult {
            success: true,
            previous_value: None,
            new_value: None,
            error: None,
        }
    }

    fn parse_value_bytes(&self, ft: &FieldType, val: &str) -> Result<Vec<u8>, String> {
        match ft {
            FieldType::Primitive(p) => match p {
                PrimitiveType::I8 => Ok(vec![val.parse::<i8>().map_err(|_| "Invalid i8")? as u8]),
                PrimitiveType::U8 => Ok(vec![parse_u64(val)? as u8]),
                PrimitiveType::I16 => Ok(val
                    .parse::<i16>()
                    .map_err(|_| "Invalid i16")?
                    .to_le_bytes()
                    .to_vec()),
                PrimitiveType::U16 => Ok((parse_u64(val)? as u16).to_le_bytes().to_vec()),
                PrimitiveType::I32 => Ok(val
                    .parse::<i32>()
                    .map_err(|_| "Invalid i32")?
                    .to_le_bytes()
                    .to_vec()),
                PrimitiveType::U32 => Ok((parse_u64(val)? as u32).to_le_bytes().to_vec()),
                PrimitiveType::I64 => Ok(val
                    .parse::<i64>()
                    .map_err(|_| "Invalid i64")?
                    .to_le_bytes()
                    .to_vec()),
                PrimitiveType::U64 => Ok(parse_u64(val)?.to_le_bytes().to_vec()),
                PrimitiveType::F32 => Ok(val
                    .parse::<f32>()
                    .map_err(|_| "Invalid f32")?
                    .to_le_bytes()
                    .to_vec()),
                PrimitiveType::F64 => Ok(val
                    .parse::<f64>()
                    .map_err(|_| "Invalid f64")?
                    .to_le_bytes()
                    .to_vec()),
                PrimitiveType::Bool => Ok(vec![
                    matches!(val.to_lowercase().as_str(), "true" | "1") as u8,
                ]),
                PrimitiveType::Pointer | PrimitiveType::Void => {
                    let v = parse_u64(val)?;
                    Ok(if self.is_64bit {
                        v.to_le_bytes().to_vec()
                    } else {
                        (v as u32).to_le_bytes().to_vec()
                    })
                }
                _ => Err("Unsupported type".into()),
            },
            _ => Err("Complex types not supported".into()),
        }
    }

    pub fn export_structure(&self, req: ExportStructureRequest) -> ExportStructureResult {
        let s = match self.structures.get(&req.structure_id) {
            Some(s) => s,
            None => {
                return ExportStructureResult {
                    success: false,
                    code: String::new(),
                    language: req.language,
                    warnings: vec![],
                    error: Some("Not found".into()),
                }
            }
        };
        let code = match req.language {
            ExportLanguage::C => self.export_c(s, &req),
            ExportLanguage::Rust => self.export_rust(s, &req),
            ExportLanguage::CSharp => self.export_csharp(s, &req),
            ExportLanguage::Python => self.export_python(s, &req),
        };
        ExportStructureResult {
            success: true,
            code,
            language: req.language,
            warnings: vec![],
            error: None,
        }
    }

    fn export_c(&self, s: &StructureDefinition, req: &ExportStructureRequest) -> String {
        let mut c = String::new();
        if let Some(p) = req.pack {
            c.push_str(&format!("#pragma pack(push, {})\n", p));
        }
        c.push_str(&format!("typedef struct {} {{\n", s.name));
        for f in &s.fields {
            if req.include_offsets {
                c.push_str(&format!("    /* {:#x} */ ", f.offset));
            }
            c.push_str(&format!(
                "    {} {};\n",
                self.type_to_c(&f.field_type),
                f.name
            ));
        }
        c.push_str(&format!("}} {};\n", s.name));
        if req.pack.is_some() {
            c.push_str("#pragma pack(pop)\n");
        }
        c
    }

    fn type_to_c(&self, ft: &FieldType) -> String {
        match ft {
            FieldType::Primitive(p) => match p {
                PrimitiveType::I8 => "int8_t",
                PrimitiveType::U8 => "uint8_t",
                PrimitiveType::I16 => "int16_t",
                PrimitiveType::U16 => "uint16_t",
                PrimitiveType::I32 => "int32_t",
                PrimitiveType::U32 => "uint32_t",
                PrimitiveType::I64 => "int64_t",
                PrimitiveType::U64 => "uint64_t",
                PrimitiveType::F32 => "float",
                PrimitiveType::F64 => "double",
                PrimitiveType::Bool => "bool",
                PrimitiveType::Char => "char",
                PrimitiveType::WChar => "wchar_t",
                _ => "void*",
            }
            .to_string(),
            FieldType::Array {
                element_type,
                count,
            } => format!("{}[{}]", self.type_to_c(element_type), count),
            FieldType::Pointer { pointee_type, .. } => format!("{}*", self.type_to_c(pointee_type)),
            FieldType::Struct(id) => self
                .structures
                .get(id)
                .map(|s| s.name.clone())
                .unwrap_or("unknown".into()),
            FieldType::StringPointer => "char*".into(),
            FieldType::WStringPointer => "wchar_t*".into(),
            FieldType::Bytes(len) => format!("uint8_t[{}]", len),
            _ => "void".into(),
        }
    }

    fn export_rust(&self, s: &StructureDefinition, req: &ExportStructureRequest) -> String {
        let mut c = format!(
            "#[repr(C{})]\n#[derive(Debug, Clone, Copy)]\npub struct {} {{\n",
            req.pack
                .map(|p| format!(", packed({})", p))
                .unwrap_or_default(),
            s.name
        );
        for f in &s.fields {
            c.push_str(&format!(
                "    pub {}: {},\n",
                f.name,
                self.type_to_rust(&f.field_type)
            ));
        }
        c.push_str("}\n");
        c
    }

    fn type_to_rust(&self, ft: &FieldType) -> String {
        match ft {
            FieldType::Primitive(p) => match p {
                PrimitiveType::I8 => "i8",
                PrimitiveType::U8 => "u8",
                PrimitiveType::I16 => "i16",
                PrimitiveType::U16 => "u16",
                PrimitiveType::I32 => "i32",
                PrimitiveType::U32 => "u32",
                PrimitiveType::I64 => "i64",
                PrimitiveType::U64 => "u64",
                PrimitiveType::F32 => "f32",
                PrimitiveType::F64 => "f64",
                PrimitiveType::Bool => "bool",
                PrimitiveType::Char => "u8",
                PrimitiveType::WChar => "u16",
                _ => "*mut ()",
            }
            .to_string(),
            FieldType::Array {
                element_type,
                count,
            } => format!("[{}; {}]", self.type_to_rust(element_type), count),
            FieldType::Pointer { pointee_type, .. } => {
                format!("*mut {}", self.type_to_rust(pointee_type))
            }
            FieldType::Struct(id) => self
                .structures
                .get(id)
                .map(|s| s.name.clone())
                .unwrap_or("Unknown".into()),
            FieldType::StringPointer => "*const i8".into(),
            FieldType::WStringPointer => "*const u16".into(),
            FieldType::Bytes(len) => format!("[u8; {}]", len),
            _ => "()".into(),
        }
    }

    fn export_csharp(&self, s: &StructureDefinition, req: &ExportStructureRequest) -> String {
        let mut c = format!(
            "[StructLayout(LayoutKind.Sequential{})]\npublic struct {} {{\n",
            req.pack
                .map(|p| format!(", Pack = {}", p))
                .unwrap_or_default(),
            s.name
        );
        for f in &s.fields {
            c.push_str(&format!(
                "    public {} {};\n",
                self.type_to_cs(&f.field_type),
                f.name
            ));
        }
        c.push_str("}\n");
        c
    }

    fn type_to_cs(&self, ft: &FieldType) -> String {
        match ft {
            FieldType::Primitive(p) => match p {
                PrimitiveType::I8 => "sbyte",
                PrimitiveType::U8 => "byte",
                PrimitiveType::I16 => "short",
                PrimitiveType::U16 => "ushort",
                PrimitiveType::I32 => "int",
                PrimitiveType::U32 => "uint",
                PrimitiveType::I64 => "long",
                PrimitiveType::U64 => "ulong",
                PrimitiveType::F32 => "float",
                PrimitiveType::F64 => "double",
                PrimitiveType::Bool => "bool",
                _ => "IntPtr",
            }
            .to_string(),
            FieldType::Pointer { .. } => "IntPtr".into(),
            _ => "object".into(),
        }
    }

    fn export_python(&self, s: &StructureDefinition, _req: &ExportStructureRequest) -> String {
        let mut c = format!(
            "from ctypes import *\n\nclass {}(Structure):\n    _fields_ = [\n",
            s.name
        );
        for f in &s.fields {
            c.push_str(&format!(
                "        (\"{}\", {}),\n",
                f.name,
                self.type_to_py(&f.field_type)
            ));
        }
        c.push_str("    ]\n");
        c
    }

    fn type_to_py(&self, ft: &FieldType) -> String {
        match ft {
            FieldType::Primitive(p) => match p {
                PrimitiveType::I8 => "c_int8",
                PrimitiveType::U8 => "c_uint8",
                PrimitiveType::I16 => "c_int16",
                PrimitiveType::U16 => "c_uint16",
                PrimitiveType::I32 => "c_int32",
                PrimitiveType::U32 => "c_uint32",
                PrimitiveType::I64 => "c_int64",
                PrimitiveType::U64 => "c_uint64",
                PrimitiveType::F32 => "c_float",
                PrimitiveType::F64 => "c_double",
                PrimitiveType::Bool => "c_bool",
                _ => "c_void_p",
            }
            .to_string(),
            FieldType::Array {
                element_type,
                count,
            } => format!("{} * {}", self.type_to_py(element_type), count),
            FieldType::Pointer { .. } | FieldType::StringPointer => "c_void_p".into(),
            FieldType::Bytes(len) => format!("c_uint8 * {}", len),
            _ => "c_void_p".into(),
        }
    }

    /// Auto-analyze memory region to detect structure fields
    pub fn auto_analyze(
        &self,
        req: AutoAnalyzeRequest,
        read_mem: impl Fn(u64, usize) -> Result<Vec<u8>, String>,
    ) -> AutoAnalyzeResult {
        info!(address = %format!("{:#x}", req.address), size = req.size, "Auto-analyzing memory region");

        // Validate request
        if req.size == 0 {
            warn!("Auto-analyze request has zero size");
            return AutoAnalyzeResult {
                success: false,
                address: req.address,
                size: req.size,
                suggested_fields: vec![],
                patterns: vec![],
                suggested_structure: None,
                error: Some("Size cannot be zero".into()),
            };
        }
        let size = req.size.min(MAX_AUTO_ANALYZE_SIZE);
        if size != req.size {
            debug!(
                requested = req.size,
                actual = size,
                "Capped auto-analyze size"
            );
        }

        let bytes = match read_mem(req.address, size) {
            Ok(b) => b,
            Err(e) => {
                error!(address = %format!("{:#x}", req.address), size, error = %e, "Failed to read memory for auto-analysis");
                return AutoAnalyzeResult {
                    success: false,
                    address: req.address,
                    size,
                    suggested_fields: vec![],
                    patterns: vec![],
                    suggested_structure: None,
                    error: Some(e),
                };
            }
        };
        let mut fields = Vec::new();
        let mut patterns = Vec::new();
        let ptr_size = if req.is_64bit { 8 } else { 4 };
        let mut offset = 0;
        let mut n = 0;
        while offset < bytes.len() {
            if req.detect_pointers && offset + ptr_size <= bytes.len() {
                let p = if req.is_64bit {
                    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap_or([0; 8]))
                } else {
                    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap_or([0; 4]))
                        as u64
                };
                if is_ptr(p, req.is_64bit) {
                    fields.push(SuggestedField {
                        name: format!("ptr_{}", n),
                        field_type: FieldType::Primitive(PrimitiveType::Pointer),
                        offset,
                        confidence: 0.7,
                        reason: "Valid pointer".into(),
                        sample_value: format!("{:#x}", p),
                    });
                    patterns.push(DetectedPattern {
                        pattern_type: StructurePatternType::ValidPointer,
                        offset,
                        size: ptr_size,
                        confidence: 0.7,
                        description: format!("Pointer to {:#x}", p),
                    });
                    n += 1;
                    offset += ptr_size;
                    continue;
                }
            }
            if req.detect_strings && offset + 4 <= bytes.len() {
                let len = detect_str(&bytes[offset..]);
                if len >= 4 {
                    let s = String::from_utf8_lossy(&bytes[offset..offset + len]);
                    fields.push(SuggestedField {
                        name: format!("str_{}", n),
                        field_type: FieldType::FixedString(len + 1),
                        offset,
                        confidence: 0.8,
                        reason: "ASCII string".into(),
                        sample_value: format!("\"{}\"", s),
                    });
                    patterns.push(DetectedPattern {
                        pattern_type: StructurePatternType::AsciiString,
                        offset,
                        size: len + 1,
                        confidence: 0.8,
                        description: format!("String: \"{}\"", s),
                    });
                    n += 1;
                    offset += len + 1;
                    continue;
                }
            }
            if offset + 4 <= bytes.len() {
                let f = f32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap_or([0; 4]));
                if is_float(f) {
                    fields.push(SuggestedField {
                        name: format!("float_{}", n),
                        field_type: FieldType::Primitive(PrimitiveType::F32),
                        offset,
                        confidence: 0.6,
                        reason: "Float value".into(),
                        sample_value: format!("{:.4}", f),
                    });
                    n += 1;
                    offset += 4;
                    continue;
                }
                let v = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap_or([0; 4]));
                fields.push(SuggestedField {
                    name: format!("field_{}", n),
                    field_type: FieldType::Primitive(PrimitiveType::U32),
                    offset,
                    confidence: 0.3,
                    reason: "Unknown u32".into(),
                    sample_value: format!("{}", v),
                });
                n += 1;
                offset += 4;
            } else {
                offset += 1;
            }
        }
        let filtered: Vec<_> = fields
            .into_iter()
            .filter(|f| f.confidence >= req.min_confidence)
            .collect();
        AutoAnalyzeResult {
            success: true,
            address: req.address,
            size: req.size,
            suggested_fields: filtered,
            patterns,
            suggested_structure: None,
            error: None,
        }
    }

    /// Save structures to file with validation
    pub fn save_structures(&self, req: SaveStructuresRequest) -> StructurePersistResult {
        info!(filename = %req.filename, "Saving structures to file");

        // Validate filename
        if req.filename.trim().is_empty() {
            warn!("Save failed: empty filename");
            return StructurePersistResult {
                success: false,
                structure_count: 0,
                enum_count: 0,
                filename: req.filename,
                error: Some("Filename cannot be empty".into()),
            };
        }

        let structs: Vec<_> = if req.structure_ids.is_empty() {
            self.structures
                .values()
                .filter(|s| req.include_auto_detected || s.source != StructureSource::AutoDetected)
                .cloned()
                .collect()
        } else {
            req.structure_ids
                .iter()
                .filter_map(|id| self.structures.get(id))
                .cloned()
                .collect()
        };
        let enums: Vec<_> = if req.enum_ids.is_empty() {
            self.enums.values().cloned().collect()
        } else {
            req.enum_ids
                .iter()
                .filter_map(|id| self.enums.get(id))
                .cloned()
                .collect()
        };

        let db = StructureDatabase {
            version: 1,
            structures: structs.clone(),
            enums: enums.clone(),
            metadata: StructureDatabaseMetadata {
                created_at: Self::timestamp(),
                modified_at: Self::timestamp(),
                is_64bit: self.is_64bit,
                target_name: None,
                notes: None,
            },
        };

        match serde_json::to_string_pretty(&db) {
            Ok(json) => match fs::write(&req.filename, &json) {
                Ok(_) => {
                    info!(structures = structs.len(), enums = enums.len(), filename = %req.filename, "Structures saved successfully");
                    StructurePersistResult {
                        success: true,
                        structure_count: structs.len(),
                        enum_count: enums.len(),
                        filename: req.filename,
                        error: None,
                    }
                }
                Err(e) => {
                    error!(filename = %req.filename, error = %e, "Failed to write file");
                    StructurePersistResult {
                        success: false,
                        structure_count: 0,
                        enum_count: 0,
                        filename: req.filename,
                        error: Some(format!("Failed to write file: {}", e)),
                    }
                }
            },
            Err(e) => {
                error!(error = %e, "Failed to serialize structures");
                StructurePersistResult {
                    success: false,
                    structure_count: 0,
                    enum_count: 0,
                    filename: req.filename,
                    error: Some(format!("Serialization error: {}", e)),
                }
            }
        }
    }

    /// Load structures from file with validation
    pub fn load_structures(&mut self, req: LoadStructuresRequest) -> StructurePersistResult {
        info!(filename = %req.filename, merge = req.merge, "Loading structures from file");

        // Validate filename
        if req.filename.trim().is_empty() {
            warn!("Load failed: empty filename");
            return StructurePersistResult {
                success: false,
                structure_count: 0,
                enum_count: 0,
                filename: req.filename,
                error: Some("Filename cannot be empty".into()),
            };
        }

        let content = match fs::read_to_string(&req.filename) {
            Ok(c) => c,
            Err(e) => {
                error!(filename = %req.filename, error = %e, "Failed to read file");
                return StructurePersistResult {
                    success: false,
                    structure_count: 0,
                    enum_count: 0,
                    filename: req.filename,
                    error: Some(format!("Failed to read file: {}", e)),
                };
            }
        };

        let db: StructureDatabase = match serde_json::from_str(&content) {
            Ok(d) => d,
            Err(e) => {
                error!(filename = %req.filename, error = %e, "Failed to parse file");
                return StructurePersistResult {
                    success: false,
                    structure_count: 0,
                    enum_count: 0,
                    filename: req.filename,
                    error: Some(format!("Parse error: {}", e)),
                };
            }
        };

        // Validate database version
        if db.version > 1 {
            warn!(
                version = db.version,
                "Database version is newer than supported"
            );
        }

        if !req.merge {
            debug!("Clearing existing structures before load");
            self.structures.clear();
            self.structure_names.clear();
            self.enums.clear();
            self.enum_names.clear();
        }

        for s in &db.structures {
            self.structure_names.insert(s.name.clone(), s.id);
            self.structures.insert(s.id, s.clone());
        }
        for e in &db.enums {
            self.enum_names.insert(e.name.clone(), e.id);
            self.enums.insert(e.id, e.clone());
        }

        info!(
            structures = db.structures.len(),
            enums = db.enums.len(),
            "Structures loaded successfully"
        );
        StructurePersistResult {
            success: true,
            structure_count: db.structures.len(),
            enum_count: db.enums.len(),
            filename: req.filename,
            error: None,
        }
    }
}

fn parse_u64(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).map_err(|e| e.to_string())
    } else {
        s.parse()
            .map_err(|e: std::num::ParseIntError| e.to_string())
    }
}

fn read_cstring(b: &[u8]) -> String {
    let end = b.iter().position(|&x| x == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).to_string()
}
fn hex_str(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{:02X}", x))
        .collect::<Vec<_>>()
        .join(" ")
}
fn is_ptr(v: u64, is_64: bool) -> bool {
    v != 0 && v >= 0x10000 && v < if is_64 { 0x7FFF_FFFF_FFFF } else { 0x7FFF_FFFF }
}
fn detect_str(b: &[u8]) -> usize {
    b.iter().take_while(|&&c| (0x20..0x7F).contains(&c)).count()
}
fn is_float(f: f32) -> bool {
    f.is_finite() && f.abs() > 0.0001 && f.abs() < 1_000_000.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::StructureFieldInput;

    #[test]
    fn test_create_structure_empty() {
        let mut mgr = StructureManager::new(true);
        let req = CreateStructureRequest {
            name: "EmptyStruct".into(),
            fields: vec![],
            is_64bit: true,
            description: None,
            tags: vec![],
        };
        let res = mgr.create_structure(req);
        assert!(res.success);
        assert!(res.structure.is_some());
        assert_eq!(res.structure.unwrap().total_size, 0);
    }

    #[test]
    fn test_create_structure_with_fields() {
        let mut mgr = StructureManager::new(true);
        let req = CreateStructureRequest {
            name: "PlayerInfo".into(),
            fields: vec![
                StructureFieldInput {
                    name: "health".into(),
                    field_type: "i32".into(),
                    offset: Some(0),
                    description: Some("Current HP".into()),
                },
                StructureFieldInput {
                    name: "mana".into(),
                    field_type: "i32".into(),
                    offset: Some(4),
                    description: None,
                },
                StructureFieldInput {
                    name: "position".into(),
                    field_type: "f32[3]".into(),
                    offset: Some(8),
                    description: None,
                },
            ],
            is_64bit: true,
            description: Some("Player data".into()),
            tags: vec!["game".into()],
        };
        let res = mgr.create_structure(req);
        assert!(res.success, "Failed: {:?}", res.error);
        let s = res.structure.unwrap();
        assert_eq!(s.name, "PlayerInfo");
        assert_eq!(s.fields.len(), 3);
        assert_eq!(s.total_size, 20); // 4 + 4 + 12
    }

    #[test]
    fn test_create_structure_duplicate_name() {
        let mut mgr = StructureManager::new(true);
        let req1 = CreateStructureRequest {
            name: "Dupe".into(),
            fields: vec![],
            is_64bit: true,
            description: None,
            tags: vec![],
        };
        let req2 = CreateStructureRequest {
            name: "Dupe".into(),
            fields: vec![],
            is_64bit: true,
            description: None,
            tags: vec![],
        };
        assert!(mgr.create_structure(req1).success);
        let res2 = mgr.create_structure(req2);
        assert!(!res2.success);
        assert!(res2.error.unwrap().contains("already exists"));
    }

    #[test]
    fn test_create_structure_empty_name() {
        let mut mgr = StructureManager::new(true);
        let req = CreateStructureRequest {
            name: "  ".into(),
            fields: vec![],
            is_64bit: true,
            description: None,
            tags: vec![],
        };
        let res = mgr.create_structure(req);
        assert!(!res.success);
        assert!(res.error.unwrap().contains("empty"));
    }

    #[test]
    fn test_parse_field_types() {
        let mgr = StructureManager::new(true);
        // Primitives
        assert!(mgr.parse_field_type("u8").is_ok());
        assert!(mgr.parse_field_type("i16").is_ok());
        assert!(mgr.parse_field_type("u32").is_ok());
        assert!(mgr.parse_field_type("i64").is_ok());
        assert!(mgr.parse_field_type("f32").is_ok());
        assert!(mgr.parse_field_type("f64").is_ok());
        assert!(mgr.parse_field_type("bool").is_ok());
        // Pointers
        assert!(mgr.parse_field_type("int*").is_ok());
        assert!(mgr.parse_field_type("void*").is_ok());
        // Arrays
        assert!(mgr.parse_field_type("u8[16]").is_ok());
        assert!(mgr.parse_field_type("i32[4]").is_ok());
        // Special
        assert!(mgr.parse_field_type("string").is_ok());
        assert!(mgr.parse_field_type("bytes[64]").is_ok());
        assert!(mgr.parse_field_type("padding[8]").is_ok());
        // Invalid
        assert!(mgr.parse_field_type("unknown_type").is_err());
    }

    #[test]
    fn test_delete_structure() {
        let mut mgr = StructureManager::new(true);
        let req = CreateStructureRequest {
            name: "ToDelete".into(),
            fields: vec![],
            is_64bit: true,
            description: None,
            tags: vec![],
        };
        let res = mgr.create_structure(req);
        let id = res.structure.unwrap().id;

        let del_res = mgr.delete_structure(id);
        assert!(del_res.success);
        assert!(mgr.get_structure(id).is_none());
    }

    #[test]
    fn test_list_structures() {
        let mut mgr = StructureManager::new(true);
        mgr.create_structure(CreateStructureRequest {
            name: "S1".into(),
            fields: vec![],
            is_64bit: true,
            description: None,
            tags: vec![],
        });
        mgr.create_structure(CreateStructureRequest {
            name: "S2".into(),
            fields: vec![],
            is_64bit: true,
            description: None,
            tags: vec![],
        });

        let list = mgr.list_structures();
        assert!(list.success);
        assert_eq!(list.structures.len(), 2);
    }

    #[test]
    fn test_create_enum() {
        let mut mgr = StructureManager::new(true);
        let res = mgr.create_enum(
            "Colors".into(),
            4,
            false,
            vec![
                ("Red".into(), 0, None),
                ("Green".into(), 1, None),
                ("Blue".into(), 2, None),
            ],
            None,
            false,
        );
        assert!(res.is_ok());
        let e = res.unwrap();
        assert_eq!(e.name, "Colors");
        assert_eq!(e.members.len(), 3);
    }

    #[test]
    fn test_export_c() {
        let mut mgr = StructureManager::new(true);
        let req = CreateStructureRequest {
            name: "TestStruct".into(),
            fields: vec![StructureFieldInput {
                name: "value".into(),
                field_type: "i32".into(),
                offset: Some(0),
                description: None,
            }],
            is_64bit: true,
            description: None,
            tags: vec![],
        };
        let res = mgr.create_structure(req);
        let id = res.structure.unwrap().id;

        let export = mgr.export_structure(ExportStructureRequest {
            structure_id: id,
            language: ExportLanguage::C,
            include_comments: true,
            include_offsets: true,
            pack: None,
        });
        assert!(export.success);
        assert!(export.code.contains("typedef struct"));
        assert!(export.code.contains("int32_t"));
    }

    #[test]
    fn test_export_rust() {
        let mut mgr = StructureManager::new(true);
        let req = CreateStructureRequest {
            name: "RustStruct".into(),
            fields: vec![StructureFieldInput {
                name: "data".into(),
                field_type: "u64".into(),
                offset: Some(0),
                description: None,
            }],
            is_64bit: true,
            description: None,
            tags: vec![],
        };
        let res = mgr.create_structure(req);
        let id = res.structure.unwrap().id;

        let export = mgr.export_structure(ExportStructureRequest {
            structure_id: id,
            language: ExportLanguage::Rust,
            include_comments: false,
            include_offsets: false,
            pack: None,
        });
        assert!(export.success);
        assert!(export.code.contains("#[repr(C)]"));
        assert!(export.code.contains("pub struct"));
    }

    #[test]
    fn test_helper_functions() {
        // Test parse_u64
        assert_eq!(parse_u64("123").unwrap(), 123);
        assert_eq!(parse_u64("0x1F").unwrap(), 31);
        assert_eq!(parse_u64("0X10").unwrap(), 16);
        assert!(parse_u64("invalid").is_err());

        // Test read_cstring
        assert_eq!(read_cstring(b"hello\0world"), "hello");
        assert_eq!(read_cstring(b"test"), "test");

        // Test hex_str
        assert_eq!(hex_str(&[0xDE, 0xAD]), "DE AD");

        // Test is_ptr
        assert!(!is_ptr(0, true));
        assert!(!is_ptr(0x1000, true)); // Too low
        assert!(is_ptr(0x7FFE0000, true)); // Valid

        // Test detect_str
        assert_eq!(detect_str(b"hello world"), 11);
        assert_eq!(detect_str(b"hi\x00more"), 2);

        // Test is_float
        assert!(is_float(1.5));
        assert!(!is_float(f32::NAN));
        assert!(!is_float(0.0));
    }

    #[test]
    fn test_structure_32bit_vs_64bit() {
        let mgr32 = StructureManager::new(false);
        let _mgr64 = StructureManager::new(true);

        // Pointer size differs
        let ptr_type = mgr32.parse_field_type("void*").unwrap();
        assert_eq!(ptr_type.size(false, &HashMap::new()), 4);
        assert_eq!(ptr_type.size(true, &HashMap::new()), 8);
    }
}
