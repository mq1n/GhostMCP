#!/usr/bin/env python3
"""
Rohitab API Monitor XML to Ghost API Pack JSON Converter

Converts Rohitab API Monitor XML definition files to the Ghost API pack JSON format.

Usage:
    python convert_rohitab_api.py <input_xml> [output_json]
    python convert_rohitab_api.py --batch <api_folder> <output_folder>

Examples:
    python convert_rohitab_api.py API/Windows/Kernel32.xml kernel32.json
    python convert_rohitab_api.py --batch API/Windows output/
"""

import xml.etree.ElementTree as ET
import json
import os
import sys
import re
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict


# =============================================================================
# Type Definitions
# =============================================================================

@dataclass
class RohitabVariable:
    """Represents a Rohitab type/variable definition"""
    name: str
    var_type: str  # Integer, Alias, Pointer, Struct, Array, Interface, Void, ModuleHandle
    base: Optional[str] = None
    size: Optional[int] = None
    unsigned: bool = False
    display: Optional[str] = None
    enum_values: List[Dict[str, str]] = field(default_factory=list)
    flag_values: List[Dict[str, str]] = field(default_factory=list)
    struct_fields: List[Dict[str, str]] = field(default_factory=list)
    array_count: Optional[int] = None


@dataclass
class RohitabParam:
    """Represents a function parameter"""
    name: str
    type_name: str
    length: Optional[str] = None  # Related param for buffer size
    post_length: Optional[str] = None  # Output buffer size param


@dataclass 
class RohitabApi:
    """Represents an API function definition"""
    name: str
    params: List[RohitabParam] = field(default_factory=list)
    return_type: str = "void"
    ordinal: Optional[int] = None
    success_return: Optional[str] = None  # "Equal" or "NotEqual"
    success_value: Optional[str] = None
    category: Optional[str] = None
    both_charset: bool = False


@dataclass
class RohitabModule:
    """Represents a DLL module definition"""
    name: str
    calling_convention: str = "STDCALL"
    error_func: Optional[str] = None
    variables: Dict[str, RohitabVariable] = field(default_factory=dict)
    apis: List[RohitabApi] = field(default_factory=list)
    current_category: Optional[str] = None


# =============================================================================
# Type Mapping: Rohitab -> Ghost
# =============================================================================

# Primitive type mappings (Rohitab name -> Ghost primitive)
PRIMITIVE_TYPE_MAP = {
    # Void
    "void": "Void",
    "VOID": "Void",
    
    # Boolean
    "BOOL": "Bool",
    "BOOLEAN": "Bool",
    "bool": "Bool",
    
    # 8-bit integers
    "BYTE": "UInt8",
    "UCHAR": "UInt8",
    "UINT8": "UInt8",
    "unsigned char": "UInt8",
    "char": "Int8",
    "CHAR": "Int8",
    "INT8": "Int8",
    "CCHAR": "Int8",
    
    # 16-bit integers
    "WORD": "UInt16",
    "USHORT": "UInt16",
    "UINT16": "UInt16",
    "unsigned short": "UInt16",
    "u_short": "UInt16",
    "SHORT": "Int16",
    "short": "Int16",
    "INT16": "Int16",
    "WCHAR": "UInt16",
    
    # 32-bit integers
    "DWORD": "UInt32",
    "UINT": "UInt32",
    "UINT32": "UInt32",
    "ULONG": "UInt32",
    "unsigned int": "UInt32",
    "unsigned long": "UInt32",
    "u_int": "UInt32",
    "u_long": "UInt32",
    "INT": "Int32",
    "INT32": "Int32",
    "LONG": "Int32",
    "int": "Int32",
    "long": "Int32",
    
    # 64-bit integers
    "UINT64": "UInt64",
    "ULONGLONG": "UInt64",
    "ULONG64": "UInt64",
    "DWORD64": "UInt64",
    "unsigned __int64": "UInt64",
    "INT64": "Int64",
    "LONGLONG": "Int64",
    "LONG64": "Int64",
    "__int64": "Int64",
    
    # Pointer-sized integers (default to 64-bit)
    "SIZE_T": "UInt64",
    "ULONG_PTR": "UInt64",
    "DWORD_PTR": "UInt64",
    "UINT_PTR": "UInt64",
    "SSIZE_T": "Int64",
    "LONG_PTR": "Int64",
    "INT_PTR": "Int64",
    
    # Floating point
    "FLOAT": "Float32",
    "float": "Float32",
    "DOUBLE": "Float64",
    "double": "Float64",
    
    # Handles (all map to Handle)
    "HANDLE": "Handle",
    "HMODULE": "Handle",
    "HINSTANCE": "Handle",
    "HWND": "Handle",
    "HDC": "Handle",
    "HKEY": "Handle",
    "HBITMAP": "Handle",
    "HBRUSH": "Handle",
    "HCURSOR": "Handle",
    "HFONT": "Handle",
    "HICON": "Handle",
    "HMENU": "Handle",
    "HPEN": "Handle",
    "HRGN": "Handle",
    "HPALETTE": "Handle",
    "HGLOBAL": "Handle",
    "HLOCAL": "Handle",
    "HRSRC": "Handle",
    "HACCEL": "Handle",
    "HDWP": "Handle",
    "HDESK": "Handle",
    "HWINSTA": "Handle",
    "HKL": "Handle",
    "HHOOK": "Handle",
    "HEVENT": "Handle",
    "HTASK": "Handle",
    "HFILE": "Handle",
    "HMETAFILE": "Handle",
    "HENHMETAFILE": "Handle",
    "HCOLORSPACE": "Handle",
    "HGLRC": "Handle",
    "HMONITOR": "Handle",
    "HTHEME": "Handle",
    "HPROPSHEETPAGE": "Handle",
    "SOCKET": "Handle",
    "SC_HANDLE": "Handle",
    "SERVICE_STATUS_HANDLE": "Handle",
    "LSA_HANDLE": "Handle",
    "HCERTSTORE": "Handle",
    "PCCERT_CONTEXT": "Handle",
    "HCRYPTPROV": "Handle",
    "HCRYPTHASH": "Handle",
    "HCRYPTKEY": "Handle",
    "HCATADMIN": "Handle",
    "HCATINFO": "Handle",
    "BCRYPT_ALG_HANDLE": "Handle",
    "BCRYPT_KEY_HANDLE": "Handle",
    "BCRYPT_HASH_HANDLE": "Handle",
    "BCRYPT_SECRET_HANDLE": "Handle",
    "NCRYPT_PROV_HANDLE": "Handle",
    "NCRYPT_KEY_HANDLE": "Handle",
    "NCRYPT_SECRET_HANDLE": "Handle",
    
    # Special
    "HRESULT": "Int32",
    "NTSTATUS": "Int32",
    "LRESULT": "Int64",
    "WPARAM": "UInt64",
    "LPARAM": "Int64",
    "ATOM": "UInt16",
    "COLORREF": "UInt32",
    "LCID": "UInt32",
    "LANGID": "UInt16",
    "REGSAM": "UInt32",
    "ACCESS_MASK": "UInt32",
    "SECURITY_INFORMATION": "UInt32",
}

# String type patterns
UNICODE_STRING_TYPES = {
    "LPWSTR", "LPCWSTR", "PWSTR", "PCWSTR", "WCHAR*", "const WCHAR*",
    "LPOLESTR", "LPCOLESTR", "OLECHAR*", "BSTR", "LPCTSTR", "LPTSTR",
    "PCTSTR", "PTSTR", "PZZWSTR", "PCZZWSTR", "PNZWCH", "PCNZWCH",
    "LPWCH", "LPCWCH", "PWCH", "PCWCH",
}

ANSI_STRING_TYPES = {
    "LPSTR", "LPCSTR", "PSTR", "PCSTR", "char*", "const char*",
    "LPCH", "LPCCH", "PCH", "PCCH", "PZZSTR", "PCZZSTR",
    "PNZCH", "PCNZCH",
}


# =============================================================================
# XML Parser
# =============================================================================

class RohitabParser:
    """Parser for Rohitab API Monitor XML files"""
    
    def __init__(self, base_path: str):
        self.base_path = Path(base_path)
        self.global_variables: Dict[str, RohitabVariable] = {}
        self.loaded_includes: Set[str] = set()
        self.modules: List[RohitabModule] = []
    
    def parse_file(self, xml_path: str) -> List[RohitabModule]:
        """Parse a Rohitab XML file and return module definitions"""
        self.modules = []
        xml_path_obj = Path(xml_path)
        
        # If the path is already absolute or exists as-is, use it directly
        if xml_path_obj.is_absolute():
            full_path = xml_path_obj
        elif xml_path_obj.exists():
            full_path = xml_path_obj.resolve()
        else:
            full_path = self.base_path / xml_path
        
        if not full_path.exists():
            print(f"Warning: File not found: {full_path}", file=sys.stderr)
            return []
        
        try:
            tree = ET.parse(full_path)
            root = tree.getroot()
            self._parse_element(root, full_path.parent)
        except ET.ParseError as e:
            print(f"Warning: XML parse error in {full_path}: {e}", file=sys.stderr)
        
        return self.modules
    
    def _parse_element(self, element: ET.Element, current_dir: Path):
        """Recursively parse XML elements"""
        
        for child in element:
            tag = child.tag
            
            if tag == "Include":
                self._handle_include(child, current_dir)
            elif tag == "Headers":
                self._parse_headers(child)
            elif tag == "Module":
                self._parse_module(child)
            elif tag == "Variable":
                var = self._parse_variable(child)
                if var:
                    self.global_variables[var.name] = var
    
    def _handle_include(self, element: ET.Element, current_dir: Path):
        """Handle Include directive"""
        filename = element.get("Filename", "")
        if not filename:
            return
        
        # Normalize path
        include_path = (self.base_path / filename).resolve()
        include_key = str(include_path)
        
        if include_key in self.loaded_includes:
            return
        
        self.loaded_includes.add(include_key)
        
        if include_path.exists():
            try:
                tree = ET.parse(include_path)
                root = tree.getroot()
                self._parse_element(root, include_path.parent)
            except ET.ParseError as e:
                print(f"Warning: Failed to parse include {include_path}: {e}", file=sys.stderr)
    
    def _parse_headers(self, element: ET.Element):
        """Parse Headers section containing type definitions"""
        for child in element:
            if child.tag == "Variable":
                var = self._parse_variable(child)
                if var:
                    self.global_variables[var.name] = var
            elif child.tag == "Condition":
                # Handle architecture-specific definitions (default to 64-bit)
                arch = child.get("Architecture", "64")
                if arch == "64":
                    for subchild in child:
                        if subchild.tag == "Variable":
                            var = self._parse_variable(subchild)
                            if var:
                                self.global_variables[var.name] = var
    
    def _parse_variable(self, element: ET.Element) -> Optional[RohitabVariable]:
        """Parse a Variable element into a RohitabVariable"""
        name = element.get("Name", "")
        if not name:
            return None
        
        var = RohitabVariable(
            name=name,
            var_type=element.get("Type", "Alias"),
            base=element.get("Base"),
            unsigned=element.get("Unsigned", "").lower() == "true",
        )
        
        # Parse size
        size_str = element.get("Size")
        if size_str:
            try:
                var.size = int(size_str)
            except ValueError:
                pass
        
        # Parse array count
        count_str = element.get("Count")
        if count_str:
            try:
                var.array_count = int(count_str)
            except ValueError:
                pass
        
        # Parse display name
        for child in element:
            if child.tag == "Display":
                var.display = child.get("Name")
            elif child.tag == "Enum":
                for set_elem in child:
                    if set_elem.tag == "Set":
                        var.enum_values.append({
                            "name": set_elem.get("Name", ""),
                            "value": set_elem.get("Value", "0")
                        })
            elif child.tag == "Flag":
                for set_elem in child:
                    if set_elem.tag == "Set":
                        var.flag_values.append({
                            "name": set_elem.get("Name", ""),
                            "value": set_elem.get("Value", "0")
                        })
            elif child.tag == "Field":
                var.struct_fields.append({
                    "name": child.get("Name", ""),
                    "type": child.get("Type", "")
                })
        
        return var
    
    def _parse_module(self, element: ET.Element):
        """Parse a Module element"""
        name = element.get("Name", "")
        if not name:
            return
        
        module = RohitabModule(
            name=name,
            calling_convention=element.get("CallingConvention", "STDCALL"),
            error_func=element.get("ErrorFunc"),
        )
        
        current_category = None
        
        for child in element:
            if child.tag == "Variable":
                var = self._parse_variable(child)
                if var:
                    module.variables[var.name] = var
            elif child.tag == "Category":
                current_category = child.get("Name")
            elif child.tag == "Api":
                api = self._parse_api(child)
                if api:
                    api.category = current_category
                    module.apis.append(api)
        
        self.modules.append(module)
    
    def _parse_api(self, element: ET.Element) -> Optional[RohitabApi]:
        """Parse an Api element"""
        name = element.get("Name", "")
        if not name:
            return None
        
        api = RohitabApi(name=name)
        
        # Parse ordinal
        ordinal_str = element.get("Ordinal")
        if ordinal_str:
            try:
                api.ordinal = int(ordinal_str)
            except ValueError:
                pass
        
        # Check for BothCharset (A/W variants)
        api.both_charset = element.get("BothCharset", "").lower() == "true"
        
        for child in element:
            if child.tag == "Param":
                param = RohitabParam(
                    name=child.get("Name", ""),
                    type_name=child.get("Type", ""),
                    length=child.get("Length"),
                    post_length=child.get("PostLength"),
                )
                api.params.append(param)
            elif child.tag == "Return":
                api.return_type = child.get("Type", "void")
            elif child.tag == "Success":
                api.success_return = child.get("Return")
                api.success_value = child.get("Value")
        
        return api


# =============================================================================
# Type Converter
# =============================================================================

class GhostTypeConverter:
    """Converts Rohitab types to Ghost API pack format"""
    
    def __init__(self, parser: RohitabParser):
        self.parser = parser
        self.all_variables = {**parser.global_variables}
    
    def update_module_variables(self, module: RohitabModule):
        """Update with module-specific variables"""
        self.all_variables.update(module.variables)
    
    def convert_type(self, type_name: str, length_param: Optional[str] = None) -> Dict[str, Any]:
        """Convert a Rohitab type name to Ghost type format"""
        if not type_name:
            return {"Primitive": "Void"}
        
        # Clean up type name
        type_name = type_name.strip()
        
        # Handle const qualifier
        is_const = type_name.startswith("const ") or type_name.startswith("CONST ")
        if is_const:
            type_name = re.sub(r'^(const|CONST)\s+', '', type_name)
        
        # Check for direct primitive mapping
        if type_name in PRIMITIVE_TYPE_MAP:
            return {"Primitive": PRIMITIVE_TYPE_MAP[type_name]}
        
        # Check for Unicode string types
        if type_name in UNICODE_STRING_TYPES:
            return {"String": {"encoding": "Unicode", "max_length": 260}}
        
        # Check for ANSI string types
        if type_name in ANSI_STRING_TYPES:
            return {"String": {"encoding": "Ansi", "max_length": 260}}
        
        # Check for pointer types (ending with *)
        if type_name.endswith("*"):
            inner_type = type_name[:-1].strip()
            inner_converted = self.convert_type(inner_type)
            
            result = {
                "Pointer": {
                    "inner": inner_converted,
                    "nullable": True
                }
            }
            
            # Add size hint if length param is provided
            if length_param:
                result["Pointer"]["size_hint"] = {"ParamName": length_param}
            
            return result
        
        # Check for pointer types (ending with **)
        if type_name.endswith("**"):
            inner_type = type_name[:-2].strip()
            inner_ptr = self.convert_type(inner_type + "*")
            return {
                "Pointer": {
                    "inner": inner_ptr,
                    "nullable": True
                }
            }
        
        # Look up in variable definitions
        if type_name in self.all_variables:
            var = self.all_variables[type_name]
            return self._convert_variable(var, length_param)
        
        # Check for bracketed types like [ERROR_CODE]
        if type_name.startswith("[") and type_name.endswith("]"):
            inner_name = type_name[1:-1]
            if inner_name in self.all_variables:
                var = self.all_variables[inner_name]
                return self._convert_variable(var, length_param)
            # Default bracketed types to Int32 (usually error codes)
            return {"Primitive": "Int32"}
        
        # Check for struct types
        if type_name.startswith("struct "):
            # Generic struct pointer
            return {"Primitive": "Void"}
        
        # Check for LP/P prefix types (pointers)
        if type_name.startswith("LP") and len(type_name) > 2:
            base_type = type_name[2:]
            if base_type.startswith("C"):  # LPCXXX is const pointer
                base_type = base_type[1:]
            return {
                "Pointer": {
                    "inner": self.convert_type(base_type),
                    "nullable": True
                }
            }
        
        if type_name.startswith("P") and len(type_name) > 1 and type_name[1].isupper():
            base_type = type_name[1:]
            if base_type.startswith("C"):  # PCXXX is const pointer
                base_type = base_type[1:]
            return {
                "Pointer": {
                    "inner": self.convert_type(base_type),
                    "nullable": True
                }
            }
        
        # Default fallback
        return {"Primitive": "Void"}
    
    def _convert_variable(self, var: RohitabVariable, length_param: Optional[str] = None) -> Dict[str, Any]:
        """Convert a RohitabVariable to Ghost type format"""
        
        if var.var_type == "Integer":
            size = var.size or 4
            unsigned = var.unsigned
            
            if size == 1:
                return {"Primitive": "UInt8" if unsigned else "Int8"}
            elif size == 2:
                return {"Primitive": "UInt16" if unsigned else "Int16"}
            elif size == 4:
                return {"Primitive": "UInt32" if unsigned else "Int32"}
            elif size == 8:
                return {"Primitive": "UInt64" if unsigned else "Int64"}
            else:
                return {"Primitive": "UInt32" if unsigned else "Int32"}
        
        elif var.var_type == "Alias":
            if var.base:
                return self.convert_type(var.base, length_param)
            return {"Primitive": "Void"}
        
        elif var.var_type == "Pointer":
            if var.base:
                inner = self.convert_type(var.base)
                result = {
                    "Pointer": {
                        "inner": inner,
                        "nullable": True
                    }
                }
                if length_param:
                    result["Pointer"]["size_hint"] = {"ParamName": length_param}
                return result
            return {"Pointer": {"inner": {"Primitive": "Void"}, "nullable": True}}
        
        elif var.var_type == "Struct":
            # For structs, we return a reference (they should be defined separately)
            return {"Primitive": "Void"}  # Structs passed as pointers typically
        
        elif var.var_type == "Array":
            if var.base and var.array_count:
                inner = self.convert_type(var.base)
                return {
                    "Array": {
                        "element_type": inner,
                        "length": var.array_count
                    }
                }
            return {"Primitive": "Void"}
        
        elif var.var_type in ("Void", "void"):
            return {"Primitive": "Void"}
        
        elif var.var_type == "ModuleHandle":
            return {"Primitive": "Handle"}
        
        elif var.var_type == "Interface":
            return {"Primitive": "Handle"}  # COM interfaces as handles
        
        return {"Primitive": "Void"}
    
    def infer_direction(self, param: RohitabParam, type_name: str) -> str:
        """Infer parameter direction from type and attributes"""
        # Check for output buffer indicators
        if param.post_length:
            return "Out"
        
        # Check for const types
        if "const " in type_name.lower() or type_name.startswith("LPCW") or type_name.startswith("LPCA") or type_name.startswith("LPCSTR") or type_name.startswith("LPCWSTR"):
            return "In"
        
        # Output parameters typically have pointer types with certain patterns
        name_lower = param.name.lower()
        if name_lower.startswith("p") and name_lower[1:2].isupper():
            # Might be output pointer
            pass
        if name_lower.startswith("lp") and ("result" in name_lower or "out" in name_lower or "return" in name_lower):
            return "Out"
        if name_lower.endswith("out") or name_lower.endswith("result"):
            return "Out"
        if name_lower.startswith("lpcb") or name_lower.startswith("pcb"):
            return "InOut"  # Size parameters are often in/out
        
        # Default to In for most parameters
        return "In"


# =============================================================================
# JSON Generator
# =============================================================================

class GhostApiPackGenerator:
    """Generates Ghost API pack JSON from parsed Rohitab data"""
    
    def __init__(self, parser: RohitabParser):
        self.parser = parser
        self.converter = GhostTypeConverter(parser)
    
    def generate(self, module: RohitabModule) -> Dict[str, Any]:
        """Generate Ghost API pack JSON for a module"""
        self.converter.update_module_variables(module)
        
        # Extract module name without .dll extension
        module_name = module.name.lower()
        if module_name.endswith(".dll"):
            pack_id = module_name[:-4]
        else:
            pack_id = module_name
        
        pack = {
            "id": pack_id,
            "name": pack_id,
            "version": "1.0.0",
            "description": f"Windows {pack_id} API definitions (converted from Rohitab API Monitor)",
            "module": module.name,
            "functions": [],
            "structs": [],
            "enums": []
        }
        
        # Convert APIs to functions
        seen_functions: Set[str] = set()
        
        for api in module.apis:
            func = self._convert_api(api, module.name)
            if func and func["name"] not in seen_functions:
                pack["functions"].append(func)
                seen_functions.add(func["name"])
        
        # Extract enums from module variables
        for var_name, var in module.variables.items():
            if var.enum_values or var.flag_values:
                enum_def = self._convert_enum(var)
                if enum_def:
                    pack["enums"].append(enum_def)
        
        return pack
    
    def _convert_api(self, api: RohitabApi, module_name: str) -> Optional[Dict[str, Any]]:
        """Convert a RohitabApi to Ghost function format"""
        if not api.name:
            return None
        
        # Determine category
        category = "General"
        if api.category:
            # Extract last part of category path
            parts = api.category.split("/")
            category = parts[-1] if parts else "General"
        
        func = {
            "name": api.name,
            "module": module_name,
            "category": category,
            "params": [],
            "return_type": self.converter.convert_type(api.return_type)
        }
        
        # Convert parameters
        for param in api.params:
            length_param = param.length or param.post_length
            param_type = self.converter.convert_type(param.type_name, length_param)
            direction = self.converter.infer_direction(param, param.type_name)
            
            # Adjust direction for post_length (output buffers)
            if param.post_length:
                direction = "Out"
            
            func["params"].append({
                "name": param.name,
                "type": param_type,
                "direction": direction
            })
        
        return func
    
    def _convert_enum(self, var: RohitabVariable) -> Optional[Dict[str, Any]]:
        """Convert a variable with enum/flag values to Ghost enum format"""
        values = var.enum_values or var.flag_values
        if not values:
            return None
        
        # Determine base type from variable definition
        base_type = "UInt32"  # Default
        if var.base:
            base_type_map = {
                "DWORD": "UInt32", "UINT": "UInt32", "ULONG": "UInt32",
                "WORD": "UInt16", "USHORT": "UInt16",
                "BYTE": "UInt8", "UCHAR": "UInt8",
                "INT": "Int32", "LONG": "Int32",
                "SHORT": "Int16",
            }
            base_type = base_type_map.get(var.base, "UInt32")
        
        enum_def = {
            "name": var.name.strip("[]"),
            "base_type": base_type,
            "is_flags": bool(var.flag_values),
            "values": []
        }
        
        for val in values:
            value_str = val.get("value", "0")
            # Parse hex or decimal value
            try:
                if value_str.startswith("0x"):
                    int_val = int(value_str, 16)
                else:
                    int_val = int(value_str)
            except ValueError:
                int_val = 0
            
            enum_def["values"].append({
                "name": val.get("name", ""),
                "value": int_val
            })
        
        return enum_def


# =============================================================================
# Main Entry Point
# =============================================================================

def convert_single_file(input_path: str, output_path: str, api_base: str):
    """Convert a single Rohitab XML file to Ghost JSON"""
    parser = RohitabParser(api_base)
    modules = parser.parse_file(input_path)
    
    if not modules:
        print(f"No modules found in {input_path}", file=sys.stderr)
        return False
    
    generator = GhostApiPackGenerator(parser)
    
    # Generate pack for first module (usually one per file)
    pack = generator.generate(modules[0])
    
    # Write JSON output
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(pack, f, indent=2, ensure_ascii=False)
    
    func_count = len(pack["functions"])
    enum_count = len(pack["enums"])
    print(f"Converted {input_path} -> {output_path}")
    print(f"  Module: {pack['module']}")
    print(f"  Functions: {func_count}")
    print(f"  Enums: {enum_count}")
    
    return True


def convert_batch(api_folder: str, output_folder: str, filter_modules: Optional[List[str]] = None):
    """Convert all XML files in a folder to Ghost JSON"""
    api_path = Path(api_folder).resolve()
    output_path = Path(output_folder)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Find all XML files in Windows subfolder
    xml_files = list(api_path.glob("Windows/*.xml"))
    
    if filter_modules:
        filter_set = {m.lower() for m in filter_modules}
        xml_files = [f for f in xml_files if f.stem.lower() in filter_set]
    
    print(f"Found {len(xml_files)} XML files to convert")
    
    success_count = 0
    total_functions = 0
    
    for xml_file in sorted(xml_files):
        output_file = output_path / f"{xml_file.stem.lower()}.json"
        
        try:
            # Use parent of Windows folder as base for includes
            parser = RohitabParser(str(api_path))
            modules = parser.parse_file(str(xml_file))
            
            if modules:
                generator = GhostApiPackGenerator(parser)
                pack = generator.generate(modules[0])
                
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(pack, f, indent=2, ensure_ascii=False)
                
                func_count = len(pack["functions"])
                total_functions += func_count
                print(f"  {xml_file.name} -> {output_file.name} ({func_count} functions)")
                success_count += 1
        except Exception as e:
            print(f"  Error converting {xml_file.name}: {e}", file=sys.stderr)
    
    print(f"\nConversion complete: {success_count}/{len(xml_files)} files")
    print(f"Total functions: {total_functions}")


def main():
    parser = argparse.ArgumentParser(
        description="Convert Rohitab API Monitor XML to Ghost API pack JSON"
    )
    parser.add_argument(
        "--batch", action="store_true",
        help="Batch convert all files in API folder"
    )
    parser.add_argument(
        "--api-base", type=str, default="scripts/API",
        help="Base path for API definitions (default: scripts/API)"
    )
    parser.add_argument(
        "--filter", type=str, nargs="*",
        help="Filter specific modules (e.g., --filter kernel32 user32)"
    )
    parser.add_argument(
        "input", type=str,
        help="Input XML file or API folder (with --batch)"
    )
    parser.add_argument(
        "output", type=str, nargs="?",
        help="Output JSON file or folder (with --batch)"
    )
    
    args = parser.parse_args()
    
    if args.batch:
        output_folder = args.output or "output"
        convert_batch(args.input, output_folder, args.filter)
    else:
        if not args.output:
            # Generate output filename from input
            input_path = Path(args.input)
            args.output = str(input_path.with_suffix(".json"))
        
        convert_single_file(args.input, args.output, args.api_base)


# =============================================================================
# Test and Compare Functions
# =============================================================================

@dataclass
class ComparisonResult:
    """Result of comparing XML source to converted JSON"""
    xml_file: str
    json_file: str
    xml_api_count: int
    json_func_count: int
    matched_apis: List[str]
    missing_in_json: List[str]
    extra_in_json: List[str]
    param_mismatches: List[Dict[str, Any]]
    success: bool


def compare_xml_to_json(xml_path: str, json_path: str, api_base: str = ".") -> ComparisonResult:
    """Compare original XML to converted JSON for 1:1 verification"""
    
    # Parse XML
    parser = RohitabParser(api_base)
    modules = parser.parse_file(xml_path)
    
    if not modules:
        return ComparisonResult(
            xml_file=xml_path,
            json_file=json_path,
            xml_api_count=0,
            json_func_count=0,
            matched_apis=[],
            missing_in_json=["ERROR: Could not parse XML"],
            extra_in_json=[],
            param_mismatches=[],
            success=False
        )
    
    module = modules[0]
    xml_apis = {api.name: api for api in module.apis}
    
    # Load JSON
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            json_pack = json.load(f)
    except Exception as e:
        return ComparisonResult(
            xml_file=xml_path,
            json_file=json_path,
            xml_api_count=len(xml_apis),
            json_func_count=0,
            matched_apis=[],
            missing_in_json=[f"ERROR: Could not load JSON: {e}"],
            extra_in_json=[],
            param_mismatches=[],
            success=False
        )
    
    json_funcs = {func["name"]: func for func in json_pack.get("functions", [])}
    
    # Compare API names
    xml_names = set(xml_apis.keys())
    json_names = set(json_funcs.keys())
    
    matched = xml_names & json_names
    missing_in_json = list(xml_names - json_names)
    extra_in_json = list(json_names - xml_names)
    
    # Compare parameters for matched APIs
    param_mismatches = []
    
    for api_name in matched:
        xml_api = xml_apis[api_name]
        json_func = json_funcs[api_name]
        
        xml_param_count = len(xml_api.params)
        json_param_count = len(json_func.get("params", []))
        
        if xml_param_count != json_param_count:
            param_mismatches.append({
                "api": api_name,
                "issue": "param_count",
                "xml_count": xml_param_count,
                "json_count": json_param_count
            })
            continue
        
        # Compare individual parameters
        for i, (xml_param, json_param) in enumerate(zip(xml_api.params, json_func.get("params", []))):
            if xml_param.name != json_param.get("name"):
                param_mismatches.append({
                    "api": api_name,
                    "issue": "param_name",
                    "param_index": i,
                    "xml_name": xml_param.name,
                    "json_name": json_param.get("name")
                })
    
    success = len(missing_in_json) == 0 and len(param_mismatches) == 0
    
    return ComparisonResult(
        xml_file=xml_path,
        json_file=json_path,
        xml_api_count=len(xml_apis),
        json_func_count=len(json_funcs),
        matched_apis=list(matched),
        missing_in_json=missing_in_json,
        extra_in_json=extra_in_json,
        param_mismatches=param_mismatches,
        success=success
    )


def run_comparison_test(api_folder: str, output_folder: str, filter_modules: Optional[List[str]] = None):
    """Run comparison test on converted files"""
    api_path = Path(api_folder).resolve()
    output_path = Path(output_folder)
    
    xml_files = list(api_path.glob("Windows/*.xml"))
    
    if filter_modules:
        filter_set = {m.lower() for m in filter_modules}
        xml_files = [f for f in xml_files if f.stem.lower() in filter_set]
    
    print(f"\n{'='*60}")
    print("COMPARISON TEST: XML vs JSON")
    print(f"{'='*60}\n")
    
    total_xml_apis = 0
    total_json_funcs = 0
    total_matched = 0
    total_missing = 0
    total_mismatches = 0
    all_results = []
    
    for xml_file in sorted(xml_files):
        json_file = output_path / f"{xml_file.stem.lower()}.json"
        
        if not json_file.exists():
            print(f"⚠️  {xml_file.name}: JSON not found at {json_file}")
            continue
        
        result = compare_xml_to_json(str(xml_file), str(json_file), str(api_path))
        all_results.append(result)
        
        total_xml_apis += result.xml_api_count
        total_json_funcs += result.json_func_count
        total_matched += len(result.matched_apis)
        total_missing += len(result.missing_in_json)
        total_mismatches += len(result.param_mismatches)
        
        # Status indicator
        if result.success:
            status = "✅"
        elif len(result.missing_in_json) > 0:
            status = "⚠️"
        else:
            status = "❌"
        
        match_rate = (len(result.matched_apis) / result.xml_api_count * 100) if result.xml_api_count > 0 else 0
        
        print(f"{status} {xml_file.name}")
        print(f"   XML APIs: {result.xml_api_count} | JSON Funcs: {result.json_func_count} | Matched: {len(result.matched_apis)} ({match_rate:.1f}%)")
        
        if result.missing_in_json and len(result.missing_in_json) <= 5:
            print(f"   Missing: {', '.join(result.missing_in_json[:5])}")
        elif result.missing_in_json:
            print(f"   Missing: {len(result.missing_in_json)} APIs (first 5: {', '.join(result.missing_in_json[:5])}...)")
        
        if result.param_mismatches and len(result.param_mismatches) <= 3:
            for m in result.param_mismatches[:3]:
                print(f"   Param issue: {m['api']} - {m['issue']}")
        elif result.param_mismatches:
            print(f"   Param issues: {len(result.param_mismatches)} (showing first 3)")
            for m in result.param_mismatches[:3]:
                print(f"     {m['api']} - {m['issue']}")
        
        print()
    
    # Summary
    overall_match_rate = (total_matched / total_xml_apis * 100) if total_xml_apis > 0 else 0
    
    print(f"{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    print(f"Total XML APIs:      {total_xml_apis}")
    print(f"Total JSON Functions: {total_json_funcs}")
    print(f"Total Matched:       {total_matched} ({overall_match_rate:.1f}%)")
    print(f"Total Missing:       {total_missing}")
    print(f"Param Mismatches:    {total_mismatches}")
    print(f"{'='*60}\n")
    
    return all_results


def detailed_api_comparison(xml_path: str, json_path: str, api_name: str, api_base: str = "."):
    """Detailed comparison of a specific API between XML and JSON"""
    
    # Parse XML
    parser = RohitabParser(api_base)
    modules = parser.parse_file(xml_path)
    
    if not modules:
        print(f"ERROR: Could not parse XML: {xml_path}")
        return
    
    module = modules[0]
    xml_api = None
    for api in module.apis:
        if api.name == api_name:
            xml_api = api
            break
    
    if not xml_api:
        print(f"ERROR: API '{api_name}' not found in XML")
        return
    
    # Load JSON
    with open(json_path, 'r', encoding='utf-8') as f:
        json_pack = json.load(f)
    
    json_func = None
    for func in json_pack.get("functions", []):
        if func["name"] == api_name:
            json_func = func
            break
    
    if not json_func:
        print(f"ERROR: Function '{api_name}' not found in JSON")
        return
    
    print(f"\n{'='*60}")
    print(f"DETAILED COMPARISON: {api_name}")
    print(f"{'='*60}\n")
    
    print("XML Definition:")
    print(f"  Name: {xml_api.name}")
    print(f"  Return: {xml_api.return_type}")
    print(f"  Category: {xml_api.category}")
    print(f"  Params ({len(xml_api.params)}):")
    for i, p in enumerate(xml_api.params):
        print(f"    [{i}] {p.name}: {p.type_name}")
        if p.length:
            print(f"        Length: {p.length}")
        if p.post_length:
            print(f"        PostLength: {p.post_length}")
    
    print(f"\nJSON Definition:")
    print(f"  Name: {json_func['name']}")
    print(f"  Return: {json.dumps(json_func['return_type'])}")
    print(f"  Category: {json_func.get('category', 'N/A')}")
    print(f"  Params ({len(json_func.get('params', []))}):")
    for i, p in enumerate(json_func.get("params", [])):
        print(f"    [{i}] {p['name']}: {json.dumps(p['type'])} ({p['direction']})")
    
    print(f"\n{'='*60}\n")


def run_tests():
    """Run all test cases"""
    print("\n" + "="*60)
    print("RUNNING CONVERSION TESTS")
    print("="*60 + "\n")
    
    test_cases = [
        # (description, xml_type, expected_ghost_type)
        ("DWORD -> UInt32", "DWORD", {"Primitive": "UInt32"}),
        ("HANDLE -> Handle", "HANDLE", {"Primitive": "Handle"}),
        ("BOOL -> Bool", "BOOL", {"Primitive": "Bool"}),
        ("LPWSTR -> Unicode String", "LPWSTR", {"String": {"encoding": "Unicode", "max_length": 260}}),
        ("LPSTR -> Ansi String", "LPSTR", {"String": {"encoding": "Ansi", "max_length": 260}}),
        ("LPVOID -> Void Pointer", "LPVOID", {"Pointer": {"inner": {"Primitive": "Void"}, "nullable": True}}),
        ("DWORD* -> UInt32 Pointer", "DWORD*", {"Pointer": {"inner": {"Primitive": "UInt32"}, "nullable": True}}),
        ("void -> Void", "void", {"Primitive": "Void"}),
        ("BYTE -> UInt8", "BYTE", {"Primitive": "UInt8"}),
        ("WORD -> UInt16", "WORD", {"Primitive": "UInt16"}),
        ("INT -> Int32", "INT", {"Primitive": "Int32"}),
        ("UINT64 -> UInt64", "UINT64", {"Primitive": "UInt64"}),
        ("HMODULE -> Handle", "HMODULE", {"Primitive": "Handle"}),
        ("HWND -> Handle", "HWND", {"Primitive": "Handle"}),
        ("SOCKET -> Handle", "SOCKET", {"Primitive": "Handle"}),
        ("NTSTATUS -> Int32", "NTSTATUS", {"Primitive": "Int32"}),
        ("HRESULT -> Int32", "HRESULT", {"Primitive": "Int32"}),
    ]
    
    # Create a dummy parser for type conversion tests
    parser = RohitabParser(".")
    converter = GhostTypeConverter(parser)
    
    passed = 0
    failed = 0
    
    for desc, rohitab_type, expected in test_cases:
        result = converter.convert_type(rohitab_type)
        
        if result == expected:
            print(f"  ✅ {desc}")
            passed += 1
        else:
            print(f"  ❌ {desc}")
            print(f"      Expected: {expected}")
            print(f"      Got:      {result}")
            failed += 1
    
    print(f"\nType Conversion Tests: {passed} passed, {failed} failed")
    print("="*60 + "\n")
    
    return failed == 0


def main():
    parser = argparse.ArgumentParser(
        description="Convert Rohitab API Monitor XML to Ghost API pack JSON"
    )
    parser.add_argument(
        "--batch", action="store_true",
        help="Batch convert all files in API folder"
    )
    parser.add_argument(
        "--test", action="store_true",
        help="Run type conversion tests"
    )
    parser.add_argument(
        "--compare", action="store_true",
        help="Compare XML to converted JSON for verification"
    )
    parser.add_argument(
        "--detail", type=str,
        help="Show detailed comparison for a specific API name"
    )
    parser.add_argument(
        "--api-base", type=str, default="scripts/API",
        help="Base path for API definitions (default: scripts/API)"
    )
    parser.add_argument(
        "--filter", type=str, nargs="*",
        help="Filter specific modules (e.g., --filter kernel32 user32)"
    )
    parser.add_argument(
        "input", type=str, nargs="?",
        help="Input XML file or API folder (with --batch)"
    )
    parser.add_argument(
        "output", type=str, nargs="?",
        help="Output JSON file or folder (with --batch)"
    )
    
    args = parser.parse_args()
    
    # Run tests
    if args.test:
        success = run_tests()
        sys.exit(0 if success else 1)
    
    # Run comparison
    if args.compare:
        if not args.input or not args.output:
            print("Error: --compare requires input (API folder) and output (JSON folder)")
            sys.exit(1)
        
        if args.detail:
            # Detailed comparison for specific API
            api_path = Path(args.input).resolve()
            xml_files = list(api_path.glob("Windows/*.xml"))
            if args.filter:
                filter_set = {m.lower() for m in args.filter}
                xml_files = [f for f in xml_files if f.stem.lower() in filter_set]
            
            for xml_file in xml_files:
                json_file = Path(args.output) / f"{xml_file.stem.lower()}.json"
                if json_file.exists():
                    detailed_api_comparison(str(xml_file), str(json_file), args.detail, str(api_path))
        else:
            run_comparison_test(args.input, args.output, args.filter)
        sys.exit(0)
    
    # Normal conversion
    if not args.input:
        parser.print_help()
        sys.exit(1)
    
    if args.batch:
        output_folder = args.output or "output"
        convert_batch(args.input, output_folder, args.filter)
    else:
        if not args.output:
            # Generate output filename from input
            input_path = Path(args.input)
            args.output = str(input_path.with_suffix(".json"))
        
        convert_single_file(args.input, args.output, args.api_base)


if __name__ == "__main__":
    main()
