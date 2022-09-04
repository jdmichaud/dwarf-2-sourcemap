"use strict";
const textDecoder = new TextDecoder();
function toHexPrint(n) {
    return `0x${n.toString(16).padStart(8, '0')}`;
}
// Target machine (wasm) is 32 bits.
// ⚠️ This implementation does not use this variable consistently.
// TODO: Systematically us is_32 when required.
const is_32 = true;
// ------------ utils.ts
function toLEB128(n) {
    const bytes = [];
    do {
        let byte = n & 0x7F;
        n >>= 7;
        if (n != 0) /* more bytes to come */
            byte |= 0x80;
        bytes.push(byte);
    } while (n != 0);
    return new Uint8Array(bytes);
}
function get8bytes(buf, pos) {
    return buf[pos] |
        buf[pos + 1] << 8 |
        buf[pos + 2] << 16 |
        buf[pos + 3] << 24 |
        buf[pos + 4] << 32 |
        buf[pos + 5] << 40 |
        buf[pos + 6] << 48 |
        buf[pos + 7] << 56;
}
function get4bytes(buf, pos) {
    return buf[pos] |
        buf[pos + 1] << 8 |
        buf[pos + 2] << 16 |
        buf[pos + 3] << 24;
}
function get2bytes(buf, pos) {
    return buf[pos] |
        buf[pos + 1] << 8;
}
// Variable size unsigned LEB128
function getLEB128(buffer, pos) {
    let value = 0;
    let shift = 0;
    while (true) {
        const byte = buffer[pos++];
        value |= ((byte & 0x7F) << shift);
        if ((byte & 0x80) === 0)
            break;
        shift += 7;
    }
    return { value, pos };
}
// Variable size signed LEB128 to 64 bits
function getsLEB128(buffer, pos) {
    let value = 0;
    let shift = 0;
    while (true) {
        const byte = buffer[pos++];
        value |= (byte & 0x7f) << shift;
        shift += 7;
        if ((0x80 & byte) === 0) {
            if (shift < 64 && (byte & 0x40) !== 0) {
                return { value: value | (~0 << shift), pos };
            }
            return { value, pos };
        }
    }
}
// Get a null terminated string in buffer starting at pos
function getString(buffer, pos) {
    let end = pos;
    while (buffer[end] !== 0)
        ++end;
    return {
        value: textDecoder.decode(buffer.subarray(pos, end)),
        pos: end + 1,
    };
}
// From wasm-sourcemap.py
function toVLQ(n) {
    const VLQ_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    n = n | 0;
    let x = n >= 0 ? (n << 1) : ((-n << 1) + 1);
    let result = "";
    while (x > 31) {
        result = `${result}${VLQ_CHARS[32 + (x & 31)]}`;
        x = x >> 5;
    }
    return `${result}${VLQ_CHARS[x]}`;
}
function isAbsolute(path) {
    // ⚠️⚠️⚠️ Only manage unix style file path for now
    return path[0] === '/';
}
// ------------ end of utils.ts
// ------------ wasm.ts
var WasmSectionType;
(function (WasmSectionType) {
    WasmSectionType[WasmSectionType["custom"] = 0] = "custom";
    WasmSectionType[WasmSectionType["type"] = 1] = "type";
    WasmSectionType[WasmSectionType["import"] = 2] = "import";
    WasmSectionType[WasmSectionType["function"] = 3] = "function";
    WasmSectionType[WasmSectionType["table"] = 4] = "table";
    WasmSectionType[WasmSectionType["memory"] = 5] = "memory";
    WasmSectionType[WasmSectionType["global"] = 6] = "global";
    WasmSectionType[WasmSectionType["export"] = 7] = "export";
    WasmSectionType[WasmSectionType["start"] = 8] = "start";
    WasmSectionType[WasmSectionType["element"] = 9] = "element";
    WasmSectionType[WasmSectionType["code"] = 10] = "code";
    WasmSectionType[WasmSectionType["data"] = 11] = "data";
    WasmSectionType[WasmSectionType["data2"] = 12] = "data2";
})(WasmSectionType || (WasmSectionType = {}));
class Section {
    id;
    start;
    size;
    constructor(id, 
    // start is the position right after the size of the section.
    start, 
    // Size of the section minus the id and size itself.
    // start + size = next byte after the section.
    size) {
        this.id = id;
        this.start = start;
        this.size = size;
    }
}
class CustomSection {
    id;
    name;
    start;
    size;
    constructor(id, name, 
    // start is the position right after the name of the custom section.
    start, 
    // Size of the section minus the id, size itself, the size of the name and the name.
    // start + size = next byte after the section.
    size) {
        this.id = id;
        this.name = name;
        this.start = start;
        this.size = size;
    }
}
// ------------ end of wasm.ts
// ------------ dwarf.ts
var TagType;
(function (TagType) {
    TagType[TagType["DW_TAG_array_type"] = 1] = "DW_TAG_array_type";
    TagType[TagType["DW_TAG_class_type"] = 2] = "DW_TAG_class_type";
    TagType[TagType["DW_TAG_entry_point"] = 3] = "DW_TAG_entry_point";
    TagType[TagType["DW_TAG_enumeration_type"] = 4] = "DW_TAG_enumeration_type";
    TagType[TagType["DW_TAG_formal_parameter"] = 5] = "DW_TAG_formal_parameter";
    TagType[TagType["DW_TAG_imported_declaration"] = 8] = "DW_TAG_imported_declaration";
    TagType[TagType["DW_TAG_label"] = 10] = "DW_TAG_label";
    TagType[TagType["DW_TAG_lexical_block"] = 11] = "DW_TAG_lexical_block";
    TagType[TagType["DW_TAG_member"] = 13] = "DW_TAG_member";
    TagType[TagType["DW_TAG_pointer_type"] = 15] = "DW_TAG_pointer_type";
    TagType[TagType["DW_TAG_reference_type"] = 16] = "DW_TAG_reference_type";
    TagType[TagType["DW_TAG_compile_unit"] = 17] = "DW_TAG_compile_unit";
    TagType[TagType["DW_TAG_string_type"] = 18] = "DW_TAG_string_type";
    TagType[TagType["DW_TAG_structure_type"] = 19] = "DW_TAG_structure_type";
    TagType[TagType["DW_TAG_subroutine_type"] = 21] = "DW_TAG_subroutine_type";
    TagType[TagType["DW_TAG_typedef"] = 22] = "DW_TAG_typedef";
    TagType[TagType["DW_TAG_union_type"] = 23] = "DW_TAG_union_type";
    TagType[TagType["DW_TAG_unspecified_parameters"] = 24] = "DW_TAG_unspecified_parameters";
    TagType[TagType["DW_TAG_variant"] = 25] = "DW_TAG_variant";
    TagType[TagType["DW_TAG_common_block"] = 26] = "DW_TAG_common_block";
    TagType[TagType["DW_TAG_common_inclusion"] = 27] = "DW_TAG_common_inclusion";
    TagType[TagType["DW_TAG_inheritance"] = 28] = "DW_TAG_inheritance";
    TagType[TagType["DW_TAG_inlined_subroutine"] = 29] = "DW_TAG_inlined_subroutine";
    TagType[TagType["DW_TAG_module"] = 30] = "DW_TAG_module";
    TagType[TagType["DW_TAG_ptr_to_member_type"] = 31] = "DW_TAG_ptr_to_member_type";
    TagType[TagType["DW_TAG_set_type"] = 32] = "DW_TAG_set_type";
    TagType[TagType["DW_TAG_subrange_type"] = 33] = "DW_TAG_subrange_type";
    TagType[TagType["DW_TAG_with_stmt"] = 34] = "DW_TAG_with_stmt";
    TagType[TagType["DW_TAG_access_declaration"] = 35] = "DW_TAG_access_declaration";
    TagType[TagType["DW_TAG_base_type"] = 36] = "DW_TAG_base_type";
    TagType[TagType["DW_TAG_catch_block"] = 37] = "DW_TAG_catch_block";
    TagType[TagType["DW_TAG_const_type"] = 38] = "DW_TAG_const_type";
    TagType[TagType["DW_TAG_constant"] = 39] = "DW_TAG_constant";
    TagType[TagType["DW_TAG_enumerator"] = 40] = "DW_TAG_enumerator";
    TagType[TagType["DW_TAG_file_type"] = 41] = "DW_TAG_file_type";
    TagType[TagType["DW_TAG_friend"] = 42] = "DW_TAG_friend";
    TagType[TagType["DW_TAG_namelist"] = 43] = "DW_TAG_namelist";
    TagType[TagType["DW_TAG_namelist_item"] = 44] = "DW_TAG_namelist_item";
    TagType[TagType["DW_TAG_packed_type"] = 45] = "DW_TAG_packed_type";
    TagType[TagType["DW_TAG_subprogram"] = 46] = "DW_TAG_subprogram";
    TagType[TagType["DW_TAG_template_type_param"] = 47] = "DW_TAG_template_type_param";
    TagType[TagType["DW_TAG_template_value_param"] = 48] = "DW_TAG_template_value_param";
    TagType[TagType["DW_TAG_thrown_type"] = 49] = "DW_TAG_thrown_type";
    TagType[TagType["DW_TAG_try_block"] = 50] = "DW_TAG_try_block";
    TagType[TagType["DW_TAG_variant_part"] = 51] = "DW_TAG_variant_part";
    TagType[TagType["DW_TAG_variable"] = 52] = "DW_TAG_variable";
    TagType[TagType["DW_TAG_volatile_type"] = 53] = "DW_TAG_volatile_type";
    TagType[TagType["DW_TAG_lo_user"] = 16512] = "DW_TAG_lo_user";
    TagType[TagType["DW_TAG_hi_user"] = 65535] = "DW_TAG_hi_user";
})(TagType || (TagType = {}));
var AttributeEncoding;
(function (AttributeEncoding) {
    AttributeEncoding[AttributeEncoding["DW_AT_sibling"] = 1] = "DW_AT_sibling";
    AttributeEncoding[AttributeEncoding["DW_AT_location"] = 2] = "DW_AT_location";
    AttributeEncoding[AttributeEncoding["DW_AT_name"] = 3] = "DW_AT_name";
    AttributeEncoding[AttributeEncoding["DW_AT_ordering"] = 9] = "DW_AT_ordering";
    AttributeEncoding[AttributeEncoding["DW_AT_byte_size"] = 11] = "DW_AT_byte_size";
    AttributeEncoding[AttributeEncoding["DW_AT_bit_offset"] = 12] = "DW_AT_bit_offset";
    AttributeEncoding[AttributeEncoding["DW_AT_bit_size"] = 13] = "DW_AT_bit_size";
    AttributeEncoding[AttributeEncoding["DW_AT_stmt_list"] = 16] = "DW_AT_stmt_list";
    AttributeEncoding[AttributeEncoding["DW_AT_low_pc"] = 17] = "DW_AT_low_pc";
    AttributeEncoding[AttributeEncoding["DW_AT_high_pc"] = 18] = "DW_AT_high_pc";
    AttributeEncoding[AttributeEncoding["DW_AT_language"] = 19] = "DW_AT_language";
    AttributeEncoding[AttributeEncoding["DW_AT_discr"] = 21] = "DW_AT_discr";
    AttributeEncoding[AttributeEncoding["DW_AT_discr_value"] = 22] = "DW_AT_discr_value";
    AttributeEncoding[AttributeEncoding["DW_AT_visibility"] = 23] = "DW_AT_visibility";
    AttributeEncoding[AttributeEncoding["DW_AT_import"] = 24] = "DW_AT_import";
    AttributeEncoding[AttributeEncoding["DW_AT_string_length"] = 25] = "DW_AT_string_length";
    AttributeEncoding[AttributeEncoding["DW_AT_common_reference"] = 26] = "DW_AT_common_reference";
    AttributeEncoding[AttributeEncoding["DW_AT_comp_dir"] = 27] = "DW_AT_comp_dir";
    AttributeEncoding[AttributeEncoding["DW_AT_const_value"] = 28] = "DW_AT_const_value";
    AttributeEncoding[AttributeEncoding["DW_AT_containing_type"] = 29] = "DW_AT_containing_type";
    AttributeEncoding[AttributeEncoding["DW_AT_default_value"] = 30] = "DW_AT_default_value";
    AttributeEncoding[AttributeEncoding["DW_AT_inline"] = 32] = "DW_AT_inline";
    AttributeEncoding[AttributeEncoding["DW_AT_is_optional"] = 33] = "DW_AT_is_optional";
    AttributeEncoding[AttributeEncoding["DW_AT_lower_bound"] = 34] = "DW_AT_lower_bound";
    AttributeEncoding[AttributeEncoding["DW_AT_producer"] = 37] = "DW_AT_producer";
    AttributeEncoding[AttributeEncoding["DW_AT_prototyped"] = 39] = "DW_AT_prototyped";
    AttributeEncoding[AttributeEncoding["DW_AT_return_addr"] = 42] = "DW_AT_return_addr";
    AttributeEncoding[AttributeEncoding["DW_AT_start_scope"] = 44] = "DW_AT_start_scope";
    AttributeEncoding[AttributeEncoding["DW_AT_bit_stride"] = 46] = "DW_AT_bit_stride";
    AttributeEncoding[AttributeEncoding["DW_AT_upper_bound"] = 47] = "DW_AT_upper_bound";
    AttributeEncoding[AttributeEncoding["DW_AT_abstract_origin"] = 49] = "DW_AT_abstract_origin";
    AttributeEncoding[AttributeEncoding["DW_AT_accessibility"] = 50] = "DW_AT_accessibility";
    AttributeEncoding[AttributeEncoding["DW_AT_address_class"] = 51] = "DW_AT_address_class";
    AttributeEncoding[AttributeEncoding["DW_AT_artificial"] = 52] = "DW_AT_artificial";
    AttributeEncoding[AttributeEncoding["DW_AT_base_types"] = 53] = "DW_AT_base_types";
    AttributeEncoding[AttributeEncoding["DW_AT_calling_convention"] = 54] = "DW_AT_calling_convention";
    AttributeEncoding[AttributeEncoding["DW_AT_count"] = 55] = "DW_AT_count";
    AttributeEncoding[AttributeEncoding["DW_AT_data_member_location"] = 56] = "DW_AT_data_member_location";
    AttributeEncoding[AttributeEncoding["DW_AT_decl_column"] = 57] = "DW_AT_decl_column";
    AttributeEncoding[AttributeEncoding["DW_AT_decl_file"] = 58] = "DW_AT_decl_file";
    AttributeEncoding[AttributeEncoding["DW_AT_decl_line"] = 59] = "DW_AT_decl_line";
    AttributeEncoding[AttributeEncoding["DW_AT_declaration"] = 60] = "DW_AT_declaration";
    AttributeEncoding[AttributeEncoding["DW_AT_discr_list"] = 61] = "DW_AT_discr_list";
    AttributeEncoding[AttributeEncoding["DW_AT_encoding"] = 62] = "DW_AT_encoding";
    AttributeEncoding[AttributeEncoding["DW_AT_external"] = 63] = "DW_AT_external";
    AttributeEncoding[AttributeEncoding["DW_AT_frame_base"] = 64] = "DW_AT_frame_base";
    AttributeEncoding[AttributeEncoding["DW_AT_friend"] = 65] = "DW_AT_friend";
    AttributeEncoding[AttributeEncoding["DW_AT_identifier_case"] = 66] = "DW_AT_identifier_case";
    AttributeEncoding[AttributeEncoding["DW_AT_macro_info"] = 67] = "DW_AT_macro_info";
    AttributeEncoding[AttributeEncoding["DW_AT_namelist_item"] = 68] = "DW_AT_namelist_item";
    AttributeEncoding[AttributeEncoding["DW_AT_priority"] = 69] = "DW_AT_priority";
    AttributeEncoding[AttributeEncoding["DW_AT_segment"] = 70] = "DW_AT_segment";
    AttributeEncoding[AttributeEncoding["DW_AT_specification"] = 71] = "DW_AT_specification";
    AttributeEncoding[AttributeEncoding["DW_AT_static_link"] = 72] = "DW_AT_static_link";
    AttributeEncoding[AttributeEncoding["DW_AT_type"] = 73] = "DW_AT_type";
    AttributeEncoding[AttributeEncoding["DW_AT_use_location"] = 74] = "DW_AT_use_location";
    AttributeEncoding[AttributeEncoding["DW_AT_variable_parameter"] = 75] = "DW_AT_variable_parameter";
    AttributeEncoding[AttributeEncoding["DW_AT_virtuality"] = 76] = "DW_AT_virtuality";
    AttributeEncoding[AttributeEncoding["DW_AT_vtable_elem_location"] = 77] = "DW_AT_vtable_elem_location";
    AttributeEncoding[AttributeEncoding["DW_AT_allocated"] = 78] = "DW_AT_allocated";
    AttributeEncoding[AttributeEncoding["DW_AT_associated"] = 79] = "DW_AT_associated";
    AttributeEncoding[AttributeEncoding["DW_AT_data_location"] = 80] = "DW_AT_data_location";
    AttributeEncoding[AttributeEncoding["DW_AT_byte_stride"] = 81] = "DW_AT_byte_stride";
    AttributeEncoding[AttributeEncoding["DW_AT_entry_pc"] = 82] = "DW_AT_entry_pc";
    AttributeEncoding[AttributeEncoding["DW_AT_use_UTF8"] = 83] = "DW_AT_use_UTF8";
    AttributeEncoding[AttributeEncoding["DW_AT_extension"] = 84] = "DW_AT_extension";
    AttributeEncoding[AttributeEncoding["DW_AT_ranges"] = 85] = "DW_AT_ranges";
    AttributeEncoding[AttributeEncoding["DW_AT_trampoline"] = 86] = "DW_AT_trampoline";
    AttributeEncoding[AttributeEncoding["DW_AT_call_column"] = 87] = "DW_AT_call_column";
    AttributeEncoding[AttributeEncoding["DW_AT_call_file"] = 88] = "DW_AT_call_file";
    AttributeEncoding[AttributeEncoding["DW_AT_call_line"] = 89] = "DW_AT_call_line";
    AttributeEncoding[AttributeEncoding["DW_AT_description"] = 90] = "DW_AT_description";
    AttributeEncoding[AttributeEncoding["DW_AT_binary_scale"] = 91] = "DW_AT_binary_scale";
    AttributeEncoding[AttributeEncoding["DW_AT_decimal_scale"] = 92] = "DW_AT_decimal_scale";
    AttributeEncoding[AttributeEncoding["DW_AT_small"] = 93] = "DW_AT_small";
    AttributeEncoding[AttributeEncoding["DW_AT_decimal_sign"] = 94] = "DW_AT_decimal_sign";
    AttributeEncoding[AttributeEncoding["DW_AT_digit_count"] = 95] = "DW_AT_digit_count";
    AttributeEncoding[AttributeEncoding["DW_AT_picture_string"] = 96] = "DW_AT_picture_string";
    AttributeEncoding[AttributeEncoding["DW_AT_mutable"] = 97] = "DW_AT_mutable";
    AttributeEncoding[AttributeEncoding["DW_AT_threads_scaled"] = 98] = "DW_AT_threads_scaled";
    AttributeEncoding[AttributeEncoding["DW_AT_explicit"] = 99] = "DW_AT_explicit";
    AttributeEncoding[AttributeEncoding["DW_AT_object_pointer"] = 100] = "DW_AT_object_pointer";
    AttributeEncoding[AttributeEncoding["DW_AT_endianity"] = 101] = "DW_AT_endianity";
    AttributeEncoding[AttributeEncoding["DW_AT_elemental"] = 102] = "DW_AT_elemental";
    AttributeEncoding[AttributeEncoding["DW_AT_pure"] = 103] = "DW_AT_pure";
    AttributeEncoding[AttributeEncoding["DW_AT_recursive"] = 104] = "DW_AT_recursive";
    AttributeEncoding[AttributeEncoding["DW_AT_signature"] = 105] = "DW_AT_signature";
    AttributeEncoding[AttributeEncoding["DW_AT_main_subprogram"] = 106] = "DW_AT_main_subprogram";
    AttributeEncoding[AttributeEncoding["DW_AT_data_bit_offset"] = 107] = "DW_AT_data_bit_offset";
    AttributeEncoding[AttributeEncoding["DW_AT_const_expr"] = 108] = "DW_AT_const_expr";
    AttributeEncoding[AttributeEncoding["DW_AT_enum_class"] = 109] = "DW_AT_enum_class";
    AttributeEncoding[AttributeEncoding["DW_AT_linkage_name"] = 110] = "DW_AT_linkage_name";
    AttributeEncoding[AttributeEncoding["DW_AT_lo_user"] = 8192] = "DW_AT_lo_user";
    AttributeEncoding[AttributeEncoding["DW_AT_hi_user"] = 16383] = "DW_AT_hi_user";
    AttributeEncoding[AttributeEncoding["DW_AT_GNU_pubnames"] = 8500] = "DW_AT_GNU_pubnames";
})(AttributeEncoding || (AttributeEncoding = {}));
var FormType;
(function (FormType) {
    FormType[FormType["DW_FORM_addr"] = 1] = "DW_FORM_addr";
    FormType[FormType["DW_FORM_block2"] = 3] = "DW_FORM_block2";
    FormType[FormType["DW_FORM_block4"] = 4] = "DW_FORM_block4";
    FormType[FormType["DW_FORM_data2"] = 5] = "DW_FORM_data2";
    FormType[FormType["DW_FORM_data4"] = 6] = "DW_FORM_data4";
    FormType[FormType["DW_FORM_data8"] = 7] = "DW_FORM_data8";
    FormType[FormType["DW_FORM_string"] = 8] = "DW_FORM_string";
    FormType[FormType["DW_FORM_block"] = 9] = "DW_FORM_block";
    FormType[FormType["DW_FORM_block1"] = 10] = "DW_FORM_block1";
    FormType[FormType["DW_FORM_data1"] = 11] = "DW_FORM_data1";
    FormType[FormType["DW_FORM_flag"] = 12] = "DW_FORM_flag";
    FormType[FormType["DW_FORM_sdata"] = 13] = "DW_FORM_sdata";
    FormType[FormType["DW_FORM_strp"] = 14] = "DW_FORM_strp";
    FormType[FormType["DW_FORM_udata"] = 15] = "DW_FORM_udata";
    FormType[FormType["DW_FORM_ref_addr"] = 16] = "DW_FORM_ref_addr";
    FormType[FormType["DW_FORM_ref1"] = 17] = "DW_FORM_ref1";
    FormType[FormType["DW_FORM_ref2"] = 18] = "DW_FORM_ref2";
    FormType[FormType["DW_FORM_ref4"] = 19] = "DW_FORM_ref4";
    FormType[FormType["DW_FORM_ref8"] = 20] = "DW_FORM_ref8";
    FormType[FormType["DW_FORM_ref_udata"] = 21] = "DW_FORM_ref_udata";
    FormType[FormType["DW_FORM_indirect"] = 22] = "DW_FORM_indirect";
    FormType[FormType["DW_FORM_sec_offset"] = 23] = "DW_FORM_sec_offset";
    FormType[FormType["DW_FORM_exprloc"] = 24] = "DW_FORM_exprloc";
    FormType[FormType["DW_FORM_flag_present"] = 25] = "DW_FORM_flag_present";
    FormType[FormType["DW_FORM_ref_sig8"] = 32] = "DW_FORM_ref_sig8";
})(FormType || (FormType = {}));
var Opcode;
(function (Opcode) {
    Opcode[Opcode["DW_LNS_extended_op"] = 0] = "DW_LNS_extended_op";
    Opcode[Opcode["DW_LNS_copy"] = 1] = "DW_LNS_copy";
    Opcode[Opcode["DW_LNS_advance_pc"] = 2] = "DW_LNS_advance_pc";
    Opcode[Opcode["DW_LNS_advance_line"] = 3] = "DW_LNS_advance_line";
    Opcode[Opcode["DW_LNS_set_file"] = 4] = "DW_LNS_set_file";
    Opcode[Opcode["DW_LNS_set_column"] = 5] = "DW_LNS_set_column";
    Opcode[Opcode["DW_LNS_negate_stmt"] = 6] = "DW_LNS_negate_stmt";
    Opcode[Opcode["DW_LNS_set_basic_block"] = 7] = "DW_LNS_set_basic_block";
    Opcode[Opcode["DW_LNS_const_add_pc"] = 8] = "DW_LNS_const_add_pc";
    Opcode[Opcode["DW_LNS_fixed_advance_pc"] = 9] = "DW_LNS_fixed_advance_pc";
    Opcode[Opcode["DW_LNS_set_prologue_end"] = 10] = "DW_LNS_set_prologue_end";
    Opcode[Opcode["DW_LNS_set_epilogue_begin"] = 11] = "DW_LNS_set_epilogue_begin";
    Opcode[Opcode["DW_LNS_set_isa"] = 12] = "DW_LNS_set_isa";
})(Opcode || (Opcode = {}));
var ExtOpcode;
(function (ExtOpcode) {
    ExtOpcode[ExtOpcode["DW_LNE_end_sequence"] = 1] = "DW_LNE_end_sequence";
    ExtOpcode[ExtOpcode["DW_LNE_set_address"] = 2] = "DW_LNE_set_address";
    ExtOpcode[ExtOpcode["DW_LNE_define_file"] = 3] = "DW_LNE_define_file";
    ExtOpcode[ExtOpcode["DW_LNE_set_discriminator"] = 4] = "DW_LNE_set_discriminator";
})(ExtOpcode || (ExtOpcode = {}));
function getAbbreviationTable(buffer, abbrevTableSection) {
    const abbreviationTable = {};
    let pos = abbrevTableSection.start;
    while (pos < abbrevTableSection.start + abbrevTableSection.size) {
        // Abbrev code as unsigned LEB128
        const { value: abbrevCode, pos: endAbbrevCodePos } = getLEB128(buffer, pos);
        pos = endAbbrevCodePos;
        // Tag as unsigned LEB128
        const { value: tag, pos: endTagPos } = getLEB128(buffer, pos);
        pos = endTagPos;
        // DW_Children on 1 byte
        const hasChildren = buffer[pos++] === 1;
        // Retrieve the attributes
        const attributes = [];
        let endOfattributes;
        do {
            // TagName as unsigned LEB128
            const { value: name, pos: endnamePos } = getLEB128(buffer, pos);
            pos = endnamePos;
            // TagForm as unsigned LEB128
            const { value: form, pos: endFormPos } = getLEB128(buffer, pos);
            pos = endFormPos;
            endOfattributes = name === 0 || form === 0;
            if (!endOfattributes) {
                attributes.push({ name, form });
            }
        } while (!endOfattributes);
        abbreviationTable[abbrevCode] = {
            tag,
            hasChildren,
            attributes,
        };
    }
    return abbreviationTable;
}
// Get the Debug Information Entries
function getDIEs(buffer, pos, infoSection, abbreviationTable, stringBuffer) {
    const dies = [[]];
    while (pos < infoSection.start + infoSection.size) {
        const address = pos - infoSection.start;
        // Get the abbreviation code
        const { value: abbrevCode, pos: endAbbrevCodePos } = getLEB128(buffer, pos);
        pos = endAbbrevCodePos;
        if (abbrevCode === 0) {
            // We end a sibling run, so we pop the current DIE and start appending
            // to its parent again.
            dies.pop();
            continue;
        }
        // ... interpret the code according to the tagForm
        const abbreviationEntry = abbreviationTable[abbrevCode];
        const fields = {};
        for (const attribute of abbreviationEntry.attributes) {
            // DWARF4.pdf 7.5.4 Attribute Encoding
            switch (attribute.form) {
                case FormType.DW_FORM_strp: { // an offset to a null terminated string in the .debug_str section
                    const offset = get4bytes(buffer, pos);
                    pos += 4;
                    const { value: str } = getString(stringBuffer, offset);
                    fields[AttributeEncoding[attribute.name]] = str;
                    break;
                }
                case FormType.DW_FORM_data1: // a a bytes constant
                case FormType.DW_FORM_ref1: { // a 1 byte reference to another DIE
                    const data = buffer[pos++];
                    fields[AttributeEncoding[attribute.name]] = data;
                    break;
                }
                case FormType.DW_FORM_data2: // a 2 bytes constant
                case FormType.DW_FORM_ref2: { // a 2 bytes reference to another DIE
                    const data = get2bytes(buffer, pos);
                    pos += 2;
                    fields[AttributeEncoding[attribute.name]] = data;
                    break;
                }
                case FormType.DW_FORM_data4: // a 4 bytes constant
                case FormType.DW_FORM_ref4: { // a 4 bytes reference to another DIE
                    const data = get4bytes(buffer, pos);
                    pos += 4;
                    fields[AttributeEncoding[attribute.name]] = data;
                    break;
                }
                case FormType.DW_FORM_udata: // an unsigned LEB128 constant
                case FormType.DW_FORM_ref_udata: { // an unsigned LEB128 reference to another DIE
                    const { value: data, pos: endPos } = getLEB128(buffer, pos);
                    pos = endPos;
                    fields[AttributeEncoding[attribute.name]] = data;
                    break;
                }
                case FormType.DW_FORM_sec_offset: { // an address to somewhere...
                    const offset = get4bytes(buffer, pos);
                    pos += 4;
                    fields[AttributeEncoding[attribute.name]] = offset;
                    break;
                }
                case FormType.DW_FORM_flag_present: { // an indication that the field is present
                    fields[AttributeEncoding[attribute.name]] = true;
                    break;
                }
                case FormType.DW_FORM_addr: { // an indication that the field is present
                    const addr = get4bytes(buffer, pos);
                    pos += 4;
                    fields[AttributeEncoding[attribute.name]] = addr;
                    break;
                }
                case FormType.DW_FORM_exprloc: {
                    const { value: length, pos: endPos } = getLEB128(buffer, pos);
                    pos = endPos;
                    fields[AttributeEncoding[attribute.name]] = buffer.slice(pos, pos + length);
                    pos += length;
                    break;
                }
                default:
                    throw new Error(`Unknown AT encoding ${attribute.form} (${FormType[attribute.form]})`);
            }
        }
        const die = {
            address,
            abbrevCode,
            hasChildren: abbreviationEntry.hasChildren,
            ...fields,
            dies: [],
        };
        dies[dies.length - 1].push(die);
        if (die.hasChildren) {
            // This DIE has children so all the subsequence DIE will be its
            // children until an abbevCode of 0.
            dies.push(die.dies);
        }
    }
    if (dies.length !== 1) {
        throw new Error('Inconsistent ordering of DIE');
    }
    return dies[0];
}
// https://dwarfstd.org/doc/dwarf-2.0.0.pdf (7.5 Format of Debugging Information)
// https://dwarfstd.org/doc/DWARF4.pdf (7.5.1.1 Format of Debugging Information)
function getCompilationUnits(buffer, infoSection, abbreviationTable, stringBuffer) {
    const { size: sectionSize, start } = infoSection;
    // Read the compilation unit header
    let pos = start;
    const compilationUnits = [];
    while (pos < start + sectionSize) {
        const start = pos;
        // Compilation unit length on 4 bytes
        const unitLength = get4bytes(buffer, pos);
        pos += 4;
        // Version on 2 bytes
        const version = get2bytes(buffer, pos);
        pos += 2;
        // Offset in the abbreviation table on 4 bytes
        const abbrevOffset = get4bytes(buffer, pos);
        pos += 4;
        // Address size on 1 byte
        const addressSize = buffer[pos++];
        // Get the Debug Information Entries (DIEs)
        const dies = getDIEs(buffer, pos, infoSection, abbreviationTable, stringBuffer);
        compilationUnits.push({
            start,
            unitLength,
            abbrevOffset,
            addressSize,
            dies,
        });
        // Nove to next compilation unit
        pos += unitLength - 7;
    }
    return compilationUnits;
}
function getLineNumberInfo(buffer, lineSection, cu) {
    function appendRow(stateMachine, matrix) {
        const { address, line, column, file, isa, discriminator, isStmt, basicBlock, endSequence, prologueEnd, epilogueBegin } = stateMachine;
        matrix.push({
            address,
            line,
            column,
            file,
            isa,
            discriminator,
            isStmt,
            basicBlock,
            endSequence,
            prologueEnd,
            epilogueBegin
        });
    }
    function advanceAddress(stateMachine, lineNumberProgramHeader, opcode) {
        // DWARF4.pdf 6.2.5.1 Special opcodes
        const adjustedOpcode = opcode - lineNumberProgramHeader.opcodeBase;
        const operationAdvance = adjustedOpcode / lineNumberProgramHeader.lineRange | 0;
        // 1. Add a signed integer to the line register.
        stateMachine.line += lineNumberProgramHeader.lineBase +
            (adjustedOpcode % lineNumberProgramHeader.lineRange);
        // 2. Modify the operation pointer by incrementing the address and op_index registers
        stateMachine.address += lineNumberProgramHeader.minimumInstructionLength *
            (((stateMachine.opIndex + operationAdvance) /
                lineNumberProgramHeader.maximumOperationsPerInstruction) | 0);
        stateMachine.opIndex += (stateMachine.opIndex + operationAdvance) %
            lineNumberProgramHeader.maximumOperationsPerInstruction;
    }
    function resetStateMachine(stateMachine, defaultIsStmt) {
        stateMachine.address = 0;
        stateMachine.opIndex = 0;
        stateMachine.file = 1;
        stateMachine.line = 1;
        stateMachine.column = 0;
        stateMachine.isStmt = defaultIsStmt;
        stateMachine.basicBlock = false;
        stateMachine.endSequence = false;
        stateMachine.prologueEnd = false;
        stateMachine.epilogueBegin = false;
        stateMachine.isa = 0;
        stateMachine.discriminator = 0;
        return stateMachine;
    }
    // DWARF4.pdf 6.2.4 The Line Number Program Header
    let pos = lineSection.start + cu.dies[0].DW_AT_stmt_list;
    const unitLength = get4bytes(buffer, pos);
    pos += 4;
    const endOfLineNumberProgram = pos + unitLength;
    const version = get2bytes(buffer, pos);
    pos += 2;
    const headerLength = get4bytes(buffer, pos);
    pos += 4;
    const startOfLineNumberProgram = pos + headerLength;
    const minimumInstructionLength = buffer[pos++];
    const maximumOperationsPerInstruction = buffer[pos++];
    const defaultIsStmt = buffer[pos++] !== 0;
    const lineBase = new Int8Array(buffer.buffer)[pos++]; // signed...
    const lineRange = buffer[pos++];
    const opcodeBase = buffer[pos++];
    const standardOpcodesLength = [];
    for (let opcodeLengthOffset = 1; opcodeLengthOffset < opcodeBase; ++opcodeLengthOffset) {
        const { value: length, pos: endPos } = getLEB128(buffer, pos);
        pos = endPos;
        standardOpcodesLength[opcodeLengthOffset] = length;
    }
    const includeDirectories = [cu.dies[0].DW_AT_comp_dir]; // comp dir must be the 0th entry
    while (buffer[pos]) {
        const { value: dir, pos: endPos } = getString(buffer, pos);
        pos = endPos;
        includeDirectories.push(dir);
    }
    pos++;
    const files = [{}]; // 1-based array
    while (buffer[pos]) {
        const { value: filename, pos: endPos } = getString(buffer, pos);
        pos = endPos;
        const { value: dirIndex, pos: endPos2 } = getLEB128(buffer, pos);
        pos = endPos2;
        const { value: timeOfLastModification, pos: endPos3 } = getLEB128(buffer, pos);
        pos = endPos3;
        const { value: fileLength, pos: endPos4 } = getLEB128(buffer, pos);
        pos = endPos4;
        files.push({
            filename,
            dirIndex,
            timeOfLastModification,
            fileLength,
        });
    }
    pos++;
    const lineNumberProgramHeader = {
        unitLength,
        version,
        headerLength,
        minimumInstructionLength,
        maximumOperationsPerInstruction,
        defaultIsStmt,
        lineBase,
        lineRange,
        opcodeBase,
        standardOpcodesLength,
        includeDirectories,
        files,
        endOfLineNumberProgram,
        startOfLineNumberProgram,
        matrix: [],
    };
    const stateMachine = resetStateMachine({}, lineNumberProgramHeader.defaultIsStmt);
    pos = lineNumberProgramHeader.startOfLineNumberProgram;
    while (pos < lineNumberProgramHeader.endOfLineNumberProgram) {
        // 6.2.3 Line Program Instructions
        const opcode = buffer[pos++];
        switch (opcode) {
            case Opcode.DW_LNS_extended_op: {
                // extended opcode. The next unsigned LEB128 gives the size of the instruction
                // (without the opcode and the size)
                const { value: opcodeLength, pos: endPos } = getLEB128(buffer, pos);
                pos = endPos;
                const extOpcode = buffer[pos++];
                switch (extOpcode) {
                    case ExtOpcode.DW_LNE_end_sequence: {
                        stateMachine.endSequence = true;
                        appendRow(stateMachine, lineNumberProgramHeader.matrix);
                        resetStateMachine(stateMachine, lineNumberProgramHeader.defaultIsStmt);
                        break;
                    }
                    case ExtOpcode.DW_LNE_set_address: {
                        const address = is_32 ? get4bytes(buffer, pos) : get8bytes(buffer, pos);
                        pos += is_32 ? 4 : 8;
                        stateMachine.address = address;
                        stateMachine.opIndex = 0;
                        break;
                    }
                    case ExtOpcode.DW_LNE_define_file: {
                        const { value: filename, pos: endPos } = getString(buffer, pos);
                        pos = endPos;
                        const { value: dirIndex, pos: endPos2 } = getLEB128(buffer, pos);
                        pos = endPos2;
                        const { value: timeOfLastModification, pos: endPos3 } = getLEB128(buffer, pos);
                        pos = endPos3;
                        const { value: fileLength, pos: endPos4 } = getLEB128(buffer, pos);
                        pos = endPos4;
                        files.push({
                            filename,
                            dirIndex,
                            timeOfLastModification,
                            fileLength,
                        });
                        break;
                    }
                    case ExtOpcode.DW_LNE_set_discriminator: {
                        break;
                    }
                    default: {
                        throw new Error(`Line Number Program: Unknown extended opcode ${extOpcode}`);
                    }
                }
                break;
            }
            // Here are the standard opcode whose length are specified in standardOpcodesLength
            case Opcode.DW_LNS_negate_stmt: {
                stateMachine.isStmt = !stateMachine.isStmt;
                break;
            }
            case Opcode.DW_LNS_advance_line: {
                const { value, pos: endPos } = getsLEB128(buffer, pos);
                pos = endPos;
                stateMachine.line += value;
                break;
            }
            case Opcode.DW_LNS_copy: {
                appendRow(stateMachine, lineNumberProgramHeader.matrix);
                stateMachine.basicBlock = false;
                stateMachine.prologueEnd = false;
                stateMachine.epilogueBegin = false;
                stateMachine.discriminator = 0;
                break;
            }
            case Opcode.DW_LNS_set_column: {
                const { value: column, pos: endPos } = getLEB128(buffer, pos);
                pos = endPos;
                stateMachine.column = column;
                break;
            }
            case Opcode.DW_LNS_set_prologue_end: {
                stateMachine.prologueEnd = true;
                break;
            }
            case Opcode.DW_LNS_advance_pc: {
                const { value: operationAdvance, pos: endPos } = getLEB128(buffer, pos);
                pos = endPos;
                // DWARF4.pdf 6.2.5.2 Standard opcodes
                stateMachine.address += lineNumberProgramHeader.minimumInstructionLength *
                    (((stateMachine.opIndex + operationAdvance) /
                        lineNumberProgramHeader.maximumOperationsPerInstruction) | 0);
                stateMachine.opIndex += (stateMachine.opIndex + operationAdvance) %
                    lineNumberProgramHeader.maximumOperationsPerInstruction;
                break;
            }
            case Opcode.DW_LNS_set_file: {
                const { value: file, pos: endPos } = getLEB128(buffer, pos);
                pos = endPos;
                stateMachine.file = file;
                break;
            }
            case Opcode.DW_LNS_set_basic_block: {
                stateMachine.basicBlock = true;
                break;
            }
            case Opcode.DW_LNS_const_add_pc: {
                // DWARF4.pdf 6.2.5.2 Standard opcodes
                const adjustedOpcode = opcode - lineNumberProgramHeader.opcodeBase;
                const operationAdvance = adjustedOpcode / lineNumberProgramHeader.lineRange | 0;
                stateMachine.address += lineNumberProgramHeader.minimumInstructionLength *
                    (((stateMachine.opIndex + operationAdvance) /
                        lineNumberProgramHeader.maximumOperationsPerInstruction) | 0);
                stateMachine.opIndex += (stateMachine.opIndex + operationAdvance) %
                    lineNumberProgramHeader.maximumOperationsPerInstruction;
                break;
            }
            case Opcode.DW_LNS_fixed_advance_pc: {
                const advance = is_32 ? get2bytes(buffer, pos) : get4bytes(buffer, pos);
                pos += is_32 ? 2 : 4;
                stateMachine.address += advance;
                stateMachine.opIndex = 0;
                break;
            }
            case Opcode.DW_LNS_set_epilogue_begin: {
                stateMachine.epilogueBegin = true;
                break;
            }
            case Opcode.DW_LNS_set_isa: {
                pos += lineNumberProgramHeader.standardOpcodesLength[opcode];
                throw new Error(`Unhandled opcode ${opcode} (${Opcode[opcode]})`);
                break;
            }
            default: {
                // DWARF4.pdf 6.2.5.1 Special opcodes
                advanceAddress(stateMachine, lineNumberProgramHeader, opcode);
                // 3. Append a row to the matrix using the current values of the state machine registers.
                appendRow(stateMachine, lineNumberProgramHeader.matrix);
                // 4. Set the basic_block register to “false.”
                // 5. Set the prologue_end register to “false.”
                // 6. Set the epilogue_begin register to “false.”
                // 7. Set the discriminator register to 0
                stateMachine.basicBlock = false;
                stateMachine.prologueEnd = false;
                stateMachine.epilogueBegin = false;
                stateMachine.discriminator = 0;
            }
        }
    }
    for (const row of lineNumberProgramHeader.matrix) {
        console.log(`0x${row.address.toString(16).padStart(16, '0')} ${row.line.toString().padStart(6, ' ')} ${row.column.toString().padStart(6, ' ')} ${row.file.toString().padStart(6, ' ')}`
            + `  ${row.isStmt ? 'is_stmt ' : ''}${row.prologueEnd ? 'prologue_end ' : ''}${row.endSequence ? 'end_sequence ' : ''}`);
    }
    return lineNumberProgramHeader;
}
function parseSections(buffer) {
    // 4 byte magic number: \0asm (0x0, 0x61, 0x73, 0x6d)
    if (!(buffer[0] === 0x0 && buffer[1] === 0x61 && buffer[2] === 0x73 && buffer[3] === 0x6d)) {
        throw new Error('Invalid wasm file, incorrect magic word');
    }
    // Version on 4 bytes
    const version = get4bytes(buffer, 4);
    // Parse sections
    let pos = 8;
    const sections = [];
    while (pos < buffer.length) {
        // Read the section ID
        const id = buffer[pos];
        pos += 1;
        // Read the section size
        const sectionSize = getLEB128(buffer, pos);
        pos = sectionSize.pos;
        // The section start at this position (right after the section length field)...
        const sectionStart = pos;
        let section;
        // Create section
        if (id === 0) {
            // Only custom sections get names: https://webassembly.github.io/spec/core/binary/modules.html#custom-section
            const nameSize = getLEB128(buffer, pos);
            const name = textDecoder.decode(new Uint8Array(buffer.buffer, nameSize.pos, nameSize.value));
            // ...except for custom section which will start after their name
            const start = nameSize.pos + nameSize.value;
            section = new CustomSection(id, name, start, sectionSize.value - (start - sectionSize.pos));
        }
        else {
            // Regular section
            section = new Section(id, sectionStart, sectionSize.value);
        }
        // Move to the end of the section
        pos += sectionSize.value;
        console.log(`${WasmSectionType[id].padStart(10, ' ')} starts=0x${section.start.toString(16).padStart(8, '0')} size=0x${section.size.toString(16).padEnd(5, ' ')} ${section.name ?? ""}`);
        sections.push(section);
    }
    return sections;
}
// Largely from wasm-sourcemap.py
function generateSourceMap(location, lineNumberInfo, compilationUnit, codeSection) {
    function resolveFilename(entry, lineNumberInfo, compilationUnit) {
        const { filename, dirIndex } = lineNumberInfo.files[entry.file];
        if (isAbsolute(filename)) {
            return filename;
        }
        // return `${lineNumberInfo.includeDirectories[dirIndex]}/${filename}`;
        return `${location}${filename}`;
    }
    const sources = [];
    const mappings = [];
    const sources_map = {};
    let lastAddress = 0;
    let lastSourceId = 0;
    let lastLine = 1;
    let lastColumn = 1;
    for (const entry of lineNumberInfo.matrix) {
        const line = entry.line;
        // start at least at column 1
        const column = entry.column == 0 ? 1 : entry.column;
        // ignore entries with line 0
        if (line == 0) {
            continue;
        }
        const address = entry.address + codeSection.start;
        const filename = resolveFilename(entry, lineNumberInfo, compilationUnit);
        let sourceId = sources.findIndex(f => f === filename);
        if (sourceId === -1) {
            sources.push(filename);
            sourceId = sources.length - 1;
        }
        const addressDelta = address - lastAddress;
        const sourceIdDelta = sourceId - lastSourceId;
        const lineDelta = line - lastLine;
        const columnDelta = column - lastColumn;
        mappings.push(`${toVLQ(addressDelta)}${toVLQ(sourceIdDelta)}${toVLQ(lineDelta)}${toVLQ(columnDelta)}`);
        lastAddress = address;
        lastSourceId = sourceId;
        lastLine = line;
        lastColumn = column;
    }
    return {
        version: 3,
        names: [],
        sources,
        sourcesContent: null,
        mappings: mappings.join(','),
    };
}
// ------------ end of sourcemap.ts
// Parse the WASM section and use the DWARF sections to generate a sourceMap.
function convertDwarfToSourceMap(sourceBuffer) {
    function getCustomSection(sections, name) {
        return sections.find(s => s instanceof CustomSection && s.name === name);
    }
    const buffer = new Uint8Array(sourceBuffer);
    const sections = parseSections(buffer);
    const abbrevSection = getCustomSection(sections, '.debug_abbrev');
    const stringSection = getCustomSection(sections, '.debug_str');
    const infoSection = getCustomSection(sections, '.debug_info');
    const debugLine = getCustomSection(sections, '.debug_line');
    if (abbrevSection === undefined || stringSection === undefined ||
        infoSection === undefined || debugLine === undefined) {
        throw new Error('Missing DWARF section. Make sure your wasm file was compiled with debug options.');
    }
    const abbreviationTable = getAbbreviationTable(buffer, abbrevSection);
    const stringBuffer = new Uint8Array(sourceBuffer, stringSection.start, stringSection.size);
    const compilationUnits = getCompilationUnits(buffer, infoSection, abbreviationTable, stringBuffer);
    const lineNumberInfos = compilationUnits.map(cu => getLineNumberInfo(buffer, debugLine, cu));
    const codeSection = sections.find(s => s.id === WasmSectionType.code);
    // TODO: deal with multiple CUs
    const sourceMap = generateSourceMap(window.location.href, lineNumberInfos[0], compilationUnits[0], codeSection);
    return sourceMap;
}
// Serialize the sourceMap into an inline base64 encoded string and add a custom
// section to the binary
function appendInlineSourceMap(sourceBuffer, sourceMap) {
    // inline mapping url example:
    // //# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiIiwic291cmNlcyI6WyJmb28uanMiLCJiYXIuanMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7O1VBQ0c7Ozs7Ozs7Ozs7Ozs7O3NCQ0RIO3NCQUNBIn0=
    const encoder = new TextEncoder();
    const sectionTitle = 'sourceMappingURL';
    // console.log('sourceMap str', JSON.stringify(sourceMaps));
    // console.log('sourceMap base64', btoa(JSON.stringify(sourceMaps)));
    const payload = `data:application/json;charset=utf-8;base64,${btoa(JSON.stringify(sourceMap))}`;
    const payloadSizeLEB128 = toLEB128(payload.length);
    const sectionSize = 1 + sectionTitle.length + payloadSizeLEB128.length + payload.length;
    const sectionSizeLEB128 = toLEB128(sectionSize);
    const result = new Uint8Array(sourceBuffer.byteLength + 1 + sectionSizeLEB128.length + sectionSize);
    result.set(new Uint8Array(sourceBuffer));
    // First a zero for custom section
    result[sourceBuffer.byteLength] = 0x00;
    // We set the total section size (minus the initial 0 and the size itself)
    result.set(sectionSizeLEB128, sourceBuffer.byteLength + 1);
    // We set the size directly without LEB128 encoding because we know its value is lower than 127
    result[sourceBuffer.byteLength + 1 + sectionSizeLEB128.length] = sectionTitle.length;
    // Set the section title
    result.set(encoder.encode(sectionTitle), sourceBuffer.byteLength + 1 + sectionSizeLEB128.length + 1);
    // Set the source map base64 url size in LEB128
    result.set(payloadSizeLEB128, sourceBuffer.byteLength + 1 + sectionSizeLEB128.length + 1 + sectionTitle.length);
    // Finally set the actual sourceMap base64 url
    result.set(encoder.encode(payload), sourceBuffer.byteLength + 1 + sectionSizeLEB128.length + 1 + sectionTitle.length + payloadSizeLEB128.length);
    return result.buffer;
}
function patchWithSourceMap(sourceBuffer) {
    return appendInlineSourceMap(sourceBuffer, convertDwarfToSourceMap(sourceBuffer));
}
//# sourceMappingURL=d2sm.js.map