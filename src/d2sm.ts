
const textDecoder = new TextDecoder();

function toHexPrint(n: number): string {
  return `0x${n.toString(16).padStart(8, '0')}`;
}

// Target machine (wasm) is 32 bits.
// ⚠️ This implementation does not use this variable consistently.
// TODO: Systematically us is_32 when required.
const is_32 = true;

// ------------ utils.ts
function toLEB128(n: number): Uint8Array {
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

function get8bytes(buf: Uint8Array, pos: number): number {
  return buf[pos] |
    buf[pos + 1] << 8 |
    buf[pos + 2] << 16 |
    buf[pos + 3] << 24 |
    buf[pos + 4] << 32 |
    buf[pos + 5] << 40 |
    buf[pos + 6] << 48 |
    buf[pos + 7] << 56;
}

function get4bytes(buf: Uint8Array, pos: number): number {
  return buf[pos] |
    buf[pos + 1] << 8 |
    buf[pos + 2] << 16 |
    buf[pos + 3] << 24;
}

function get2bytes(buf: Uint8Array, pos: number): number {
  return buf[pos] |
    buf[pos + 1] << 8;
}

interface ConvertionResult<T> {
  // The decoded value
  value: T,
  // The position in the buffer after convertion (position of the nex byte to read)
  pos: number,
}

// Variable size unsigned LEB128
function getLEB128(buffer: Uint8Array, pos: number): ConvertionResult<number> {
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
function getsLEB128(buffer: Uint8Array, pos: number): ConvertionResult<number> {
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
function getString(buffer: Uint8Array, pos: number): ConvertionResult<string> {
  let end = pos;
  while (buffer[end] !== 0) ++end;
  return {
    value: textDecoder.decode(buffer.subarray(pos, end)),
    pos: end + 1,
  };
}

// From wasm-sourcemap.py
function toVLQ(n: number): string {
  const VLQ_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  n = n | 0;
  let x = n >= 0 ? (n << 1) : ((-n << 1) + 1);
  let result = "";
  while (x > 31) {
    result = `${result}${VLQ_CHARS[32 + (x & 31)]}`;
    x = x >> 5;
  }
  return `${result}${VLQ_CHARS[x]}`;
}

function isAbsolute(path: string): boolean {
  // ⚠️⚠️⚠️ Only manage unix style file path for now
  return path[0] === '/';
}

// ------------ end of utils.ts

// ------------ wasm.ts

enum WasmSectionType {
  custom   = 0,
  type     = 1,
  import   = 2,
  function = 3,
  table    = 4,
  memory   = 5,
  global   = 6,
  export   = 7,
  start    = 8,
  element  = 9,
  code     = 10,
  data     = 11,
  data2    = 12, // This section's name is supposed to be 'data'
}

class Section {
  constructor(
    readonly id: number,
    // start is the position right after the size of the section.
    readonly start: number,
    // Size of the section minus the id and size itself.
    // start + size = next byte after the section.
    readonly size: number,
  ) {}
}

class CustomSection {
  constructor(
    readonly id: number,
    readonly name: string,
    // start is the position right after the name of the custom section.
    readonly start: number,
    // Size of the section minus the id, size itself, the size of the name and the name.
    // start + size = next byte after the section.
    readonly size: number,
  ) {}
}

// ------------ end of wasm.ts


// ------------ dwarf.ts

enum TagType {
  DW_TAG_array_type = 0x01,
  DW_TAG_class_type = 0x02,
  DW_TAG_entry_point = 0x03,
  DW_TAG_enumeration_type = 0x04,
  DW_TAG_formal_parameter = 0x05,
  DW_TAG_imported_declaration = 0x08,
  DW_TAG_label = 0x0a,
  DW_TAG_lexical_block = 0x0b,
  DW_TAG_member = 0x0d,
  DW_TAG_pointer_type = 0x0f,
  DW_TAG_reference_type = 0x10,
  DW_TAG_compile_unit = 0x11,
  DW_TAG_string_type = 0x12,
  DW_TAG_structure_type = 0x13,
  DW_TAG_subroutine_type = 0x15,
  DW_TAG_typedef = 0x16,
  DW_TAG_union_type = 0x17,
  DW_TAG_unspecified_parameters = 0x18,
  DW_TAG_variant = 0x19,
  DW_TAG_common_block = 0x1a,
  DW_TAG_common_inclusion = 0x1b,
  DW_TAG_inheritance = 0x1c,
  DW_TAG_inlined_subroutine = 0x1d,
  DW_TAG_module = 0x1e,
  DW_TAG_ptr_to_member_type = 0x1f,
  DW_TAG_set_type = 0x20,
  DW_TAG_subrange_type = 0x21,
  DW_TAG_with_stmt = 0x22,
  DW_TAG_access_declaration = 0x23,
  DW_TAG_base_type = 0x24,
  DW_TAG_catch_block = 0x25,
  DW_TAG_const_type = 0x26,
  DW_TAG_constant = 0x27,
  DW_TAG_enumerator = 0x28,
  DW_TAG_file_type = 0x29,
  DW_TAG_friend = 0x2a,
  DW_TAG_namelist = 0x2b,
  DW_TAG_namelist_item = 0x2c,
  DW_TAG_packed_type = 0x2d,
  DW_TAG_subprogram = 0x2e,
  DW_TAG_template_type_param = 0x2f,
  DW_TAG_template_value_param = 0x30,
  DW_TAG_thrown_type = 0x31,
  DW_TAG_try_block = 0x32,
  DW_TAG_variant_part = 0x33,
  DW_TAG_variable = 0x34,
  DW_TAG_volatile_type = 0x35,
  DW_TAG_lo_user = 0x4080,
  DW_TAG_hi_user = 0xffff,
}

enum AttributeEncoding {
  DW_AT_sibling = 0x01,
  DW_AT_location = 0x02,
  DW_AT_name = 0x03,
  DW_AT_ordering = 0x09,
  DW_AT_byte_size = 0x0b,
  DW_AT_bit_offset = 0x0c,
  DW_AT_bit_size = 0x0d,
  DW_AT_stmt_list = 0x10,
  DW_AT_low_pc = 0x11,
  DW_AT_high_pc = 0x12,
  DW_AT_language = 0x13,
  DW_AT_discr = 0x15,
  DW_AT_discr_value = 0x16,
  DW_AT_visibility = 0x17,
  DW_AT_import = 0x18,
  DW_AT_string_length = 0x19,
  DW_AT_common_reference = 0x1a,
  DW_AT_comp_dir = 0x1b,
  DW_AT_const_value = 0x1c,
  DW_AT_containing_type = 0x1d,
  DW_AT_default_value = 0x1e,
  DW_AT_inline = 0x20,
  DW_AT_is_optional = 0x21,
  DW_AT_lower_bound = 0x22,
  DW_AT_producer = 0x25,
  DW_AT_prototyped = 0x27,
  DW_AT_return_addr = 0x2a,
  DW_AT_start_scope = 0x2c,
  DW_AT_bit_stride = 0x2e,
  DW_AT_upper_bound = 0x2f,
  DW_AT_abstract_origin = 0x31,
  DW_AT_accessibility = 0x32,
  DW_AT_address_class = 0x33,
  DW_AT_artificial = 0x34,
  DW_AT_base_types = 0x35,
  DW_AT_calling_convention = 0x36,
  DW_AT_count = 0x37,
  DW_AT_data_member_location = 0x38,
  DW_AT_decl_column = 0x39,
  DW_AT_decl_file = 0x3a,
  DW_AT_decl_line = 0x3b,
  DW_AT_declaration = 0x3c,
  DW_AT_discr_list = 0x3d,
  DW_AT_encoding = 0x3e,
  DW_AT_external = 0x3f,
  DW_AT_frame_base = 0x40,
  DW_AT_friend = 0x41,
  DW_AT_identifier_case = 0x42,
  DW_AT_macro_info = 0x43,
  DW_AT_namelist_item = 0x44,
  DW_AT_priority = 0x45,
  DW_AT_segment = 0x46,
  DW_AT_specification = 0x47,
  DW_AT_static_link = 0x48,
  DW_AT_type = 0x49,
  DW_AT_use_location = 0x4a,
  DW_AT_variable_parameter = 0x4b,
  DW_AT_virtuality = 0x4c,
  DW_AT_vtable_elem_location = 0x4d,
  DW_AT_allocated = 0x4e,
  DW_AT_associated = 0x4f,
  DW_AT_data_location = 0x50,
  DW_AT_byte_stride = 0x51,
  DW_AT_entry_pc = 0x52,
  DW_AT_use_UTF8 = 0x53,
  DW_AT_extension = 0x54,
  DW_AT_ranges = 0x55,
  DW_AT_trampoline = 0x56,
  DW_AT_call_column = 0x57,
  DW_AT_call_file = 0x58,
  DW_AT_call_line = 0x59,
  DW_AT_description = 0x5a,
  DW_AT_binary_scale = 0x5b,
  DW_AT_decimal_scale = 0x5c,
  DW_AT_small = 0x5d,
  DW_AT_decimal_sign = 0x5e,
  DW_AT_digit_count = 0x5f,
  DW_AT_picture_string = 0x60,
  DW_AT_mutable = 0x61,
  DW_AT_threads_scaled = 0x62,
  DW_AT_explicit = 0x63,
  DW_AT_object_pointer = 0x64,
  DW_AT_endianity = 0x65,
  DW_AT_elemental = 0x66,
  DW_AT_pure = 0x67,
  DW_AT_recursive = 0x68,
  DW_AT_signature = 0x69,
  DW_AT_main_subprogram = 0x6a,
  DW_AT_data_bit_offset = 0x6b,
  DW_AT_const_expr = 0x6c,
  DW_AT_enum_class = 0x6d,
  DW_AT_linkage_name = 0x6e,
  DW_AT_lo_user = 0x2000,
  DW_AT_hi_user = 0x3fff,
  DW_AT_GNU_pubnames = 0x2134, // Not in DRAFT4.pdf
}

enum FormType {
  DW_FORM_addr = 0x01,
  DW_FORM_block2 = 0x03,
  DW_FORM_block4 = 0x04,
  DW_FORM_data2 = 0x05,
  DW_FORM_data4 = 0x06,
  DW_FORM_data8 = 0x07,
  DW_FORM_string = 0x08,
  DW_FORM_block = 0x09,
  DW_FORM_block1 = 0x0a,
  DW_FORM_data1 = 0x0b,
  DW_FORM_flag = 0x0c,
  DW_FORM_sdata = 0x0d,
  DW_FORM_strp = 0x0e,
  DW_FORM_udata = 0x0f,
  DW_FORM_ref_addr = 0x10,
  DW_FORM_ref1 = 0x11,
  DW_FORM_ref2 = 0x12,
  DW_FORM_ref4 = 0x13,
  DW_FORM_ref8 = 0x14,
  DW_FORM_ref_udata = 0x15,
  DW_FORM_indirect = 0x16,
  DW_FORM_sec_offset = 0x17,
  DW_FORM_exprloc = 0x18,
  DW_FORM_flag_present = 0x19,
  DW_FORM_ref_sig8 = 0x20,
}

enum Opcode {
  DW_LNS_extended_op = 0x0, // see DWARF4.pdf 6.2.3 Line Program Instructions
  DW_LNS_copy = 0x1,
  DW_LNS_advance_pc = 0x2,
  DW_LNS_advance_line = 0x3,
  DW_LNS_set_file = 0x4,
  DW_LNS_set_column = 0x5,
  DW_LNS_negate_stmt = 0x6,
  DW_LNS_set_basic_block  = 0x7,
  DW_LNS_const_add_pc = 0x8,
  DW_LNS_fixed_advance_pc = 0x9,
  DW_LNS_set_prologue_end = 0xA,
  DW_LNS_set_epilogue_begin = 0xB,
  DW_LNS_set_isa = 0xC,
}

enum ExtOpcode {
  DW_LNE_end_sequence = 0x1,
  DW_LNE_set_address = 0x2,
  DW_LNE_define_file = 0x3,
  DW_LNE_set_discriminator = 0x4,
}

interface AbbreviationAttribute {
  name: AttributeEncoding,
  form: FormType,
}

interface Abbreviation {
  tag: number,
  hasChildren: boolean,
  attributes: Array<AbbreviationAttribute>,
}

type AbbrvMap = { [k: number]: Abbreviation };

function getAbbreviationTable(buffer: Uint8Array, abbrevTableSection: CustomSection): AbbrvMap {
  const abbreviationTable: AbbrvMap = {};
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

type Die = {
  address: number,
  abbrevCode: number,
  hasChildren: boolean,
  dies: Array<Die>,
// TODO: Need to figure that out
// } & { [k in typeof AttributeEncoding[keyof typeof AttributeEncoding]]?: any };
} & { [k: string]: any };

// Get the Debug Information Entries
function getDIEs(buffer: Uint8Array, pos: number, infoSection: CustomSection,
  abbreviationTable: AbbrvMap, stringBuffer: Uint8Array): Array<Die> {
  const dies: Array<Array<Die>> = [[]];
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
    const fields: { [k: string]: any } = {};
    for (const attribute of abbreviationEntry.attributes) {
      // DWARF4.pdf 7.5.4 Attribute Encoding
      switch (attribute.form) {
        case FormType.DW_FORM_strp: { // an offset to a null terminated string in the .debug_str section
          const offset = get4bytes(buffer, pos); pos += 4;
          const { value: str } = getString(stringBuffer, offset);
          fields[AttributeEncoding[attribute.name]] = str;
          break;
        }
        case FormType.DW_FORM_data1:  // a a bytes constant
        case FormType.DW_FORM_ref1: { // a 1 byte reference to another DIE
          const data = buffer[pos++];
          fields[AttributeEncoding[attribute.name]] = data;
          break;
        }
        case FormType.DW_FORM_data2: // a 2 bytes constant
        case FormType.DW_FORM_ref2: { // a 2 bytes reference to another DIE
          const data = get2bytes(buffer, pos); pos += 2;
          fields[AttributeEncoding[attribute.name]] = data;
          break;
        }
        case FormType.DW_FORM_data4: // a 4 bytes constant
        case FormType.DW_FORM_ref4: { // a 4 bytes reference to another DIE
          const data = get4bytes(buffer, pos); pos += 4;
          fields[AttributeEncoding[attribute.name]] = data;
          break;
        }
        case FormType.DW_FORM_data8: // a 8 bytes constant
        case FormType.DW_FORM_ref8: { // a 8 bytes reference to another DIE
          const data = get8bytes(buffer, pos); pos += 8;
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
          const offset = get4bytes(buffer, pos); pos += 4;
          fields[AttributeEncoding[attribute.name]] = offset;
          break;
        }
        case FormType.DW_FORM_flag_present: { // an indication that the field is present
          fields[AttributeEncoding[attribute.name]] = true;
          break;
        }
        case FormType.DW_FORM_addr: { // an indication that the field is present
          const addr = get4bytes(buffer, pos); pos += 4;
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

    const die: Die = {
      address,
      abbrevCode,
      hasChildren: abbreviationEntry.hasChildren,
      ...fields,
      dies: [],
    } as Die;

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

interface CompilationUnit {
  start: number,
  unitLength: number,
  abbrevOffset: number,
  addressSize: number,
  dies: Array<Die>,
}

// https://dwarfstd.org/doc/dwarf-2.0.0.pdf (7.5 Format of Debugging Information)
// https://dwarfstd.org/doc/DWARF4.pdf (7.5.1.1 Format of Debugging Information)
function getCompilationUnits(buffer: Uint8Array, infoSection: CustomSection,
  abbreviationTable: { [k: number]: Abbreviation }, stringBuffer: Uint8Array): CompilationUnit[] {
  const { size: sectionSize, start } = infoSection;
  // Read the compilation unit header
  let pos = start;
  const compilationUnits = [];
  while (pos < start + sectionSize) {
    const start = pos;
    // Compilation unit length on 4 bytes
    const unitLength = get4bytes(buffer, pos); pos += 4;
    // Version on 2 bytes
    const version = get2bytes(buffer, pos); pos += 2;
    // Offset in the abbreviation table on 4 bytes
    const abbrevOffset = get4bytes(buffer, pos); pos += 4;
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

interface StateMachine {
  address: number,
  opIndex: number,
  line: number,
  column: number,
  file: number,
  isa: number,
  discriminator: number,
  isStmt: boolean,
  basicBlock: boolean,
  endSequence: boolean,
  prologueEnd: boolean,
  epilogueBegin: boolean,
}

type MatrixEntry = Omit<StateMachine, 'opIndex'>;

interface FileEntry {
  filename: string,
  dirIndex: number,
  timeOfLastModification: number,
  fileLength: number,
}

interface LineNumberProgramHeader {
  unitLength: number,
  version: number,
  headerLength: number,
  minimumInstructionLength: number,
  maximumOperationsPerInstruction: number,
  defaultIsStmt: boolean,
  lineBase: number,
  lineRange: number,
  opcodeBase: number,
  standardOpcodesLength: Array<number>,
  includeDirectories: Array<string>,
  files: Array<FileEntry>,
  endOfLineNumberProgram: boolean,
  startOfLineNumberProgram: boolean,
  matrix: Array<MatrixEntry>,
}

function getLineNumberInfo(buffer: Uint8Array, lineSection: CustomSection,
  cu: CompilationUnit): LineNumberProgramHeader {
  function appendRow(stateMachine: StateMachine, matrix: MatrixEntry[]): void {
    const {
      address, line, column, file, isa, discriminator, isStmt, basicBlock, endSequence, prologueEnd, epilogueBegin
    } = stateMachine;
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

  function advanceAddress(stateMachine: StateMachine,
    lineNumberProgramHeader: LineNumberProgramHeader, opcode: Opcode): void {
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

  function resetStateMachine(stateMachine: StateMachine, defaultIsStmt: boolean): StateMachine {
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
  const unitLength = get4bytes(buffer, pos); pos += 4;
  const endOfLineNumberProgram = pos + unitLength;
  const version = get2bytes(buffer, pos); pos += 2;
  const headerLength = is_32 ? get4bytes(buffer, pos) : get8bytes(buffer, pos);
  pos += is_32 ? 4 : 8;
  const startOfLineNumberProgram = pos + headerLength;
  const minimumInstructionLength = buffer[pos++];
  const maximumOperationsPerInstruction = buffer[pos++];
  const defaultIsStmt = buffer[pos++] !== 0;
  const lineBase = new Int8Array(buffer.buffer)[pos++]; // signed...
  const lineRange = buffer[pos++];
  const opcodeBase = buffer[pos++];
  const standardOpcodesLength = [];
  for (let opcodeLengthOffset = 1; opcodeLengthOffset < opcodeBase; ++opcodeLengthOffset) {
    const { value: length, pos: endPos } = getLEB128(buffer, pos); pos = endPos;
    standardOpcodesLength[opcodeLengthOffset] = length;
  }
  const includeDirectories = [cu.dies[0].DW_AT_comp_dir]; // comp dir must be the 0th entry
  while (buffer[pos]) {
    const { value: dir, pos: endPos } = getString(buffer, pos);
    pos = endPos;
    includeDirectories.push(dir);
  }
  pos++;
  const files: Array<FileEntry> = [{} as any]; // 1-based array
  while (buffer[pos]) {
    const { value: filename, pos: endPos } = getString(buffer, pos); pos = endPos;
    const { value: dirIndex, pos: endPos2 } = getLEB128(buffer, pos); pos = endPos2;
    const { value: timeOfLastModification, pos: endPos3 } = getLEB128(buffer, pos); pos = endPos3;
    const { value: fileLength, pos: endPos4 } = getLEB128(buffer, pos); pos = endPos4;
    files.push({
      filename,
      dirIndex,
      timeOfLastModification,
      fileLength,
    });
  }
  pos++;
  const lineNumberProgramHeader: LineNumberProgramHeader = {
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

  const stateMachine = resetStateMachine({} as any, lineNumberProgramHeader.defaultIsStmt);
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
        const advance = is_32 ? get2bytes(buffer, pos): get4bytes(buffer, pos);
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

function parseSections(buffer: Uint8Array): Array<Section | CustomSection> {
  // 4 byte magic number: \0asm (0x0, 0x61, 0x73, 0x6d)
  if (!(buffer[0] === 0x0 && buffer[1] === 0x61 && buffer[2] === 0x73 && buffer[3] === 0x6d)) {
    throw new Error('Invalid wasm file, incorrect magic word');
  }
  // Version on 4 bytes
  const version = get4bytes(buffer, 4);
  // Parse sections
  let pos = 8;
  const sections: Array<Section | CustomSection> = [];
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
      section = new CustomSection(
        id,
        name,
        start,
        sectionSize.value - (start - sectionSize.pos),
      );
    } else {
      // Regular section
      section = new Section(
        id,
        sectionStart,
        sectionSize.value,
      );
    }
    // Move to the end of the section
    pos += sectionSize.value;
    console.log(`${WasmSectionType[id].padStart(10, ' ')} starts=0x${section.start.toString(16).padStart(8, '0')} size=0x${section.size.toString(16).padEnd(5, ' ')} ${(section as any).name ?? ""}`);
    sections.push(section);
  }
  return sections;
}

// ------------ end of dwarf.ts

// ------------ sourcemap.ts

interface SourceMap {
  version: 3,
  names: Array<string>,
  sources: Array<string>,
  sourcesContent: null,
  mappings: string,
}

// Largely from wasm-sourcemap.py
function generateSourceMap(location: string, lineNumberInfo: LineNumberProgramHeader,
  compilationUnit: CompilationUnit, codeSection: Section): SourceMap {
  function resolveFilename(entry: MatrixEntry, lineNumberInfo: LineNumberProgramHeader,
    compilationUnit: CompilationUnit): string {
    const { filename, dirIndex } = lineNumberInfo.files[entry.file];
    if (isAbsolute(filename)) {
      return filename;
    }
    // return `${lineNumberInfo.includeDirectories[dirIndex]}/${filename}`;
    return `${location}${filename}`;
  }

  const sources = []
  const mappings = []
  const sources_map = {}
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
function convertDwarfToSourceMap(sourceBuffer: ArrayBuffer): SourceMap {
  function getCustomSection(sections: Array<Section | CustomSection>, name: string): CustomSection {
    return sections.find(s => s instanceof CustomSection && s.name === name) as CustomSection;
  }
  const buffer = new Uint8Array(sourceBuffer);
  const sections = parseSections(buffer);

  const abbrevSection = getCustomSection(sections, '.debug_abbrev');
  const stringSection = getCustomSection(sections, '.debug_str');
  const infoSection = getCustomSection(sections, '.debug_info')
  const debugLine = getCustomSection(sections, '.debug_line');

  if (abbrevSection === undefined || stringSection === undefined ||
    infoSection === undefined || debugLine === undefined) {
    throw new Error('Missing DWARF section. Make sure your wasm file was compiled with debug options.');
  }

  const abbreviationTable = getAbbreviationTable(buffer, abbrevSection);
  const stringBuffer = new Uint8Array(sourceBuffer, stringSection.start, stringSection.size);
  const compilationUnits = getCompilationUnits(buffer, infoSection, abbreviationTable, stringBuffer);
  const lineNumberInfos = compilationUnits.map(cu => getLineNumberInfo(buffer, debugLine, cu));
  const codeSection = sections.find(s => s.id === WasmSectionType.code) as Section;
  // TODO: deal with multiple CUs
  const sourceMap = generateSourceMap(window.location.href, lineNumberInfos[0], compilationUnits[0], codeSection);

  return sourceMap;
}

// Serialize the sourceMap into an inline base64 encoded string and add a custom
// section to the binary
function appendInlineSourceMap(sourceBuffer: ArrayBuffer, sourceMap: SourceMap): ArrayBuffer {
  // inline mapping url example:
  // //# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiIiwic291cmNlcyI6WyJmb28uanMiLCJiYXIuanMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7O1VBQ0c7Ozs7Ozs7Ozs7Ozs7O3NCQ0RIO3NCQUNBIn0=
  const encoder = new TextEncoder()
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

function patchWithSourceMap(sourceBuffer: ArrayBuffer): ArrayBuffer {
  return appendInlineSourceMap(sourceBuffer, convertDwarfToSourceMap(sourceBuffer));
}
