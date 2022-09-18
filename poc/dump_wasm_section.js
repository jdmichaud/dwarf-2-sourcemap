const textDecoder = new TextDecoder();

async function getSourceBuffer(wasmFile) {
  const isBrowser = new Function("try {return this===window;}catch(e){ return false;}")();
  if (isBrowser) {
    const response = await fetch(wasmFile);
    const sourceBuffer = await response.arrayBuffer();
    return sourceBuffer;
  }
  fs = require('fs');
  return fs.readFileSync(wasmFile).buffer;
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

function parse(sourceBuffer) {
  const sectionType = [
    'custom',   // 0
    'type',     // 1
    'import',   // 2
    'function', // 3
    'table',    // 4
    'memory',   // 5
    'global',   // 6
    'export',   // 7
    'start',    // 8
    'element',  // 9
    'code',     // 10
    'data',     // 11
    'data',     // 12
  ];

  const buffer = new Uint8Array(sourceBuffer);
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
    const id = buffer[pos];
    pos += 1;
    const sectionSize = getLEB128(buffer, pos);
    pos = sectionSize.pos;
    // The section start at this position (right after the section length field)...
    const sectionStart = pos;
    // Only custom sections get names: https://webassembly.github.io/spec/core/binary/modules.html#custom-section
    let name;
    let customSectionStart;
    if (id === 0) {
      const nameSize = getLEB128(buffer, pos);
      name = textDecoder.decode(new Uint8Array(sourceBuffer, nameSize.pos, nameSize.value));
      // ...except for custom section which will start after their name
      customSectionStart = nameSize.pos + nameSize.value;
    }
    // Move to the end of the section
    pos += sectionSize.value;
    // Create section
    const section = {
      id,
      name,
      start: sectionStart,
      size: sectionSize.value,
      // Only for custom section, 0 otherwise
      customSectionStart,
    };
    console.log(`${sectionType[id].padStart(10, ' ')} starts=0x${section.start.toString(16).padStart(8, 0)} size=0x${section.size.toString(16)} ${section.name ?? ""}`);
    sections.push(section);
  }
}

async function main() {
  // Wasm code
  const sourceBuffer = await getSourceBuffer(process.argv[2]);

  parse(sourceBuffer);

  // Memory for the wasm process
  const memory = new WebAssembly.Memory({ initial: 2 });
  const arrayBuffer = memory.buffer;
  const buffer = new Uint8Array(arrayBuffer);

  const wasm = await WebAssembly.instantiate(sourceBuffer, {
    env: {
      memory,
      log: (offset, size) => {
        console.log(textDecoder.decode(new Uint8Array(memory.buffer, offset, size)));
      },
    },
  });
}

main();

