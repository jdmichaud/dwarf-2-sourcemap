async function main() {
  const wasmFile = await fetch('main.wasm');
  const sourceBuffer = await wasmFile.arrayBuffer();
  const sourceBufferWithDebug = patchWithSourceMap(sourceBuffer);
  const wasmFileWithDebug = new Response(sourceBufferWithDebug, {
    headers: {
      'Content-Type': 'application/wasm'
    }
  });

  // Memory for the wasm process
  const memory = new WebAssembly.Memory({ initial: 1 });
  const arrayBuffer = memory.buffer;
  const buffer = new Uint8Array(arrayBuffer);

  const wasm = await WebAssembly.instantiateStreaming(wasmFileWithDebug, {
    env: {
      memory,
      log: (offset, size) => {
        console.log(textDecoder.decode(new Uint8Array(memory.buffer, offset, size)));
      },
    },
  });

  console.log(wasm.instance.exports.add(2, 3));
  console.log('ready');
}

window.onload = main;
