# dwarf-2-sourcemap

Debugging WASM files in the browser is, at the time of this writing, is still an
unreliable journey. [Chrome has a special extension](https://developer.chrome.com/blog/wasm-debugging-2020/)
for this but Firefox does not. So if you are a loyal Firefox user, your out of
luck.

But despair not, this project purposes it to use the debugging symbol present
in your WASM file in order to generate a sourceMap comprehensible by Firefox
(and incidentally Chrome).

This tool reads the DWARF debug symbols that are present in your WASM file, if
your compiler included them, and generate, on the fly and in the browser, the
corresponding sourceMaps that are then embedded inline in the WASM buffer.
Instantiating your module with that "patched" buffer should allow you to debug
your WASM source code.

⚠️ This is still a work in progress ! PR welcomed.

# Usage

To use it, download the d2sm.js solution and serve it. Then, in your code,
before instantiating the WASM module, call `patchWithSourceMap` providing the
`arrayBuffer` containing the WASM code.

See [test.js](test/test.js) for an example usage:
```javascript
async function main() {
  const wasmFile = await fetch('main.wasm');
  const sourceBuffer = await wasmFile.arrayBuffer();
  // Patch the WASM arrayBuffer with an inline sourceMap section corresponding
  // to your DWARF symbol.
  const sourceBufferWithDebug = patchWithSourceMap(sourceBuffer);
  // Repackage the Response for instantiateStreaming below.
  const wasmFileWithDebug = new Response(sourceBufferWithDebug, {
    headers: {
      'Content-Type': 'application/wasm'
    }
  });
  const memory = new WebAssembly.Memory({ initial: 1 });
  const arrayBuffer = memory.buffer;
  const buffer = new Uint8Array(arrayBuffer);
  // Please note that the WebAssembly.instantiate API on firefox is buggy:
  // https://bugzilla.mozilla.org/show_bug.cgi?id=1787593
  const wasm = await WebAssembly.instantiateStreaming(wasmFileWithDebug, {
    env: {
      memory,
      log: (offset, size) => {
        console.log(textDecoder.decode(new Uint8Array(memory.buffer, offset, size)));
      },
    },
  });

  console.log(wasm.instance.exports.add(2, 3));
}

window.onload = main;
```

# References

- sourcemaps: https://www.mattzeunert.com/2016/02/14/how-do-source-maps-work.html 
- sourcemaps in more and better details: https://pvdz.ee/weblog/281 
- example of inline sourcemap: https://github.com/thlorenz/inline-source-map 

- wasm format: https://coinexsmartchain.medium.com/wasm-introduction-part-1-binary-format-57895d851580 
- Also: https://blog.ttulka.com/learning-webassembly-2-wasm-binary-format 
- Official WASM specs: https://webassembly.github.io/spec/core/intro/index.html 

- How to embed sourcemap in wasm: https://medium.com/oasislabs/webassembly-debugging-bec0aa93f8c6 

To dump the DWARF info of a wasm file: 
```bash
llvm-dwarfdump-14 -debug-info -debug-line --recurse-depth=0 main.wasm > main.dwarf 
```
To embed the sourcemap in the wasm:
```bash
python3 wasm-sourcemap.py --dwarfdump-output main.dwarf main.wasm --output main.wasm.sourcemap -u http://localhost:8000/main.wasm.sourcemap -w main2.wasm 
```

- DWARF: https://dwarfstd.org/doc/Debugging%20using%20DWARF-2012.pdf 
- DWARF 2.0 specs: https://dwarfstd.org/doc/dwarf-2.0.0.pdf 
- DWARF 4.0 specs: https://dwarfstd.org/doc/DWARF4.pdf 

Example implementation: 
- DWARF reader: https://github.com/ziglang/zig/blob/6072226/lib/std/dwarf.zig

> Note: From the .debug_info custom section, we are interested in the top level 
> DIEs (the compilation units) in order to retrieve the "DW_AT_comp_dir". 

- The article I wrote about it: http://site.novidee.com/blog/blog-entry.html?article=20220821-how-to-debug-wasm-in-firefox.html 

# Acknowledgement

* https://github.com/oasislabs/wasm-sourcemap: for the idea of live patching the WASM buffer
* https://github.com/emscripten-core/emscripten/blob/e6b78a3/tools/wasm-sourcemap.py: for the conversion
from DWARF to sourceMaps.
