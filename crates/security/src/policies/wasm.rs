use anyhow::{Context, Result};
use wasmi::{Engine, Linker, Module, Store};

// Define the interface for the WASM module
// We'll use a simple interface:
// - Host provides `input` (JSON string)
// - WASM exports `evaluate(input_ptr: i32, input_len: i32) -> i32`

// A minimal WASM module that exports "alloc" and "evaluate" and returns 1 (allow).
// This is used for the "wasm" placeholder policy.
pub const DUMMY_WASM_ALLOW: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x0f, // Type Section (ID 1, Size 15)
      0x03, // Count 3
      0x60, 0x01, 0x7f, 0x01, 0x7f, // (i32)->i32
      0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, // (i32, i32)->i32
      0x60, 0x00, 0x00, // ()->()

    0x03, 0x03, // Function Section (ID 3, Size 3)
      0x02, 0x00, 0x01, // Count 2, Types 0, 1

    0x05, 0x03, // Memory Section (ID 5, Size 3)
      0x01, 0x00, 0x01, // Count 1, Limit 0, 1

    0x07, 0x1d, // Export Section (ID 7, Size 29)
      0x03, // Count 3
      0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00, // "memory" mem 0
      0x05, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x00, 0x00, // "alloc" func 0
      0x08, 0x65, 0x76, 0x61, 0x6c, 0x75, 0x61, 0x74, 0x65, 0x00, 0x01, // "evaluate" func 1

    0x0a, 0x0b, // Code Section (ID 10, Size 11)
      0x02, // Count 2
      0x04, 0x00, 0x41, 0x00, 0x0b, // Func 0 body: const 0
      0x04, 0x00, 0x41, 0x01, 0x0b  // Func 1 body: const 1
];

pub fn evaluate_wasm_policy(
    wasm_bytes: &[u8],
    input_json: &str,
) -> Result<bool> {
    let engine = Engine::default();
    let module = Module::new(&engine, wasm_bytes)
        .context("Failed to create WASM module")?;

    let linker = Linker::new(&engine);
    let mut store = Store::new(&engine, ());

    // Instantiate and start
    // Suppress deprecated warning as we are using a known flow
    #[allow(deprecated)]
    let instance = linker
        .instantiate(&mut store, &module)
        .context("Failed to instantiate module")?
        .start(&mut store)
        .context("Failed to start module")?;

    // Allocate memory for input string in WASM linear memory
    let alloc_func = instance
        .get_typed_func::<i32, i32>(&store, "alloc")
        .context("WASM module must export 'alloc(size: i32) -> i32'")?;

    let input_bytes = input_json.as_bytes();
    let input_len = input_bytes.len() as i32;

    let input_ptr = alloc_func.call(&mut store, input_len)?;

    // Write input string to WASM memory
    let memory = instance
        .get_memory(&store, "memory")
        .context("WASM module must export 'memory'")?;

    memory.write(&mut store, input_ptr as usize, input_bytes)?;

    // Call evaluate function
    let evaluate_func = instance
        .get_typed_func::<(i32, i32), i32>(&store, "evaluate")
        .context("WASM module must export 'evaluate(ptr: i32, len: i32) -> i32'")?;

    let result = evaluate_func.call(&mut store, (input_ptr, input_len))?;

    // We assume 1 is allow, 0 is deny
    Ok(result != 0)
}
