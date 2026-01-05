use anyhow::{Context, Result};
use wasmi::{Engine, Linker, Module, Store};

// Define the interface for the WASM module
// We'll use a simple interface:
// - Host provides `input` (JSON string)
// - WASM exports `evaluate(input_ptr: i32, input_len: i32) -> i32`

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
