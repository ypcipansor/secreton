#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Simple fuzz target that just exercises basic operations
    if data.len() > 0 {
        let _first_byte = data[0];
        // Just some basic operations to trigger code paths
        let _sum: u64 = data.iter().map(|&x| x as u64).sum();
        let _len = data.len();
    }
});
