(module
  (import "env" "alloc" (func $alloc (param i32) (result i32)))
  (memory (export "memory") 1)

  ;; Helper to allocate memory (simple bump pointer, leaks memory but fine for one-shot)
  (global $heap_ptr (mut i32) (i32.const 1024))
  (func (export "alloc") (param $size i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $heap_ptr))
    (global.set $heap_ptr (i32.add (global.get $heap_ptr) (local.get $size)))
    (local.get $ptr)
  )

  (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
    ;; For testing, we just return 1 (allow)
    i32.const 1
  )
)
