;; Get 2 params, 32bits offset and 64bits to write
(module
    (memory 1)

    (func (export "write")
        (param $offset i32)  ;; Offset within memory
        (param $value i64)   ;; 64-bit integer to write
        (i64.store  
            (local.get $offset)  ;; Get the memory offset
            (local.get $value)   ;; Get the i64 value
        )
    )

    (func (export "nop")
        nop
    )
)