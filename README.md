# 🏎️ circom-witness-rs

## Benchmarks

### [semaphore-rs](https://github.com/worldcoin/semaphore-rs/tree/main)

```
cargo bench --bench=criterion --features=bench,depth_30
```

With `circom-witness-rs`:
```
witness_30              time:   [993.84 µs 996.62 µs 999.42 µs]
```

With wasm witness generator from [`circom-compat`](https://github.com/arkworks-rs/circom-compat/blob/master/src/witness/witness_calculator.rs):
```
witness_30              time:   [24.630 ms 24.693 ms 24.759 ms]
```

With native c++ witness generator from circom: `9.640ms`

**Result: For semaphore circuit (depth 30) `circom-witness-rs` is ~25x faster than wasm and ~10x faster than native c++ version**

