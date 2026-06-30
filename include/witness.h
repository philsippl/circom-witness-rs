#pragma once
#include "rust/cxx.h"
#include <cstdint>
#include <memory>

typedef unsigned long long u64;
typedef uint32_t u32;
typedef uint8_t u8;

struct Circom_CalcWit;

// Each circuit's generated code lives in its own `wit_<name>` namespace.
// build.rs emits a dispatcher (src/dispatch.cc) implementing these functions,
// selecting the circuit by index.
void run(Circom_CalcWit *buf, uint32_t circuit);
uint get_size_of_io_map(uint32_t circuit);
uint get_total_signal_no(uint32_t circuit);
uint get_main_input_signal_no(uint32_t circuit);
uint get_main_input_signal_start(uint32_t circuit);
uint get_number_of_components(uint32_t circuit);
uint get_size_of_constants(uint32_t circuit);
uint get_size_of_input_hashmap(uint32_t circuit);
uint get_size_of_witness(uint32_t circuit);
