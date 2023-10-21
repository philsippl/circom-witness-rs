#pragma once
#include "rust/cxx.h"
#include <memory>

typedef unsigned long long u64;
typedef uint32_t u32;
typedef uint8_t u8;

struct Circom_CalcWit;

void run(Circom_CalcWit *buf);
uint get_size_of_io_map();
