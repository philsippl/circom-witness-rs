mod field;

use std::{env, io::Read, str::FromStr, time::Instant};

use byteorder::{LittleEndian, ReadBytesExt};
use ffi::InputOutputList;
use field::*;
use ruint::{aliases::U256, uint};

#[cxx::bridge]
mod ffi {

    #[derive(Debug, Default, Clone)]
    pub struct InputOutputList {
        pub defs: Vec<IODef>,
    }

    #[derive(Debug, Clone, Default)]
    pub struct IODef {
        pub code: usize,
        pub offset: usize,
        pub lengths: Vec<usize>,
    }

    #[derive(Debug, Default, Clone)]
    struct Circom_Component {
        templateId: u32,
        signalStart: u64,
        inputCounter: u32,
        templateName: String,
        componentName: String,
        idFather: u64,
        subcomponents: Vec<u32>,
        outputIsSet: Vec<bool>,
    }

    #[derive(Debug)]
    struct Circom_CalcWit {
        signalValues: Vec<FrElement>,
        componentMemory: Vec<Circom_Component>,
        circuitConstants: Vec<FrElement>,
        templateInsId2IOSignalInfoList: Vec<InputOutputList>,
        listOfTemplateMessages: Vec<String>,
    }

    // Rust types and signatures exposed to C++.
    extern "Rust" {
        type FrElement;

        fn create_vec(len: usize) -> Vec<FrElement>;
        fn create_vec_u32(len: usize) -> Vec<u32>;
        fn generate_position_array(
            prefix: String,
            dimensions: Vec<u32>,
            size_dimensions: u32,
            index: u32,
        ) -> String;

        // Field operations
        unsafe fn Fr_mul(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_add(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_sub(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_copy(to: *mut FrElement, a: *const FrElement);
        unsafe fn Fr_copyn(to: *mut FrElement, a: *const FrElement, n: usize);
        // fn Fr_neg(to: &mut FrElement, a: &FrElement);
        // fn Fr_inv(to: &mut FrElement, a: &FrElement);
        // fn Fr_div(to: &mut FrElement, a: &FrElement, b: &FrElement);
        // fn Fr_square(to: &mut FrElement, a: &FrElement);
        // fn Fr_shl(to: &mut FrElement, a: &FrElement, b: u32);
        // fn Fr_shr(to: &mut FrElement, a: &FrElement, b: u32);
        // fn Fr_band(to: &mut FrElement, a: &FrElement, b: &FrElement);
        // fn Fr_bor(to: &mut FrElement, a: &FrElement, b: &FrElement);
        // fn Fr_bxor(to: &mut FrElement, a: &FrElement, b: &FrElement);
        // fn Fr_bnot(to: &mut FrElement, a: &FrElement);
        unsafe fn Fr_eq(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_neq(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_lt(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_gt(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_leq(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_geq(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_isTrue(a: *mut FrElement) -> bool;
        // fn Fr_fromBool(to: &mut FrElement, a: bool);
        unsafe fn Fr_toInt(a: *mut FrElement) -> u64;
        // fn Fr_pow(to: &mut FrElement, a: &FrElement, b: &FrElement);
        // fn Fr_idiv(to: &mut FrElement, a: &FrElement, b: &FrElement);
    }

    // C++ types and signatures exposed to Rust.
    unsafe extern "C++" {
        include!("witness/include/blobstore.h");

        unsafe fn run(ctx: *mut Circom_CalcWit);
        fn get_size_of_io_map() -> u32;
        fn get_total_signal_no() -> u32;
        fn get_main_input_signal_no() -> u32;
        fn get_main_input_signal_start() -> u32;
        fn get_number_of_components() -> u32;
        fn get_size_of_constants() -> u32;
        fn get_size_of_input_hashmap() -> u32;
        fn get_size_of_witness() -> u32;
    }
}

const DAT_BYTES: &[u8] = include_bytes!("poseidon.dat");

pub fn get_constants() -> Vec<FrElement> {
    if ffi::get_size_of_constants() == 0 {
        return vec![];
    }

    // skip the first part
    let mut bytes = &DAT_BYTES[(ffi::get_size_of_input_hashmap() as usize) * 24
        + (ffi::get_size_of_witness() as usize) * 8..];
    let mut constants = vec![FrElement(U256::from(0)); ffi::get_size_of_constants() as usize];
    for i in 0..ffi::get_size_of_constants() as usize {
        let sv = bytes.read_i32::<LittleEndian>().unwrap() as i32;
        let typ = bytes.read_u32::<LittleEndian>().unwrap() as u32;

        let mut buf = [0; 32];
        bytes.read_exact(&mut buf);

        if typ & 0x80000000 == 0 {
            constants[i] = FrElement(U256::from(sv).mul_mod(R, M));
        } else {
            constants[i] = FrElement(U256::from_le_bytes(buf));
        }
    }

    return constants;
}

pub fn get_iosignals() -> Vec<InputOutputList> {
    if ffi::get_size_of_io_map() == 0 {
        return vec![];
    }

    // skip the first part
    let mut bytes = &DAT_BYTES[(ffi::get_size_of_input_hashmap() as usize) * 24
        + (ffi::get_size_of_witness() as usize) * 8
        + (ffi::get_size_of_constants() as usize * 40)..];
    let io_size = ffi::get_size_of_io_map() as usize;
    let mut indices = vec![0usize; io_size];
    let mut map: Vec<InputOutputList> = vec![InputOutputList::default(); io_size];

    (0..io_size).for_each(|i| {
        let t32 = bytes.read_u32::<LittleEndian>().unwrap() as usize;
        indices[i] = t32;
    });

    (0..io_size).for_each(|i| {
        let l32 = bytes.read_u32::<LittleEndian>().unwrap() as usize;
        let mut io_list: InputOutputList = InputOutputList { defs: vec![] };

        (0..l32).for_each(|_j| {
            let offset = bytes.read_u32::<LittleEndian>().unwrap() as usize;
            let len = bytes.read_u32::<LittleEndian>().unwrap() as usize + 1;

            let mut lengths = vec![0usize; len];

            (1..len).for_each(|k| {
                lengths[k] = bytes.read_u32::<LittleEndian>().unwrap() as usize;
            });

            io_list.defs.push(ffi::IODef {
                code: 0,
                offset,
                lengths,
            });
        });
        map[indices[i] % io_size] = io_list;
    });
    map
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut signal_values = vec![FrElement(uint!(0_U256)); ffi::get_total_signal_no() as usize];
    signal_values[0] = FrElement(uint!(1_U256).mul_mod(R, M));

    for (i, w) in args.into_iter().skip(1).enumerate() {
        signal_values[ffi::get_main_input_signal_start() as usize + i] =
            FrElement(U256::from_str(&w).unwrap().mul_mod(R, M));
    }

    let mut ctx = ffi::Circom_CalcWit {
        signalValues: signal_values,
        componentMemory: vec![
            ffi::Circom_Component::default();
            ffi::get_number_of_components() as usize
        ],
        circuitConstants: get_constants(),
        templateInsId2IOSignalInfoList: get_iosignals(),
        listOfTemplateMessages: vec![],
    };

    // measure time
    let now = Instant::now();
    unsafe {
        ffi::run(&mut ctx as *mut _);
    }
    println!("calculation took: {:?}", now.elapsed());

    for i in 0..ctx.signalValues.len() {
        println!(
            "signalValues[{}]: {:?}",
            i,
            ctx.signalValues[i].0.mul_redc(uint!(1_U256), M, INV)
        );
    }
}
