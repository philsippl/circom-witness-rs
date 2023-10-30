mod field;

use std::{env, io::Read, str::FromStr, time::Instant};

use byteorder::{LittleEndian, ReadBytesExt};
use ffi::InputOutputList;
use field::*;
use ruint::{aliases::U256, uint};
use serde_json::Value;

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
        templateId: u64,
        signalStart: u64,
        inputCounter: u64,
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
        unsafe fn Fr_lor(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn print(a: *mut FrElement);
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

const DAT_BYTES: &[u8] = include_bytes!("semaphore.dat");

#[derive(Debug, Default, Clone)]
pub struct HashSignalInfo {
    pub hash: u64,
    pub signalid: u64,
    pub signalsize: u64,
}

pub fn get_input_hash_map() -> Vec<HashSignalInfo> {
    let mut bytes = &DAT_BYTES[..(ffi::get_size_of_input_hashmap() as usize) * 24];
    let mut input_hash_map = vec![HashSignalInfo::default(); ffi::get_size_of_input_hashmap() as usize];
    for i in 0..ffi::get_size_of_input_hashmap() as usize {
        let hash = bytes.read_u64::<LittleEndian>().unwrap();
        let signalid = bytes.read_u64::<LittleEndian>().unwrap();
        let signalsize = bytes.read_u64::<LittleEndian>().unwrap();
        input_hash_map[i] = HashSignalInfo {
            hash,
            signalid,
            signalsize,
        };
    }
    input_hash_map
}

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
    let hashmap_size = ffi::get_size_of_input_hashmap() as usize;
    let mut indices = vec![0usize; io_size];
    let mut map: Vec<InputOutputList> = vec![InputOutputList::default(); hashmap_size];

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
        map[indices[i] % hashmap_size] = io_list;
    });
    map
}

fn fnv1a(s: &str) -> u64 {
    let mut hash: u64 = 0xCBF29CE484222325;
    for c in s.bytes() {
        hash ^= c as u64;
        hash = hash.wrapping_mul(0x100000001B3);
    }
    hash
}

fn set_input_signal(input_hashmap: Vec<HashSignalInfo>, signal_values: &mut Vec<FrElement>, h: u64, i: u64, val: FrElement) {
    let pos = input_hashmap.iter().position(|x| x.hash == h).unwrap();
    let si = input_hashmap[pos].signalid + i;
    signal_values[si as usize] = val;
}

fn main() {
    let mut signal_values = vec![FrElement(uint!(0_U256)); ffi::get_total_signal_no() as usize];
    signal_values[0] = FrElement(uint!(1_U256).mul_mod(R, M));

    let data = r#"
    {
        "identityNullifier": "0x099ab25e555083e656e9ec66a5368d1edd3314bd2dc77553813c5145d37326a3",
        "identityTrapdoor": "0x1db60e4cd8008edd85c68d461bf00d04f1620372f45c6ffacdb1a318791c2dd3",
        "treePathIndices": [
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0"
        ],
        "treeSiblings": [
            "0x0",
            "0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864",
            "0x1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1",
            "0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238",
            "0x07f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952a",
            "0x2b94cf5e8746b3f5c9631f4c5df32907a699c58c94b2ad4d7b5cec1639183f55",
            "0x2dee93c5a666459646ea7d22cca9e1bcfed71e6951b953611d11dda32ea09d78",
            "0x078295e5a22b84e982cf601eb639597b8b0515a88cb5ac7fa8a4aabe3c87349d",
            "0x2fa5e5f18f6027a6501bec864564472a616b2e274a41211a444cbe3a99f3cc61",
            "0x0e884376d0d8fd21ecb780389e941f66e45e7acce3e228ab3e2156a614fcd747",
            "0x1b7201da72494f1e28717ad1a52eb469f95892f957713533de6175e5da190af2",
            "0x1f8d8822725e36385200c0b201249819a6e6e1e4650808b5bebc6bface7d7636",
            "0x2c5d82f66c914bafb9701589ba8cfcfb6162b0a12acf88a8d0879a0471b5f85a",
            "0x14c54148a0940bb820957f5adf3fa1134ef5c4aaa113f4646458f270e0bfbfd0",
            "0x190d33b12f986f961e10c0ee44d8b9af11be25588cad89d416118e4bf4ebe80c",
            "0x22f98aa9ce704152ac17354914ad73ed1167ae6596af510aa5b3649325e06c92"
        ],
        "externalNullifier": "0x00fd3a1e9736c12a5d4a31f26362b577ccafbd523d358daf40cdc04d90e17f77",
        "signalHash": "0x00bc6bb462e38af7da48e0ae7b5cbae860141c04e5af2cf92328cd6548df111f"
    }"#;

    let input_map = get_input_hash_map();

    let v: Value = serde_json::from_str(data).unwrap();
    if let Value::Object(map) = v {
        for (key, value) in map {
            let h = fnv1a(key.as_str());
            if value.is_array() {
                for (idx, item) in value.as_array().unwrap().iter().enumerate() {
                    let x = U256::from_str(item.as_str().unwrap()).unwrap();
                    set_input_signal(input_map.clone(), &mut signal_values, h, idx as u64, FrElement(x.mul_mod(R, M)));
                }
            } else {
                let x = U256::from_str(value.as_str().unwrap()).unwrap();
                set_input_signal(input_map.clone(), &mut signal_values, h, 0, FrElement(x.mul_mod(R, M)));
            }
        }
    } 

    // for i in 0..signal_values.len() {
    //     println!(
    //         "signalValues[{}]: {:?}",
    //         i,
    //         signal_values[i].0
    //     );
    // }

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
