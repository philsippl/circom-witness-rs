mod field;

use field::*;
use ruint::aliases::U256;

#[cxx::bridge]
mod ffi {

    #[derive(Debug)]
    pub struct InputOutputList {
        pub list: Vec<IODef>,
    }

    #[derive(Debug, Clone)]
    pub struct IODef {
        pub code: usize,
        pub offset: usize,
        pub lengths: Vec<usize>,
    }

    #[derive(Debug, Default)]
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
        // fn Fr_eq(a: &FrElement, b: &FrElement) -> bool;
        // fn Fr_neq(a: &FrElement, b: &FrElement) -> bool;
        // fn Fr_lt(a: &FrElement, b: &FrElement) -> bool;
        // fn Fr_gt(a: &FrElement, b: &FrElement) -> bool;
        // fn Fr_leq(a: &FrElement, b: &FrElement) -> bool;
        // fn Fr_geq(a: &FrElement, b: &FrElement) -> bool;
        // fn Fr_fromBool(to: &mut FrElement, a: bool);
        // fn Fr_toInt(a: &FrElement) -> u64;
        // fn Fr_pow(to: &mut FrElement, a: &FrElement, b: &FrElement);
        // fn Fr_idiv(to: &mut FrElement, a: &FrElement, b: &FrElement);
    }

    // C++ types and signatures exposed to Rust.
    unsafe extern "C++" {
        include!("witness/include/blobstore.h");

        unsafe fn run(ctx: *mut Circom_CalcWit);
    }
}

fn main() {
    let mut ctx = ffi::Circom_CalcWit {
        signalValues: vec![
            FrElement(U256::from(1)),
            FrElement(U256::from(1)),
            FrElement(U256::from(1)),
            FrElement(U256::from(1)),
            FrElement(U256::from(1)),
        ],
        componentMemory: vec![ffi::Circom_Component::default()],
        circuitConstants: vec![
            FrElement(U256::from(5)),
            FrElement(U256::from(5)),
            FrElement(U256::from(5)),
        ],
        templateInsId2IOSignalInfoList: vec![ffi::InputOutputList {
            list: vec![ffi::IODef {
                code: 0,
                offset: 0,
                lengths: vec![1],
            }],
        }],
        listOfTemplateMessages: vec!["".to_string()],
    };

    // ffi::run(&mut ctx);
    unsafe {
        ffi::run(&mut ctx as *mut _);
    }

    for i in 0..ctx.signalValues.len() {
        println!("signalValues[{}]: {:?}", i, ctx.signalValues[i].0);
    }

    dbg!(ctx);
}
