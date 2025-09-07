use crate::{graph::{Node, Operation}, M};
use rand::Rng;
use ruint::aliases::U256;
use std::{ptr, sync::Mutex};

pub const INV: u64 = 14042775128853446655;

static NODES: Mutex<Vec<Node>> = Mutex::new(Vec::new());
static VALUES: Mutex<Vec<U256>> = Mutex::new(Vec::new());
static CONSTANT: Mutex<Vec<bool>> = Mutex::new(Vec::new());

#[derive(Debug, Default, Clone, Copy)]
pub struct FrElement(pub usize);

#[allow(warnings)]
pub fn print_eval() {
    let nodes = NODES.lock().unwrap();
    let values = VALUES.lock().unwrap();
    let constant = CONSTANT.lock().unwrap();

    let mut constants = 0_usize;
    for (i, node) in nodes.iter().enumerate() {
        print!("{}: {:?}", i, node);
        if constant[i] {
            constants += 1;
            println!(" = {}", values[i]);
        } else {
            println!();
        }
    }
    eprintln!(
        "{} nodes of which {} constant and {} dynamic",
        nodes.len(),
        constants,
        nodes.len() - constants
    );
}

pub fn get_graph() -> Vec<Node> {
    NODES.lock().unwrap().clone()
}

pub fn undefined(i: usize) -> FrElement {
    FrElement(i)
}

pub fn constant(c: U256) -> FrElement {
    let mut nodes = NODES.lock().unwrap();
    let mut values = VALUES.lock().unwrap();
    let mut constant = CONSTANT.lock().unwrap();
    assert_eq!(nodes.len(), values.len());
    assert_eq!(nodes.len(), constant.len());

    nodes.push(Node::Constant(c));
    values.push(c);
    constant.push(true);

    FrElement(nodes.len() - 1)
}

pub fn input(i: usize, value: U256) -> FrElement {
    let mut nodes = NODES.lock().unwrap();
    let mut values = VALUES.lock().unwrap();
    let mut constant = CONSTANT.lock().unwrap();
    assert_eq!(nodes.len(), values.len());
    assert_eq!(nodes.len(), constant.len());

    nodes.push(Node::Input(i));
    values.push(value);
    constant.push(false);

    FrElement(nodes.len() - 1)
}

fn binop(op: Operation, to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    let mut nodes = NODES.lock().unwrap();
    let mut values = VALUES.lock().unwrap();
    let mut constant = CONSTANT.lock().unwrap();
    assert_eq!(nodes.len(), values.len());
    assert_eq!(nodes.len(), constant.len());

    let (a, b, to) = unsafe { ((*a).0, (*b).0, &mut (*to).0) };
    assert!(a < nodes.len());
    assert!(b < nodes.len());
    nodes.push(Node::Op(op, a, b));
    *to = nodes.len() - 1;

    let (va, vb) = (values[a], values[b]);
    values.push(op.eval(va, vb));

    let (ca, cb) = (constant[a], constant[b]);
    constant.push(ca && cb);
}

#[allow(warnings)]
pub fn Fr_mul(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Mul, to, a, b);
}

#[allow(warnings)]
pub unsafe fn Fr_add(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Add, to, a, b);
}

#[allow(warnings)]
pub unsafe fn Fr_sub(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Sub, to, a, b);
}

#[allow(warnings)]
pub fn Fr_copy(to: *mut FrElement, a: *const FrElement) {
    unsafe {
        *to = *a;
    }
}

#[allow(warnings)]
pub fn Fr_copyn(to: *mut FrElement, a: *const FrElement, n: usize) {
    unsafe {
        ptr::copy_nonoverlapping(a, to, n);
    }
}

/// Create a vector of FrElement with length `len`.
/// Needed because the default constructor of opaque type is not implemented.
#[allow(warnings)]
pub fn create_vec(len: usize) -> Vec<FrElement> {
    (0..len).map(|i| FrElement(i)).collect()
}

#[allow(warnings)]
pub fn create_vec_u32(len: usize) -> Vec<u32> {
    vec![0; len]
}

#[allow(warnings)]
pub fn generate_position_array(
    prefix: String,
    dimensions: Vec<u32>,
    size_dimensions: u32,
    index: u32,
) -> String {
    let mut positions: String = prefix;
    let mut index = index;
    for i in 0..size_dimensions {
        let last_pos = index % dimensions[size_dimensions as usize - 1 - i as usize];
        index /= dimensions[size_dimensions as usize - 1 - i as usize];
        let new_pos = format!("[{}]", last_pos);
        positions = new_pos + &positions;
    }
    positions
}

#[allow(warnings)]
pub unsafe fn Fr_toInt(a: *const FrElement) -> u64 {
    let nodes = NODES.lock().unwrap();
    let values = VALUES.lock().unwrap();
    let constant = CONSTANT.lock().unwrap();
    assert_eq!(nodes.len(), values.len());
    assert_eq!(nodes.len(), constant.len());

    let a = unsafe { (*a).0 };
    assert!(a < nodes.len());
    assert!(constant[a]);
    values[a].try_into().unwrap()
}

#[allow(warnings)]
pub unsafe fn print(a: *const FrElement) {
    println!("DEBUG>> {:?}", (*a).0);
}

#[allow(warnings)]
pub fn Fr_isTrue(a: *mut FrElement) -> bool {
    let nodes = NODES.lock().unwrap();
    let values = VALUES.lock().unwrap();
    let constant = CONSTANT.lock().unwrap();
    assert_eq!(nodes.len(), values.len());
    assert_eq!(nodes.len(), constant.len());

    let a = unsafe { (*a).0 };
    assert!(a < nodes.len());
    assert!(constant[a]);
    values[a] != U256::ZERO
}

#[allow(warnings)]
pub unsafe fn Fr_eq(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Eq, to, a, b);
}

#[allow(warnings)]
pub unsafe fn Fr_neq(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Neq, to, a, b);
}

#[allow(warnings)]
pub unsafe fn Fr_lt(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Lt, to, a, b);
}

#[allow(warnings)]
pub unsafe fn Fr_gt(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Gt, to, a, b);
}

#[allow(warnings)]
pub unsafe fn Fr_leq(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Leq, to, a, b);
}

#[allow(warnings)]
pub unsafe fn Fr_geq(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Geq, to, a, b);
}

#[allow(warnings)]
pub unsafe fn Fr_lor(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Lor, to, a, b);
}

#[allow(warnings)]
pub unsafe fn Fr_shl(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Shl, to, a, b);
}

#[allow(warnings)]
pub unsafe fn Fr_shr(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Shr, to, a, b);
}

#[allow(warnings)]
pub unsafe fn Fr_band(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Band, to, a, b);
}

#[allow(warnings)]
pub unsafe fn Fr_neg(to: *mut FrElement, a: *const FrElement) {
    binop(Operation::Neg, to, a, a);
}

#[allow(warnings)]
pub unsafe fn Fr_inv(to: *mut FrElement, a: *const FrElement) {
    binop(Operation::Inv, to, a, a);
}

#[allow(warnings)]
pub unsafe fn Fr_div(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Div, to, a, b);
}

#[allow(warnings)]
pub unsafe fn Fr_pow(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Pow, to, a, b);
}

#[allow(warnings)]
pub unsafe fn Fr_land(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Land, to, a, b);
}

#[allow(warnings)]
pub unsafe fn Fr_idiv(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::IDiv, to, a, b);
}

#[allow(warnings)]
pub unsafe fn bbf(component_name: String, lvarcall: &Vec<FrElement>, destination: *mut FrElement) {
    let mut nodes = NODES.lock().unwrap();
    let mut values = VALUES.lock().unwrap();
    let mut constant = CONSTANT.lock().unwrap();
    assert_eq!(nodes.len(), values.len());
    assert_eq!(nodes.len(), constant.len());

    let params = lvarcall.iter().map(|x| x.0).collect();
    nodes.push(Node::BBF(component_name, params));
    let destination = unsafe { &mut (*destination).0 };
    *destination = nodes.len() - 1;

    let mut rng = rand::thread_rng();
    values.push(rng.gen::<U256>() % M);

    constant.push(false);
}