use std::ptr;

use ruint::{aliases::U256, uint};

#[derive(Debug, Default, Clone, Copy)]
pub struct FrElement(pub U256);

pub const M: U256 =
    uint!(21888242871839275222246405745257275088548364400416034343698204186575808495617_U256);

pub const INV: u64 = 14042775128853446655;

pub const R: U256 = uint!(0x0e0a77c19a07df2f666ea36f7879462e36fc76959f60cd29ac96341c4ffffffb_U256);

#[allow(warnings)]
pub unsafe fn Fr_mul(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    (*to).0 = (*a).0.mul_mod((*b).0, M);
}

#[allow(warnings)]
pub unsafe fn Fr_add(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    (*to).0 = (*a).0.add_mod((*b).0, M);
}

#[allow(warnings)]
pub unsafe fn Fr_sub(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    (*to).0 = (*a).0.add_mod((M - (*b).0), M);
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
pub fn create_vec(len: usize) -> Vec<FrElement> {
    vec![FrElement(U256::from(0)); len]
}

pub fn create_vec_u32(len: usize) -> Vec<u32> {
    vec![0; len]
}

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

pub unsafe fn Fr_toInt(a: *const FrElement) -> u64 {
    (*a).0.as_limbs()[0]
}

pub unsafe fn print(a: *const FrElement) {
    println!("DEBUG>> {:?}", (*a).0);
}

pub unsafe fn Fr_isTrue(a: *mut FrElement) -> bool {
    (*a).0 != U256::from(0)
}

pub unsafe fn Fr_eq(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    (*to).0 = U256::from(((*a).0 == (*b).0) as i32);
}

pub unsafe fn Fr_neq(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    (*to).0 = U256::from(((*a).0 != (*b).0) as i32);
}

pub unsafe fn Fr_lt(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    (*to).0 = U256::from(
        ((*a).0 < (*b).0) as i32,
    );
}

pub unsafe fn Fr_gt(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    (*to).0 = U256::from(
        ((*a).0 > (*b).0) as i32,
    );
}

pub unsafe fn Fr_leq(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    (*to).0 = U256::from(
        ((*a).0 <= (*b).0) as i32,
    );
}

pub unsafe fn Fr_geq(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    (*to).0 = U256::from(
        ((*a).0 >= (*b).0) as i32,
    );
}

pub unsafe fn Fr_lor(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    (*to).0 = U256::from(
        (Fr_isTrue(&mut FrElement((*a).0 + (*b).0))) as i32,
    );
}