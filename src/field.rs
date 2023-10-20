use std::ptr;

use ruint::{aliases::U256, uint};

#[derive(Debug, Default, Clone, Copy)]
pub struct FrElement(pub U256);

pub const M: U256 =
    uint!(21888242871839275222246405745257275088548364400416034343698204186575808495617_U256);

pub const INV: u64 = 14042775128853446655;

pub const R: U256 = uint!(0x0e0a77c19a07df2f666ea36f7879462e36fc76959f60cd29ac96341c4ffffffb_U256);

#[allow(warnings)]
pub fn Fr_mul(to: &mut FrElement, a: &FrElement, b: &FrElement) {
    to.0 = a.0.mul_mod(b.0, M);
}

#[allow(warnings)]
pub fn Fr_add(to: &mut FrElement, a: &FrElement, b: &FrElement) {
    to.0 = a.0.add_mod(b.0, M);
}

#[allow(warnings)]
pub fn Fr_sub(to: &mut FrElement, a: &FrElement, b: &FrElement) {
    to.0 = a.0.add_mod(-b.0, M);
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
