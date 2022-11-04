use core::{
    fmt::Debug,
    ops::{BitAnd, BitOr, BitXor, Div, Not, Rem},
};

use ark_ff::PrimeField;
use ark_r1cs_std::{
    bits::ToBitsGadget, boolean::Boolean, eq::EqGadget, fields::fp::FpVar, select::CondSelectGadget,
};
use ark_relations::r1cs::SynthesisError;

pub trait WordVar<F: PrimeField>:
    Debug
    + Default
    + Eq
    + Ord
    + Copy
    + Div<Output = Self>
    + Rem<Output = Self>
    + Not<Output = Self>
    + BitOr<Output = Self>
    + BitXor<Output = Self>
    + BitAnd<Output = Self>
    + EqGadget<F>
    + CondSelectGadget<F>
    + ToBitsGadget<F>
{
    type Signed: Eq + Ord + Copy;

    type NativeWord: tinyram_emu::word::Word;

    /// Convert `self` to a field element
    fn to_fpvar(self) -> FpVar<F>;

    /// Convert `self` to a `BIT_SIZE`-bit signed integer.
    fn to_signed(self) -> Self::Signed;

    /// Returns `(self + 1, overflow)`
    fn checked_increment(self) -> (Self, Boolean<F>);

    /// Computes the sum of `self` and `other`, and returns the carry bit (if any).
    fn carrying_add(self, other: Self) -> Result<(Self, Boolean<F>), SynthesisError>;

    /// Computes `self - other`, and returns the carry bit (if any).
    fn borrowing_sub(self, other: Self) -> (Self, Boolean<F>);

    /// Computes the `BIT_SIZE` least-significant bits of `self * other`,
    /// and returns 1 if the full product does not fit in `BIT_SIZE` bits.
    fn mul_low(self, other: Self) -> (Self, Boolean<F>);

    /// Computes the `BIT_SIZE` most-significant bits of `self * other`,
    /// and returns 1 if the product does not fit in `BIT_SIZE` bits.
    fn mul_high(self, other: Self) -> (Self, Boolean<F>);

    /// Computes the `BIT_SIZE` most-significant bits of `self * other`,
    /// when `self` and `other` are viewed as `BIT_SIZE`-bit signed integers.
    /// and returns 1 if the product does not fit in `BIT_SIZE` bits.
    fn signed_mul_high(self, other: Self) -> (Self, Boolean<F>);

    /// Computes `self / other`, where `/` represents unsigned integer division.
    /// If `other` is 0, returns `(0, true)`.
    /// Else, this method returns `(self / other, false)`.
    fn checked_div(self, other: Self) -> (Self, Boolean<F>);

    /// Computes `self % other`.
    /// If `other` is 0, returns `(0, true)`.
    /// Else, this method returns `(self % other, false)`.
    fn checked_rem(self, other: Self) -> (Self, Boolean<F>);

    /// Computes `self << other`, and additionally returns the MSB of the result.
    fn shl(self, other: Self) -> (Self, Boolean<F>);

    /// Computes `self >> other`, and additionally returns the LSB of the result.
    fn shr(self, other: Self) -> (Self, Boolean<F>);
}
