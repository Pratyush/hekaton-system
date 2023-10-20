use ark_ec::{
    short_weierstrass::{Affine, SWCurveConfig},
    AffineRepr,
};
use ark_ff::Field;

pub trait AffineReprExt: AffineRepr
where
    Self::BaseField: Half,
{
    /// Performs the first half of batch addition in-place.
    fn batch_add_loop_1(
        a: &mut Self,
        b: &mut Self,
        half: &Self::BaseField, // The value 2.inverse().
        inversion_tmp: &mut Self::BaseField,
    );

    /// Performs the second half of batch addition in-place.
    fn batch_add_loop_2(a: &mut Self, b: Self, inversion_tmp: &mut Self::BaseField);
}

pub trait Half: Field {
    /// The value 2.inverse().
    const HALF: Self;
}

impl Half for crate::Fq {
    const HALF: Self = ark_ff::MontFp!("2001204777610833696708894912867952078278441409969503942666029068062015825245418932221343814564507832018947136279894");
}

impl Half for crate::Fq2 {
    const HALF: Self = Self::new(crate::Fq::HALF, crate::Fq::ZERO);
}

#[test]
fn half() {
    assert_eq!(crate::Fq::HALF, crate::Fq::ONE.double().inverse().unwrap());
    assert_eq!(
        crate::Fq2::HALF,
        crate::Fq2::ONE.double().inverse().unwrap()
    );
}

impl<C: SWCurveConfig> AffineReprExt for Affine<C>
where
    Self::BaseField: Half,
{
    /// Performs the first half of batch addition in-place:
    ///     `lambda` := `(y2 - y1) / (x2 - x1)`,
    /// for two given affine points.
    fn batch_add_loop_1(
        a: &mut Self,
        b: &mut Self,
        half: &Self::BaseField,
        inversion_tmp: &mut Self::BaseField,
    ) {
        if a.is_zero() || b.is_zero() {
        } else if a.x == b.x {
            // Double
            // In our model, we consider self additions rare.
            // So we consider it inconsequential to make them more expensive
            // This costs 1 modular mul more than a standard squaring,
            // and one amortised inversion
            if a.y == b.y {
                // Compute one half (1/2) and cache it.

                let x_sq = b.x.square();
                b.x -= &b.y; // x - y
                a.x = b.y.double(); // denominator = 2y
                a.y = x_sq.double() + x_sq + C::COEFF_A; // numerator = 3x^2 + a
                b.y -= &(a.y * half); // y - (3x^2 + a)/2
                a.y *= *inversion_tmp; // (3x^2 + a) * tmp
                *inversion_tmp *= &a.x; // update tmp
            } else {
                // No inversions take place if either operand is zero
                a.infinity = true;
                b.infinity = true;
            }
        } else {
            // We can recover x1 + x2 from this. Note this is never 0.
            a.x -= &b.x; // denominator = x1 - x2
            a.y -= &b.y; // numerator = y1 - y2
            a.y *= *inversion_tmp; // (y1 - y2)*tmp
            *inversion_tmp *= &a.x // update tmp
        }
    }

    /// Performs the second half of batch addition in-place:
    ///     `x3` := `lambda^2 - x1 - x2`
    ///     `y3` := `lambda * (x1 - x3) - y1`.
    fn batch_add_loop_2(a: &mut Self, b: Self, inversion_tmp: &mut Self::BaseField) {
        if a.is_zero() {
            *a = b;
        } else if !b.is_zero() {
            let lambda = a.y * *inversion_tmp;
            *inversion_tmp *= &a.x; // Remove the top layer of the denominator

            // x3 = l^2 - x1 - x2 or for squaring: 2y + l^2 + 2x - 2y = l^2 - 2x
            a.x += &b.x.double();
            a.x = lambda.square() - a.x;
            // y3 = l*(x2 - x3) - y2 or
            // for squaring: (3x^2 + a)/2y(x - y - x3) - (y - (3x^2 + a)/2) = l*(x - x3) - y
            a.y = lambda * (b.x - a.x) - b.y;
        }
    }
}
