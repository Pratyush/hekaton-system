use ark_ec::pairing::{MillerLoopOutput, Pairing, PairingOutput};
use ark_ff::Field;
use ark_std::{rand::Rng, One, UniformRand, Zero};

/// PairingCheck represents a check of the form e(A,B)e(C,D)... = T. Checks can
/// be aggregated together using random linear combination. The efficiency comes
/// from keeping the results from the miller loop output before proceding to a final
/// exponentiation when verifying if all checks are verified.
/// It is a tuple:
/// - a miller loop result that is to be multiplied by other miller loop results
/// before going into a final exponentiation result
/// - a right side result which is already in the right subgroup Gt which is to
/// be compared to the left side when "final_exponentiatiat"-ed
#[derive(Debug, Copy, Clone)]
pub struct PairingCheck<E: Pairing> {
    left: <E as Pairing>::TargetField,
    right: <E as Pairing>::TargetField,
    /// simple counter tracking number of non_randomized checks. If there are
    /// more than 1 non randomized check, it is invalid.
    non_randomized: u8,
}

impl<E> PairingCheck<E>
where
    E: Pairing,
{
    pub(crate) fn new() -> PairingCheck<E> {
        Self {
            left: <E as Pairing>::TargetField::one(),
            right: <E as Pairing>::TargetField::one(),
            // a fixed "1 = 1" check doesn't count
            non_randomized: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_invalid() -> PairingCheck<E> {
        Self {
            left: <E as Pairing>::TargetField::one(),
            right: <E as Pairing>::TargetField::one() + <E as Pairing>::TargetField::one(),
            non_randomized: 2,
        }
    }

    /// Returns a pairing check from the output of the miller pairs and the
    /// expected right hand side such that the following must hold:
    /// $$
    ///   finalExponentiation(res) = exp
    /// $$
    ///
    /// Note the check is NOT randomized and there must be only up to ONE check
    /// only that can not be randomized when merging.
    fn from_pair(
        result: <E as Pairing>::TargetField,
        exp: <E as Pairing>::TargetField,
    ) -> PairingCheck<E> {
        Self {
            left: result,
            right: exp,
            non_randomized: 1,
        }
    }

    /// Returns a pairing check from the output of the miller pairs and the
    /// expected right hand side such that the following must hold:
    /// $$
    ///   finalExponentiation(\Prod_i lefts[i]) = exp
    /// $$
    ///
    /// Note the check is NOT randomized and there must be only up to ONE check
    /// only that can not be randomized when merging.
    pub fn from_products(
        lefts: Vec<<E as Pairing>::TargetField>,
        right: <E as Pairing>::TargetField,
    ) -> PairingCheck<E> {
        let product = lefts
            .iter()
            .fold(<E as Pairing>::TargetField::one(), |mut acc, l| {
                acc *= l;
                acc
            });
        Self::from_pair(product, right)
    }

    /// returns a pairing tuple that is scaled by a random element.
    /// When aggregating pairing checks, this creates a random linear
    /// combination of all checks so that it is secure. Specifically
    /// we have e(A,B)e(C,D)... = out <=> e(g,h)^{ab + cd} = out
    /// We rescale using a random element $r$ to give
    /// e(rA,B)e(rC,D) ... = out^r <=>
    /// e(A,B)^r e(C,D)^r = out^r <=> e(g,h)^{abr + cdr} = out^r
    /// (e(g,h)^{ab + cd})^r = out^r
    #[cfg(test)]
    pub fn rand(
        rng: impl Rng,
        it: &[(E::G1Affine, E::G2Affine)],
        out: &E::TargetField,
    ) -> PairingCheck<E> {
        #[cfg(test)]
        use ark_ff::PrimeField;
        #[cfg(test)]
        use rayon::prelude::*;

        let coeff: E::ScalarField = rand_scalar::<E>(rng);
        let miller_out = it
            .into_par_iter()
            .map(|&(a, b)| E::miller_loop(a * coeff, b).0)
            .product();
        let out = if !out.is_one() {
            // we only need to make this expensive operation is the output is
            // not one since 1^r = 1
            out.pow(&coeff.into_bigint())
        } else {
            *out
        };
        PairingCheck {
            left: miller_out,
            right: out,
            non_randomized: 0,
        }
    }

    /// takes another pairing tuple and combine both sides together. Note the checks are not
    /// randomized when merged, the checks must have been randomized before.
    pub(crate) fn merge(&mut self, p2: &PairingCheck<E>) {
        mul_assign_if_not_one(&mut self.left, &p2.left);
        mul_assign_if_not_one(&mut self.right, &p2.right);
        // A merged PairingCheck is only randomized if both of its contributors are.
        self.non_randomized += p2.non_randomized;
    }

    /// Returns false if there is more than 1 non-random check and otherwise
    /// returns true if
    /// $$
    ///   FinalExponentiation(left) == right
    /// $$
    pub fn verify(&self) -> bool {
        if self.non_randomized > 1 {
            dbg!(format!(
                "Pairing checks have more than 1 non-random checks {}",
                self.non_randomized
            ));
            return false;
        }
        E::final_exponentiation(MillerLoopOutput(self.left)) == Some(PairingOutput(self.right))
    }
}

fn rand_scalar<E: Pairing>(mut r: impl Rng) -> E::ScalarField {
    loop {
        let c = E::ScalarField::rand(&mut r);
        if !c.is_zero() {
            return c;
        }
    }
}

fn mul_assign_if_not_one<F: Field>(left: &mut F, right: &F) {
    if left.is_one() {
        *left = *right;
    } else if right.is_one() {
        // nothing to do here
    } else {
        *left *= right;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::{Bls12_381 as Bls12, G1Projective, G2Projective};
    use ark_ec::CurveGroup;
    use ark_std::{rand::Rng, UniformRand};
    use rand_core::SeedableRng;

    fn gen_pairing_check(mut r: impl Rng) -> PairingCheck<Bls12> {
        let g1r = G1Projective::rand(&mut r);
        let g2r = G2Projective::rand(&mut r);
        let exp = Bls12::pairing(g1r, g2r);
        let tuple =
            PairingCheck::<Bls12>::rand(&mut r, &[(g1r.into_affine(), g2r.into_affine())], &exp.0);
        assert!(tuple.verify());
        tuple
    }

    #[test]
    fn test_pairing_randomize() {
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(0u64);
        let tuples = (0..3)
            .map(|_| gen_pairing_check(&mut rng))
            .collect::<Vec<_>>();
        let final_tuple = tuples
            .iter()
            .fold(PairingCheck::<Bls12>::new(), |mut acc, tu| {
                acc.merge(&tu);
                acc
            });
        assert!(final_tuple.verify());
    }
}
