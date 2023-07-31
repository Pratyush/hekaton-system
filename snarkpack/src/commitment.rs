use crate::inner_product;
use crate::Error;
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup,
};
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_iter, fmt::Debug, vec::Vec};
use rayon::prelude::*;
/// This module implements two binding commitment schemes used in the Groth16
/// aggregation.
/// The first one is a commitment scheme that commits to a single vector $a$ of
/// length n in the second base group $G_1$ (for example):
/// * it requires a structured SRS $v_1$ of the form $(h,h^u,h^{u^2}, ...
/// ,g^{h^{n-1}})$ with $h \in G_2$ being a random generator of $G_2$ and $u$ a
/// random scalar (coming from a power of tau ceremony for example)
/// * it requires a second structured SRS $v_2$ of the form $(h,h^v,h^{v^2},
/// ...$ with $v$ being a random scalar different than u (coming from another
/// power of tau ceremony for example)
/// The Commitment is a tuple $(\prod_{i=0}^{n-1} e(a_i,v_{1,i}),
/// \prod_{i=0}^{n-1} e(a_i,v_{2,i}))$
///
/// The second one takes two vectors $a \in G_1^n$ and $b \in G_2^n$ and commits
/// to them using a similar approach as above. It requires an additional SRS
/// though:
/// * $v_1$ and $v_2$ stay the same
/// * An additional tuple $w_1 = (g^{u^n},g^{u^{n+1}},...g^{u^{2n-1}})$ and $w_2 =
/// (g^{v^n},g^{v^{n+1},...,g^{v^{2n-1}})$ where $g$ is a random generator of
/// $G_1$
/// The commitment scheme returns a tuple:
/// * $\prod_{i=0}^{n-1} e(a_i,v_{1,i})e(w_{1,i},b_i)$
/// * $\prod_{i=0}^{n-1} e(a_i,v_{2,i})e(w_{2,i},b_i)$
///
/// The second commitment scheme enables to save some KZG verification in the
/// verifier of the Groth16 verification protocol since we pack two vectors in
/// one commitment.
/// Key is a generic commitment key that is instanciated with g and h as basis,
/// and a and b as powers.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Key<G: AffineRepr> {
    /// Exponent is a
    pub a: Vec<G>,
    /// Exponent is b
    pub b: Vec<G>,
}

/// Commitment key used by the "single" commitment on G1 values as
/// well as in the "pair" commtitment.
/// It contains $\{h^a^i\}_{i=1}^n$ and $\{h^b^i\}_{i=1}^n$
pub type VKey<E> = Key<<E as Pairing>::G2Affine>;

/// Commitment key used by the "pair" commitment. Note the sequence of
/// powers starts at $n$ already.
/// It contains $\{g^{a^{n+i}}\}_{i=1}^n$ and $\{g^{b^{n+i}}\}_{i=1}^n$
pub type WKey<E> = Key<<E as Pairing>::G1Affine>;

impl<G: AffineRepr> Key<G> {
    /// Returns true if commitment keys have the exact required length.
    /// It is necessary for the IPP scheme to work that commitment
    /// key have the exact same number of arguments as the number of proofs to
    /// aggregate.
    pub fn has_correct_len(&self, n: usize) -> bool {
        self.a.len() == n && self.b.len() == n
    }

    /// Returns both vectors scaled by the given vector entrywise.
    /// In other words, it returns $\{v_i^{s_i}\}$
    pub fn scale(&self, s: &[G::ScalarField]) -> Result<Self, Error> {
        if self.a.len() != s.len() {
            return Err(Error::InvalidKeyLength);
        }
        let (a, b): (Vec<_>, Vec<_>) = cfg_iter!(self.a)
            .zip(&self.b)
            .zip(s)
            .map(|((a, b), s)| (*a * s, *b * s))
            .unzip();
        let a = G::Group::normalize_batch(&a);
        let b = G::Group::normalize_batch(&b);

        Ok(Self { a, b })
    }

    /// Returns the left and right commitment key part. It makes copy.
    pub fn split(mut self, at: usize) -> (Self, Self) {
        let a_right = self.a.split_off(at);
        let b_right = self.b.split_off(at);
        (
            Self {
                a: self.a,
                b: self.b,
            },
            Self {
                a: a_right,
                b: b_right,
            },
        )
    }

    /// Takes a left and right commitment key and returns a commitment
    /// key $left \circ right^{scale} = (left_i*right_i^{scale} ...)$. This is
    /// required step during GIPA recursion.
    pub fn compress(&self, right: &Self, scale: G::ScalarField) -> Result<Self, Error> {
        let left = self;
        if left.a.len() != right.a.len() {
            return Err(Error::InvalidKeyLength);
        }
        let (a, b): (Vec<G::Group>, Vec<G::Group>) = cfg_iter!(&left.a)
            .zip(&left.b)
            .zip(cfg_iter!(&right.a).zip(&right.b))
            .map(|((l_a, l_b), (&r_a, &r_b))| (r_a * scale + l_a, r_b * scale + l_b))
            .unzip();
        let a = G::Group::normalize_batch(&a);
        let b = G::Group::normalize_batch(&b);

        Ok(Self { a, b })
    }

    /// Returns the first values in the vector of v1 and v2 (respectively
    /// w1 and w2). When commitment key is of size one, it's a proxy to get the
    /// final values.
    pub fn first(&self) -> (G, G) {
        (self.a[0], self.b[0])
    }
}

/// Commitments for both CM_S and `CM_D` consists of a of [`PairingOutput`] elements.
#[derive(PartialEq, CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct Commitment<E: Pairing> {
    pub t: PairingOutput<E>,
    pub u: PairingOutput<E>,
}

impl<E: Pairing> Commitment<E> {
    pub fn new(t: PairingOutput<E>, u: PairingOutput<E>) -> Self {
        Self { t, u }
    }
}

impl<E: Pairing> Default for Commitment<E> {
    fn default() -> Self {
        Self {
            t: PairingOutput(E::TargetField::ONE),
            u: PairingOutput(E::TargetField::ONE),
        }
    }
}

/// Commits to a single vector of G1 elements in the following way:
/// $T = \prod_{i=0}^n e(A_i, v_{1,i})$
/// $U = \prod_{i=0}^n e(A_i, v_{2,i})$
/// Output is $(T,U)$
pub fn commit_single<E: Pairing>(
    vkey: &VKey<E>,
    a_s: &[E::G1Affine],
) -> Result<Commitment<E>, Error> {
    try_par! {
        let t = inner_product::pairing::<E>(a_s, &vkey.a),
        let u = inner_product::pairing::<E>(a_s, &vkey.b)
    };
    Ok(Commitment { t, u })
}

/// Commits to a tuple of G1 vector and G2 vector in the following way:
/// $T = \prod_{i=0}^n e(A_i, v_{1,i})e(B_i,w_{1,i})$
/// $U = \prod_{i=0}^n e(A_i, v_{2,i})e(B_i,w_{2,i})$
/// Output is $(T,U)$
pub fn commit_double<E: Pairing>(
    vkey: &VKey<E>,
    wkey: &WKey<E>,
    a: &[E::G1Affine],
    b: &[E::G2Affine],
) -> Result<Commitment<E>, Error> {
    try_par! {
        // (A * v)
        let t1 = inner_product::pairing::<E>(a, &vkey.a),
        // (w * B)
        let t2 = inner_product::pairing::<E>(&wkey.a, b),
        let u1 = inner_product::pairing::<E>(a, &vkey.b),
        let u2 = inner_product::pairing::<E>(&wkey.b, b)
    };
    Ok(Commitment {
        t: t1 + t2,
        u: u1 + u2,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::srs::structured_generators_scalar_power;
    use ark_bls12_381::{Bls12_381 as Bls12, Fr, G1Projective, G2Projective};
    use ark_ec::Group;
    use ark_std::UniformRand;
    use rand_core::SeedableRng;

    #[test]
    fn test_commit_single() {
        let n = 6;
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(0u64);
        let h = G2Projective::generator();
        let u = Fr::rand(&mut rng);
        let v = Fr::rand(&mut rng);
        let v1 = structured_generators_scalar_power(n, &h, &u);
        let v2 = structured_generators_scalar_power(n, &h, &v);
        let vkey = VKey::<Bls12> { a: v1, b: v2 };
        let a = (0..n)
            .map(|_| G1Projective::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();
        let c1 = commit_single::<Bls12>(&vkey, &a).unwrap();
        let c2 = commit_single::<Bls12>(&vkey, &a).unwrap();
        assert_eq!(c1, c2);
        let b = (0..n)
            .map(|_| G1Projective::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();
        let c3 = commit_single::<Bls12>(&vkey, &b).unwrap();
        assert!(c1 != c3);
    }

    #[test]
    fn test_commit_pair() {
        let n = 6;
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(0u64);
        let h = G2Projective::generator();
        let g = G1Projective::generator();
        let u = Fr::rand(&mut rng);
        let v = Fr::rand(&mut rng);
        let v1 = structured_generators_scalar_power(n, &h, &u);
        let v2 = structured_generators_scalar_power(n, &h, &v);
        let w1 = structured_generators_scalar_power(2 * n, &g, &u);
        let w2 = structured_generators_scalar_power(2 * n, &g, &v);

        let vkey = VKey::<Bls12> { a: v1, b: v2 };
        let wkey = WKey::<Bls12> {
            a: w1[n..].to_vec(),
            b: w2[n..].to_vec(),
        };
        let a = (0..n)
            .map(|_| G1Projective::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();
        let b = (0..n)
            .map(|_| G2Projective::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();
        let c1 = commit_double::<Bls12>(&vkey, &wkey, &a, &b).unwrap();
        let c2 = commit_double::<Bls12>(&vkey, &wkey, &a, &b).unwrap();
        assert_eq!(c1, c2);
        commit_double::<Bls12>(&vkey, &wkey, &a[1..2], &b).expect_err("this should have failed");
    }
}
