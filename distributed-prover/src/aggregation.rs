use crate::util::{G16Com, G16Proof, G16ProvingKey, ProtoTranscript, TranscriptProtocol};

use core::borrow::Borrow;

use ark_crypto_primitives::crh::sha256::{digest::Digest, Sha256};
use ark_ec::{
    pairing::{MillerLoopOutput, Pairing, PairingOutput},
    scalar_mul::{fixed_base::FixedBase, variable_base::VariableBaseMSM},
    AffineRepr, CurveGroup, Group,
};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::One;
use rand::RngCore;
use rayon::prelude::*;

macro_rules! try_par {
    ($(let $name:ident = $f:expr),+) => {
        $(
            let mut $name = None;
        )+
            rayon::scope(|s| {
                $(
                    let $name = &mut $name;
                    s.spawn(move |_| {
                        *$name = Some($f);
                    });)+
            });
        $(
            let $name = $name.unwrap()?;
        )+
    };
}

macro_rules! par {
    ($(let $name:ident = $f:expr),+) => {
        $(
            let mut $name = None;
        )+
            rayon::scope(|s| {
                $(
                    let $name = &mut $name;
                    s.spawn(move |_| {
                        *$name = Some($f);
                    });)+
            });
        $(
            let $name = $name.unwrap();
        )+
    };

    ($(let ($name1:ident, $name2:ident) = $f:block),+) => {
        $(
            let mut $name1 = None;
            let mut $name2 = None;
        )+
            rayon::scope(|s| {
                $(
                    let $name1 = &mut $name1;
                    let $name2 = &mut $name2;
                    s.spawn(move |_| {
                        let (a, b) = $f;
                        *$name1 = Some(a);
                        *$name2 = Some(b);
                    });)+
            });
        $(
            let $name1 = $name1.unwrap();
            let $name2 = $name2.unwrap();
        )+
    }
}

pub(crate) fn pairing_miller_affine<E: Pairing>(
    left: &[E::G1Affine],
    right: &[E::G2Affine],
) -> MillerLoopOutput<E> {
    assert_eq!(left.len(), right.len());

    let left = left
        .par_iter()
        .map(|e| E::G1Prepared::from(*e))
        .collect::<Vec<_>>();
    let right = right
        .par_iter()
        .map(|e| E::G2Prepared::from(*e))
        .collect::<Vec<_>>();

    E::multi_miller_loop(left, right)
}

/// Returns the miller loop result of the inner pairing product
pub(crate) fn pairing<E: Pairing>(left: &[E::G1Affine], right: &[E::G2Affine]) -> PairingOutput<E> {
    let miller_result = pairing_miller_affine::<E>(left, right);
    E::final_exponentiation(miller_result).expect("invalid pairing")
}

/// Multiplies a set of group elements by a same-sized set of scalars. outputs the vec of results
fn scalar_pairing<G: AffineRepr>(gp: &[G], scalars: &[G::ScalarField]) -> Vec<G> {
    let proj_results = gp
        .par_iter()
        .zip(scalars)
        .map(|(si, ri)| *si * *ri)
        .collect::<Vec<_>>();

    G::Group::normalize_batch(&proj_results)
}

pub(crate) fn msm<G: AffineRepr>(left: &[G], right: &[G::ScalarField]) -> G::Group {
    assert_eq!(
        left.len(),
        right.len(),
        "cannot MSM over different sized inputs"
    );
    VariableBaseMSM::msm(left, right).unwrap()
}

/// Returns powers of a generator
pub(crate) fn structured_generators_scalar_power<G: CurveGroup>(
    num: usize,
    g: &G,
    s: &G::ScalarField,
) -> Vec<G::Affine> {
    assert!(num > 0);
    let mut powers_of_scalar = Vec::with_capacity(num);
    let mut pow_s = G::ScalarField::one();
    for _ in 0..num {
        powers_of_scalar.push(pow_s);
        pow_s *= s;
    }
    let scalar_bits = G::ScalarField::MODULUS_BIT_SIZE as usize;
    let window_size = FixedBase::get_mul_window_size(num);
    let g_table = FixedBase::get_window_table::<G>(scalar_bits, window_size, g.clone());
    let powers_of_g =
        FixedBase::msm::<G>(scalar_bits, window_size, &g_table, &powers_of_scalar[..]);
    powers_of_g.into_iter().map(|v| v.into_affine()).collect()
}

/// Returns a vector `(0, s, s^2, ..., s^{num-1})`
pub(crate) fn structured_scalar_power<F: Field>(num: usize, s: F) -> Vec<F> {
    let mut powers = vec![F::one()];
    for i in 1..num {
        powers.push(powers[i - 1] * s);
    }
    powers
}

/// The output of the `CM_D` commitment method
#[derive(PartialEq, CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct IppCom<E: Pairing> {
    pub t: PairingOutput<E>,
    pub u: PairingOutput<E>,
}

// Recall this commitment is doubly homomorphic. Multiplying by `x` here is the same as the
// commitment of the same input but with one of them multiplied by `x`
impl<'a, E: Pairing> core::ops::Mul<E::ScalarField> for &'a IppCom<E> {
    type Output = IppCom<E>;

    fn mul(self, x: E::ScalarField) -> Self::Output {
        IppCom {
            t: self.t * x,
            u: self.u * x,
        }
    }
}

// Similarly, you can add commitments and it's the same as adding the committed vectors
impl<'a, E: Pairing> core::ops::Add<&IppCom<E>> for &'a IppCom<E> {
    type Output = IppCom<E>;

    fn add(self, other: &IppCom<E>) -> Self::Output {
        IppCom {
            t: self.t + other.t,
            u: self.u + other.u,
        }
    }
}

/// A key used for inner-pairing style commitments. Refer to the `CM_D` procedure in the paper
#[derive(Clone, Debug, Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct IppComKey<E: Pairing> {
    v1: Vec<E::G2Affine>,
    v2: Vec<E::G2Affine>,
    w1: Vec<E::G1Affine>,
    w2: Vec<E::G1Affine>,
}

pub type SuperComCommittingKey<E> = IppComKey<E>;

impl<E: Pairing> IppComKey<E> {
    /// Computes a commitment to `left_inputs`. This is the `CM_1` procedure.
    pub(crate) fn commit_left(&self, left_inputs: &[E::G1Affine]) -> IppCom<E> {
        par! {
            let t = pairing::<E>(left_inputs, &self.v1),
            let u = pairing::<E>(left_inputs, &self.v2)
        };
        IppCom { t, u }
    }

    /// Computes a commitment to `right_inputs`. This is the `CM_2` procedure.
    pub(crate) fn commit_right(&self, right_inputs: &[E::G2Affine]) -> IppCom<E> {
        par! {
            let t = pairing::<E>(&self.w1, right_inputs),
            let u = pairing::<E>(&self.w2, right_inputs)
        };
        IppCom { t, u }
    }

    /// Computes a commitment to `left_inputs` and `right_inputs`. This is the `CM_D` procedure
    pub fn commit_ambi(
        &self,
        left_inputs: &[E::G1Affine],
        right_inputs: &[E::G2Affine],
    ) -> IppCom<E> {
        par! {
            // (A * v)
            let t1 = pairing::<E>(left_inputs, &self.v1),
            let u1 = pairing::<E>(left_inputs, &self.v2),
            // (w * B)
            let t2 = pairing::<E>(&self.w1, right_inputs),
            let u2 = pairing::<E>(&self.w2, right_inputs)
        };

        IppCom {
            t: t1 + t2,
            u: u1 + u2,
        }
    }

    /// Makes a committing key with new `v1` and `v2` such that `vi' = vi^si`
    pub fn rescale_left(&self, s: &[E::ScalarField]) -> Self {
        assert_eq!(
            self.v1.len(),
            s.len(),
            "rescale_left inputs differ in length"
        );

        let (new_v1, new_v2): (Vec<_>, Vec<_>) = self
            .v1
            .par_iter()
            .zip(self.v2.par_iter())
            .zip(s.par_iter())
            .map(|((a, b), s)| (*a * s, *b * s))
            .unzip();
        let new_v1 = <E::G2Affine as AffineRepr>::Group::normalize_batch(&new_v1);
        let new_v2 = <E::G2Affine as AffineRepr>::Group::normalize_batch(&new_v2);

        IppComKey {
            v1: new_v1,
            v2: new_v2,
            w1: self.w1.clone(),
            w2: self.w2.clone(),
        }
    }
}

/// A key used for inner-pairing style commitments, but only committing to the left-hand side
/// (i.e., elements in G1). This is denoted `CM_1` in the paper
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct IppComLeftKey<E: Pairing> {
    v1: Vec<E::G2Affine>,
    v2: Vec<E::G2Affine>,
}

/// A key used for inner-pairing style commitments, but only committing to the right-hand side
/// (i.e., elements in G2). This is denoted `CM_2` in the paper.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct IppComRightKey<E: Pairing> {
    w1: Vec<E::G1Affine>,
    w2: Vec<E::G1Affine>,
}

pub struct AggProvingKey<E: Pairing> {
    /// This is the key used to produce ALL inner-pairing commitments
    pub(crate) ck: IppComKey<E>,

    // The elements of si are the curve point representing the i-th public input in some set of
    // Groth16 CRSs. The first public input is always set to 1, so we have a total of 4 here
    pub(crate) s0: Vec<E::G1Affine>,
    pub(crate) s1: Vec<E::G1Affine>,
    pub(crate) s2: Vec<E::G1Affine>,
    pub(crate) s3: Vec<E::G1Affine>,

    // Commitments to the above
    com_s0: IppCom<E>,
    com_s1: IppCom<E>,
    com_s2: IppCom<E>,
    com_s3: IppCom<E>,

    // The CRS values that get paired with the sum of the s values above
    h: Vec<E::G2Affine>,
    // Commitment to h
    com_h: IppCom<E>,

    // The CRS values that get paired with D and C, respectively
    delta0: Vec<E::G2Affine>,
    delta1: Vec<E::G2Affine>,
    // Commitment to above
    com_delta0: IppCom<E>,
    com_delta1: IppCom<E>,

    // Temporary values. These are the alpha and beta from the CRSs
    alpha: Vec<E::G1Affine>,
    beta: Vec<E::G2Affine>,
}

impl<E: Pairing> AggProvingKey<E> {
    pub fn new(ck: IppComKey<E>, pks: &[G16ProvingKey<E>]) -> Self {
        // Extract the group elements in the CRS corresponding to the public inputs
        let s0 = pks
            .par_iter()
            .map(|pk| pk.vk.gamma_abc_g[0])
            .collect::<Vec<_>>();
        let s1 = pks
            .par_iter()
            .map(|pk| pk.vk.gamma_abc_g[1])
            .collect::<Vec<_>>();
        let s2 = pks
            .par_iter()
            .map(|pk| pk.vk.gamma_abc_g[2])
            .collect::<Vec<_>>();
        let s3 = pks
            .par_iter()
            .map(|pk| pk.vk.gamma_abc_g[3])
            .collect::<Vec<_>>();

        // Commit to those group elements
        let com_s0 = ck.commit_left(&s0);
        let com_s1 = ck.commit_left(&s1);
        let com_s2 = ck.commit_left(&s2);
        let com_s3 = ck.commit_left(&s3);

        // Extract the group elements in the CRS that get paired with the si values
        let h = pks.par_iter().map(|pk| pk.vk.gamma_h).collect::<Vec<_>>();
        let com_h = ck.commit_right(&h);

        // Extract the group elements in the CRS that get paired with the si values
        let delta0 = pks
            .par_iter()
            .map(|pk| pk.vk.deltas_h[0])
            .collect::<Vec<_>>();
        let delta1 = pks
            .par_iter()
            .map(|pk| pk.vk.deltas_h[0])
            .collect::<Vec<_>>();
        let com_delta0 = ck.commit_right(&delta0);
        let com_delta1 = ck.commit_right(&delta1);

        let alpha = pks.par_iter().map(|pk| pk.vk.alpha_g).collect::<Vec<_>>();
        let beta = pks.par_iter().map(|pk| pk.vk.beta_h).collect::<Vec<_>>();

        AggProvingKey {
            ck,
            s0,
            s1,
            s2,
            s3,
            com_s0,
            com_s1,
            com_s2,
            com_s3,
            h,
            com_h,
            delta0,
            delta1,
            com_delta0,
            com_delta1,
            alpha,
            beta,
        }
    }

    /// Aggregates the subcircuit proofs
    pub fn agg_subcircuit_proofs(
        &self,
        pt: &mut ProtoTranscript,
        super_com: &IppCom<E>,
        proofs: &[G16Proof<E>],
        pub_inputs: &[E::ScalarField],
    ) {
        assert_eq!(
            pub_inputs.len(),
            3,
            "there are only 3 pub inputs: entry_chal, tr_chal, root"
        );

        let num_proofs = proofs.len();

        let a_vals = proofs.iter().map(|p| p.a).collect::<Vec<_>>();
        let b_vals = proofs.iter().map(|p| p.b).collect::<Vec<_>>();
        let c_vals = proofs.iter().map(|p| p.c).collect::<Vec<_>>();
        // Each proof has only 1 commitment (it's stage0)
        let d_vals = proofs.iter().map(|p| p.ds[0]).collect::<Vec<_>>();

        let ref_a_vals = &a_vals;
        let ref_b_vals = &b_vals;
        let ref_c_vals = &c_vals;

        par! {
            let com_ab = self.ck.commit_ambi(ref_a_vals, ref_b_vals),
            let com_c = self.ck.commit_left(ref_c_vals)
        };
        let com_d = super_com;

        // Compute the combined public inputs. In the paper this is S₁^1 · S₂^pubinput₁ · ...
        let prepared_input = self
            .s0
            .par_iter()
            .zip(self.s1.par_iter())
            .zip(self.s2.par_iter())
            .zip(self.s3.par_iter())
            .map(|(((s0, s1), s2), s3)| {
                // Remember the first public input is always 1, so s0 gets no coeff
                *s0 + (*s1) * pub_inputs[0] + (*s2) * pub_inputs[1] + (*s3) * pub_inputs[2]
            })
            .collect::<Vec<_>>();
        // TODO: Rewrite scalar_pairing so that we don't need this to be affine
        let prepared_input = E::G1::normalize_batch(&prepared_input);

        // Sanity check. Does the first proof validate?
        assert_eq!(
            E::pairing(&a_vals[0], &b_vals[0]),
            E::pairing(&self.alpha[0], &self.beta[0])
                + E::pairing(&prepared_input[0], &self.h[0])
                + E::pairing(&d_vals[0], &self.delta0[0])
                + E::pairing(&c_vals[0], &self.delta1[0])
        );
        /*

        // Now make a prepared input commitment in the same way
        let com_prepared_input = &(&(&self.com_s0 + &((&self.com_s1) * pub_inputs[0]))
            + &((&self.com_s2) * pub_inputs[1]))
            + &((&self.com_s3) * pub_inputs[2]);

        // Derive a random scalar to perform a linear combination of proofs
        pt.append_serializable(b"AB-commitment", &com_ab);
        pt.append_serializable(b"C-commitment", &com_c);
        let r = pt.challenge_scalar::<E::ScalarField>(b"r-random-fiatshamir");

        // 1,r, r^2, r^3, r^4 ...
        let r_s = structured_scalar_power(num_proofs, r);
        let ref_r_s = &r_s;
        // 1,r^-1, r^-2, r^-3
        let r_inv = r_s
            .par_iter()
            .map(|ri| ri.inverse().unwrap())
            .collect::<Vec<_>>();

        // A^{r}
        let a_r = scalar_pairing(&a_vals, &r_s);
        let ref_a_r = &a_r;

        // S^{r}
        let s_r = scalar_pairing(&prepared_input, &r_s);
        let ref_s_r = &s_r;

        let ref_c_vals = &c_vals;
        par! {
            // compute A * B^r for the verifier
            let agg_ab = pairing::<E>(&ref_a_r, &ref_b_vals),
            // compute C^r for the verifier
            let agg_c = msm::<E::G1Affine>(&ref_c_vals, &ref_r_s)
        };

        let ref_agg_c = &agg_c;
        let aggregated_c = agg_c.into_affine();
        let rescaled_ck = self.ck.rescale_left(&r_inv);

        assert_eq!(rescaled_ck.commit_ambi(&ref_a_r, &ref_b_vals), com_ab);
        // Debugging: alphas^r
        let alpha_r = scalar_pairing(&self.alpha, &r_s);
        let c_r = scalar_pairing(&c_vals, &r_s);
        let d_r = scalar_pairing(&c_vals, &r_s);

        assert_eq!(
            pairing::<E>(&ref_a_r, &ref_b_vals),
            pairing::<E>(&alpha_r, &self.beta)
                + pairing::<E>(&ref_s_r, &self.h)
                + pairing::<E>(&d_r, &self.delta0)
                + pairing::<E>(&c_r, &self.delta1)
        );
        */

        todo!()
    }
}

impl<E: Pairing> IppComKey<E> {
    /// Generates a key that can commit to up to `size` commitments. This is a trusted setup
    pub fn gen<R: RngCore>(mut rng: R, size: usize) -> Self {
        let g = E::G1::generator();
        let h = E::G2::generator();

        let a = E::ScalarField::rand(&mut rng);
        let b = E::ScalarField::rand(&mut rng);

        par! {
            let v1 = structured_generators_scalar_power(size, &h, &a),
            let v2 = structured_generators_scalar_power(size, &h, &b),
            let w1 = structured_generators_scalar_power(size, &g, &a),
            let w2 = structured_generators_scalar_power(size, &g, &b)
        }

        SuperComCommittingKey { v1, v2, w1, w2 }
    }
}
