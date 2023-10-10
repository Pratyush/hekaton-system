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

#[derive(Clone, Debug, Default, CanonicalSerialize)]
pub struct IppComKeyRef<'a, E: Pairing> {
    v1: &'a [E::G2Affine],
    v2: &'a [E::G2Affine],
    w1: &'a [E::G1Affine],
    w2: &'a [E::G1Affine],
}

pub type SuperComCommittingKey<E> = IppComKey<E>;

impl<'a, E: Pairing> IppComKeyRef<'a, E> {
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
}

impl<E: Pairing> IppComKey<E> {
    fn as_ref(&self) -> IppComKeyRef<E> {
        IppComKeyRef {
            v1: self.v1.as_slice(),
            v2: self.v2.as_slice(),
            w1: self.w1.as_slice(),
            w2: self.w2.as_slice(),
        }
    }

    /// Computes a commitment to `left_inputs`. This is the `CM_1` procedure.
    pub(crate) fn commit_left(&self, left_inputs: &[E::G1Affine]) -> IppCom<E> {
        self.as_ref().commit_left(left_inputs)
    }

    /// Computes a commitment to `right_inputs`. This is the `CM_2` procedure.
    pub(crate) fn commit_right(&self, right_inputs: &[E::G2Affine]) -> IppCom<E> {
        self.as_ref().commit_right(right_inputs)
    }

    /// Computes a commitment to `left_inputs` and `right_inputs`. This is the `CM_D` procedure
    pub fn commit_ambi(
        &self,
        left_inputs: &[E::G1Affine],
        right_inputs: &[E::G2Affine],
    ) -> IppCom<E> {
        self.as_ref().commit_ambi(left_inputs, right_inputs)
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
            .map(|pk| pk.vk.deltas_h[1])
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
        let com_prepared_input = &(&(&self.com_s0 + &((&self.com_s1) * pub_inputs[0]))
            + &((&self.com_s2) * pub_inputs[1]))
            + &((&self.com_s3) * pub_inputs[2]);

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
        for i in 0..num_proofs {
            assert_eq!(
                E::pairing(&a_vals[i], &b_vals[i]),
                E::pairing(&self.alpha[i], &self.beta[i])
                    + E::pairing(&prepared_input[i], &self.h[i])
                    + E::pairing(&d_vals[i], &self.delta0[i])
                    + E::pairing(&c_vals[i], &self.delta1[i])
            );
        }

        // Derive a random scalar to perform a linear combination of proofs
        pt.append_serializable(b"AB-commitment", &com_ab);
        pt.append_serializable(b"C-commitment", &com_c);
        pt.append_serializable(b"D-commitment", com_d);
        let r = pt.challenge_scalar::<E::ScalarField>(b"r-random-fiatshamir");

        // 1,r, r^2, r^3, r^4 ...
        let r_s = structured_scalar_power(num_proofs, r);
        let ref_r_s = &r_s;
        // 1,r^-1, r^-2, r^-3
        let r_inv = r_s
            .par_iter()
            .map(|ri| ri.inverse().unwrap())
            .collect::<Vec<_>>();

        // Compute X^r for X = A, alpha, prepared_input
        let ref_r_s = &r_s;
        par! {
            let a_r = scalar_pairing(&a_vals, &ref_r_s),
            let c_r = scalar_pairing(&c_vals, &ref_r_s),
            let d_r = scalar_pairing(&d_vals, &ref_r_s),
            let alpha_r = scalar_pairing(&self.alpha, &ref_r_s),
            let prepared_input_r = scalar_pairing(&prepared_input, &ref_r_s)
        }
        // Check each individual equation holds with the r coeffs
        for i in 0..num_proofs {
            assert_eq!(
                E::pairing(&a_r[i], &b_vals[i]),
                E::pairing(&alpha_r[i], &self.beta[i])
                    + E::pairing(&prepared_input_r[i], &self.h[i])
                    + E::pairing(&d_r[i], &self.delta0[i])
                    + E::pairing(&c_r[i], &self.delta1[i])
            );
        }

        // Start building the aggregate values for the proving step
        let ref_a_r = &a_r;
        let ref_c_r = &c_r;
        let ref_d_r = &d_r;
        let ref_prepared_input_r = &prepared_input_r;

        // Start the MT protocol

        let rescaled_ck = self.ck.rescale_left(&r_inv);
        assert_eq!(rescaled_ck.commit_ambi(&a_r, &ref_b_vals), com_ab);
        // Compute cross producs
        /*
        let z_ah = pairing::<E>(&ref_a_r, &self.h);
        let z_adelta0 = pairing::<E>(&ref_a_r, &self.delta0);
        let z_adelta1 = pairing::<E>(&ref_a_r, &self.delta1);
        let z_sb = pairing::<E>(&prepared_input_r, &b_vals);
        let z_sdelta0 = pairing::<E>(&prepared_input_r, &self.delta0);
        let z_sdelta1 = pairing::<E>(&prepared_input_r, &self.delta1);
        */

        // Multiply every LHS with every RHS
        let cross_terms = [ref_a_r, ref_prepared_input_r, &d_r, &c_r]
            .into_par_iter()
            .map(|lhs| {
                [ref_b_vals, &self.h, &self.delta0, &self.delta1]
                    .into_par_iter()
                    .map(|rhs| pairing::<E>(lhs, rhs))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        // Check that the pairing product equation holds with the r coeffs
        let z_ab = cross_terms[0][0];
        let z_sh = cross_terms[1][1];
        let z_ddelta0 = cross_terms[2][2];
        let z_cdelta1 = cross_terms[3][3];
        assert_eq!(
            z_ab,
            pairing::<E>(&alpha_r, &self.beta) + z_sh + z_ddelta0 + z_cdelta1
        );

        // Get challenges s,t
        pt.append_serializable(b"cross-terms", &cross_terms);
        let s = pt.challenge_scalar::<E::ScalarField>(b"s-random-fiatshamir");
        let t = pt.challenge_scalar::<E::ScalarField>(b"t-random-fiatshamir");
        // Compute squares and cubes
        let s_sq = s * s;
        let s_cube = s_sq * s;
        let t_sq = t * t;
        let t_cube = t_sq * t;

        // Now compute a combination wrt powers of s and t
        let left = {
            // Compute L = A' · (S')^s · (D')^{s²} · (C')^{s³}
            par! {
                let s_to_the_s =
                    scalar_pairing(ref_prepared_input_r, vec![s; num_proofs].as_slice()),
                let d_to_the_s2 = scalar_pairing(ref_d_r, vec![s_sq; num_proofs].as_slice()),
                let c_to_the_s3 = scalar_pairing(ref_c_r, vec![s_cube; num_proofs].as_slice())
            };
            let sum = ref_a_r
                .into_par_iter()
                .zip(s_to_the_s.into_par_iter())
                .zip(d_to_the_s2.into_par_iter())
                .zip(c_to_the_s3.into_par_iter())
                .map(|(((a, s), d), c)| *a + s + d + c)
                .collect::<Vec<_>>();
            E::G1::normalize_batch(&sum)
        };
        let right = {
            // Compute R = B · H^t · δ₀^{t²} · δ₁^{t³}
            par! {
                let h_to_the_t = scalar_pairing(&self.h, vec![t; num_proofs].as_slice()),
                let delta0_to_the_t2 =
                    scalar_pairing(&self.delta0, vec![t_sq; num_proofs].as_slice()),
                let delta1_to_the_t3 =
                    scalar_pairing(&self.delta0, vec![t_cube; num_proofs].as_slice())
            };
            let sum = ref_b_vals
                .into_par_iter()
                .zip(h_to_the_t.into_par_iter())
                .zip(delta0_to_the_t2.into_par_iter())
                .zip(delta1_to_the_t3.into_par_iter())
                .map(|(((b, s), d), c)| *b + s + d + c)
                .collect::<Vec<_>>();
            E::G2::normalize_batch(&sum)
        };
        // Compute the corresponding commitments
        let com_lr = {
            let s_partial_sum =
                &(&(&com_ab + &(&com_prepared_input * s)) + &(com_d * s_sq)) + &(&com_c * s_cube);
            let t_partial_sum =
                &(&(&self.com_h * t) + &(&self.com_delta0 * t_sq)) + &(&self.com_delta1 * t_cube);
            &s_partial_sum + &t_partial_sum
        };
        // Take the product of the left and right sides
        let z_lr = pairing::<E>(&left, &right);

        let (tipp_proof, challenges, challenges_inv) =
            prove_tipp(self.ck.clone(), r_s, left, right, z_lr, pt);

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

/// gipa_tipp_mipp peforms the recursion of the GIPA protocol for TIPP and MIPP.
/// It returns a proof containing all intermdiate committed values, as well as
/// the challenges generated necessary to do the polynomial commitment proof
/// later in TIPP.
fn prove_tipp<E: Pairing>(
    ck: IppComKey<E>,
    mut r: Vec<E::ScalarField>,
    mut a: Vec<E::G1Affine>,
    mut b: Vec<E::G2Affine>,
    agg_ab: PairingOutput<E>,
    transcript: &mut ProtoTranscript,
) -> (TippProof<E>, Vec<E::ScalarField>, Vec<E::ScalarField>) {
    // storing the values for including in the proof
    let mut vkey = (ck.v1, ck.v2);
    let mut wkey = (ck.w1, ck.w2);
    let mut comms_ab = Vec::new();
    let mut z_ab = Vec::new();

    let mut challenges: Vec<E::ScalarField> = Vec::new();
    let mut challenges_inv: Vec<E::ScalarField> = Vec::new();

    transcript.append_serializable(b"Aggregated AB", &agg_ab);
    let mut delta_inv: E::ScalarField =
        transcript.challenge_scalar::<E::ScalarField>(b"first-challenge");
    let mut delta = delta_inv.inverse().unwrap();

    let mut i = 0;

    while a.len() > 1 {
        // recursive step
        // Recurse with problem of half size
        let split = a.len() / 2;

        // TIPP ///
        let (a_left, a_right) = a.split_at_mut(split);
        let (b_left, b_right) = b.split_at_mut(split);
        // r[:n']   r[:n']
        let (r_left, r_right) = r.split_at_mut(split);

        let [vk_left, vk_right] = split_key(vkey);
        let [wk_left, wk_right] = split_key(wkey);

        // since we do this in parallel we take reference first so it can be
        // moved within the macro's rayon scope.
        let (rvk_left, rvk_right) = (&vk_left, &vk_right);
        let (rwk_left, rwk_right) = (&wk_left, &wk_right);
        let (ra_left, ra_right) = (&a_left, &a_right);
        let (rb_left, rb_right) = (&b_left, &b_right);

        // TODO: remove these clones
        let ck_lr = IppComKeyRef {
            v1: &rvk_left.0,
            v2: &rvk_left.1,
            w1: &rwk_right.0,
            w2: &rwk_right.1,
        };
        let ck_rl = IppComKeyRef {
            v1: &rvk_right.0,
            v2: &rvk_right.1,
            w1: &rwk_left.0,
            w2: &rwk_left.1,
        };

        // See section 3.3 for paper version with equivalent names
        par! {
            /********************************************************/
            // Compute left and right inner products:
            //
            // For TIPP (i.e. A and B):
            // \prod e(A_right,B_left)
            let l_ab = pairing::<E>(&ra_right, &rb_left),
            let r_ab = pairing::<E>(&ra_left, &rb_right),

            // Compute left cross commitments
            //
            // For TIPP:
            let cm_l_ab = ck_lr.commit_ambi(&ra_right, &rb_left),

            // Compute right cross commitments
            //
            // For TIPP:
            // T_ab_r = e(A_left,B_right)
            let cm_r_ab = ck_rl.commit_ambi(&ra_left, &rb_right)
        };

        // Fiat-Shamir challenge
        // combine both TIPP and MIPP transcript
        if i == 0 {
            // already generated c_inv and c outside of the loop
        } else {
            transcript.append_serializable(b"delta_inv", &delta_inv);
            transcript.append_serializable(b"L_AB", &l_ab);
            transcript.append_serializable(b"R_AB", &r_ab);
            transcript.append_serializable(b"cm_L_AB", &cm_l_ab);
            transcript.append_serializable(b"cm_R_AB", &cm_r_ab);
            delta_inv = transcript.challenge_scalar::<E::ScalarField>(b"delta_inv_i");

            // Optimization for multiexponentiation to rescale G2 elements with
            // 128-bit challenge Swap 'c' and 'c_inv' since can't control bit size
            // of c_inv
            delta = delta_inv.inverse().unwrap();
        }

        // Set up values for next step of recursion
        // A[:n'] + delta * A[n':]
        fold_vec(&mut a, delta);
        // B[:n'] + delta_inv * B[n':]
        fold_vec(&mut b, delta_inv);

        // Collapse randomness
        r_left
            .par_iter_mut()
            .zip(r_right.par_iter_mut())
            .for_each(|(left, right)| {
                // r[:n'] + delta_inv * r[n':]
                *right *= &delta_inv;
                *left += right;
            });
        let len = r_left.len();
        r.resize(len, E::ScalarField::ZERO); // shrink to new size

        // Compress commitment keys:
        // v_left + v_right^x^-1
        vkey = fold_ck(&vk_left, &vk_right, delta_inv);

        // w_left + w_right^x
        wkey = fold_ck(&wk_left, &wk_right, delta);

        comms_ab.push((cm_l_ab, cm_r_ab));
        z_ab.push((l_ab, r_ab));
        challenges.push(delta);
        challenges_inv.push(delta_inv);

        i += 1;
    }

    assert!(a.len() == 1 && b.len() == 1);
    assert!(vkey.0.len() == 1 && vkey.1.len() == 1);
    assert!(wkey.0.len() == 1 && wkey.1.len() == 1);

    let (final_a, final_b) = (a[0], b[0]);
    let final_vkey = (vkey.0[0], vkey.1[0]);
    let final_wkey = (wkey.0[0], wkey.1[0]);

    (
        TippProof {
            num_proofs: a.len().try_into().unwrap(), // TODO: ensure u32
            comms_lr_ab: comms_ab,
            lr_ab: z_ab,
            final_a,
            final_b,
            final_vkey,
            final_wkey,
        },
        challenges,
        challenges_inv,
    )
}

#[derive(Debug, Clone)]
pub struct TippProof<E: Pairing> {
    pub num_proofs: u32,
    pub comms_lr_ab: Vec<(IppCom<E>, IppCom<E>)>,
    pub lr_ab: Vec<(PairingOutput<E>, PairingOutput<E>)>,
    pub final_a: E::G1Affine,
    pub final_b: E::G2Affine,
    /// final commitment keys $v$ and $w$ - there is only one element at the
    /// end for v1 and v2 hence it's a tuple.
    pub final_vkey: (E::G2Affine, E::G2Affine),
    pub final_wkey: (E::G1Affine, E::G1Affine),
}

/// Splits a key in half and returns the left and right commitment key parts
pub fn split_key<G: AffineRepr>(key: (Vec<G>, Vec<G>)) -> [(Vec<G>, Vec<G>); 2] {
    let (mut a, mut b) = key;
    let split = a.len() / 2;

    let a_right = a.split_off(split);
    let b_right = b.split_off(split);
    [(a, b), (a_right, b_right)]
}

/// Folds a vector in half with a scalar mul. If `vec = [v || w]` then this outputs `u` such that
/// `uᵢ = vᵢ + scalar * wᵢ`
pub(crate) fn fold_vec<C: AffineRepr>(vec: &mut Vec<C>, scalar: C::ScalarField) {
    let split = vec.len() / 2;

    let (left, right) = vec.split_at(split);
    let left_group = left
        .into_par_iter()
        .zip(right)
        .map(|(&l, &r)| l + r * scalar)
        .collect::<Vec<_>>();
    assert_eq!(left_group.len(), left.len());
    *vec = C::Group::normalize_batch(&left_group);
}

pub fn fold_ck<G: AffineRepr>(
    left: &(Vec<G>, Vec<G>),
    right: &(Vec<G>, Vec<G>),
    scale: G::ScalarField,
) -> (Vec<G>, Vec<G>) {
    assert_eq!(left.0.len(), right.0.len());

    let (a, b): (Vec<G::Group>, Vec<G::Group>) = left
        .0
        .par_iter()
        .zip(left.1.par_iter())
        .zip(right.0.par_iter().zip(right.1.par_iter()))
        .map(|((l_a, l_b), (r_a, r_b))| (*r_a * scale + l_a, *r_b * scale + l_b))
        .unzip();
    let a = G::Group::normalize_batch(&a);
    let b = G::Group::normalize_batch(&b);

    (a, b)
}
