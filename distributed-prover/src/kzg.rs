use crate::pairing_ops::structured_generators_scalar_power;

use ark_crypto_primitives::crh::sha256::{digest::Digest, Sha256};
use ark_ec::{
    pairing::{MillerLoopOutput, Pairing, PairingOutput},
    scalar_mul::{fixed_base::FixedBase, variable_base::VariableBaseMSM},
    AffineRepr, CurveGroup, Group,
};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::One;
use rand::RngCore;
use rayon::prelude::*;

/// OpeningProof represents the KZG evaluation proof for the SRS used in our scheme.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct KzgEvalProof<G: AffineRepr>(pub G, pub G);

impl<G: AffineRepr> KzgEvalProof<G> {
    pub fn new_from_proj(a: G::Group, b: G::Group) -> Self {
        let s = [a, b];
        let s = G::Group::normalize_batch(&s);

        KzgEvalProof(s[0], s[1])
    }
}

pub struct KzgComKey<E: Pairing> {
    /// $\{g^a^i\}_{i=0}^{2n-1}$ where n is the number of proofs to be aggregated
    /// We take all powers instead of only ones from n -> 2n-1 (w commitment key
    /// is formed from these powers) since the prover will create a shifted
    /// polynomial of degree 2n-1 when doing the KZG opening proof.
    pub g_alpha_powers: Vec<E::G1Affine>,
    /// $\{h^a^i\}_{i=0}^{n-1}$ - here we don't need to go to 2n-1 since v
    /// commitment key only goes up to n-1 exponent.
    pub h_alpha_powers: Vec<E::G2Affine>,
    /// $\{g^b^i\}_{i=0}^{2n-1}$
    pub g_beta_powers: Vec<E::G1Affine>,
    /// $\{h^b^i\}_{i=0}^{n-1}$
    pub h_beta_powers: Vec<E::G2Affine>,
}

impl<E: Pairing> KzgComKey<E> {
    pub(crate) fn prove_commitment_v(
        &self,
        challenges: &[E::ScalarField],
        point: E::ScalarField,
    ) -> KzgEvalProof<E::G2Affine> {
        // f_v
        let vkey_poly = ipa_polynomial(challenges, E::ScalarField::ONE);

        prove_evaluation(&self.h_alpha_powers, &self.h_beta_powers, vkey_poly, point)
    }

    pub(crate) fn prove_commitment_w(
        &self,
        challenges: &[E::ScalarField],
        r: E::ScalarField,
        point: E::ScalarField,
    ) -> KzgEvalProof<E::G1Affine> {
        // this computes f(X) = \prod (1 + x (rX)^{2^j})
        let f = ipa_polynomial(challenges, r);
        // this computes f_w(X) = X^n * f(X) - it simply shifts all coefficients to by n
        let fw_coeffs = [vec![E::ScalarField::ZERO; f.len()], f.coeffs].concat();
        let fw = DensePolynomial::from_coefficients_vec(fw_coeffs);

        prove_evaluation(&self.g_alpha_powers, &self.g_beta_powers, fw, point)
    }

    pub(crate) fn gen<R: RngCore>(mut rng: R, size: usize) -> Self {
        let alpha = E::ScalarField::rand(&mut rng);
        let beta = E::ScalarField::rand(&mut rng);
        let g = E::G1::generator();
        let h = E::G2::generator();

        let mut g_alpha_powers = Vec::new();
        let mut g_beta_powers = Vec::new();
        let mut h_alpha_powers = Vec::new();
        let mut h_beta_powers = Vec::new();
        rayon::scope(|s| {
            let alpha = &alpha;
            let h = &h;
            let g = &g;
            let beta = &beta;
            let g_alpha_powers = &mut g_alpha_powers;
            s.spawn(move |_| {
                *g_alpha_powers = structured_generators_scalar_power(2 * size, g, alpha);
            });
            let g_beta_powers = &mut g_beta_powers;
            s.spawn(move |_| {
                *g_beta_powers = structured_generators_scalar_power(2 * size, g, beta);
            });

            let h_alpha_powers = &mut h_alpha_powers;
            s.spawn(move |_| {
                *h_alpha_powers = structured_generators_scalar_power(size, h, alpha);
            });

            let h_beta_powers = &mut h_beta_powers;
            s.spawn(move |_| {
                *h_beta_powers = structured_generators_scalar_power(size, h, beta);
            });
        });

        debug_assert!(h_alpha_powers[0] == E::G2Affine::generator());
        debug_assert!(h_beta_powers[0] == E::G2Affine::generator());
        debug_assert!(g_alpha_powers[0] == E::G1Affine::generator());
        debug_assert!(g_beta_powers[0] == E::G1Affine::generator());
        KzgComKey {
            g_alpha_powers,
            g_beta_powers,
            h_alpha_powers,
            h_beta_powers,
        }
    }
}

// Compute the coefficients of the polynomial $\prod_{j=0}^{l-1} (1 + x_{l-j}(rX)^{2j})$
// It does this in logarithmic time directly; here is an example with 2
// challenges:
//
//     We wish to compute $(1+x_1ra)(1+x_0(ra)^2) = 1 +  x_1ra + x_0(ra)^2 + x_0x_1(ra)^3$
//     Algorithm: $c_{-1} = [1]$; $c_j = c_{i-1} \| (x_{l-j} * c_{i-1})$; $r = r*r$
//     $c_0 = c_{-1} \| (x_1 * r * c_{-1}) = [1] \| [rx_1] = [1, rx_1]$, $r = r^2$
//     $c_1 = c_0 \| (x_0 * r^2c_0) = [1, rx_1] \| [x_0r^2, x_0x_1r^3] = [1, x_1r, x_0r^2, x_0x_1r^3]$
//     which is equivalent to $f(a) = 1 + x_1ra + x_0(ra)^2 + x_0x_1r^2a^3$
//
// This method expects the coefficients in reverse order so transcript[i] =
// x_{l-j}.
// f(Y) = Y^n * \prod (1 + x_{l-j-1} (r_shiftY^{2^j}))
fn ipa_polynomial<F: Field>(challenges: &[F], r: F) -> DensePolynomial<F> {
    let mut coefficients = vec![F::one()];
    let mut power_2_r = r;

    for (i, x) in challenges.iter().enumerate() {
        let n = coefficients.len();
        if i > 0 {
            power_2_r = power_2_r.square();
        }
        for j in 0..n {
            let coeff = coefficients[j] * &(*x * &power_2_r);
            coefficients.push(coeff);
        }
    }

    DensePolynomial::from_coefficients_vec(coefficients)
}

/// Returns the KZG opening proof for the given commitment key. Specifically, it
/// returns $g^{f(alpha) - f(z) / (alpha - z)}$ for $a$ and $b$.
fn prove_evaluation<G: AffineRepr>(
    srs_powers_alpha: &[G], // h^alpha^i
    srs_powers_beta: &[G],  // h^beta^i
    poly: DensePolynomial<G::ScalarField>,
    point: G::ScalarField,
) -> KzgEvalProof<G> {
    assert!(
        srs_powers_alpha.len() == poly.coeffs().len(),
        "SRS len ({}) != coefficients len ({})",
        srs_powers_alpha.len(),
        poly.coeffs().len()
    );

    // f_v(X) - f_v(z) / (X - z)
    let mut witness_poly =
        &poly / &DensePolynomial::from_coefficients_vec(vec![-point, G::ScalarField::ONE]);

    witness_poly
        .coeffs
        .resize(srs_powers_alpha.len(), <G::ScalarField>::ZERO);

    assert_eq!(witness_poly.coeffs.len(), srs_powers_alpha.len());
    assert_eq!(witness_poly.coeffs.len(), srs_powers_beta.len());

    // we do one proof over h^a and one proof over h^b (or g^a and g^b depending
    // on the curve we are on). that's the extra cost of the commitment scheme
    // used which is compatible with Groth16 CRS instead of the scheme
    // defined in [BMMTV19]
    let (a, b) = rayon::join(
        || G::Group::msm(&srs_powers_alpha, &witness_poly.coeffs).expect("msm for a failed!"),
        || G::Group::msm(&srs_powers_beta, &witness_poly.coeffs).expect("msm for b failed!"),
    );
    KzgEvalProof::new_from_proj(a, b)
}
