use super::{
    data_structures::EvaluationProof, polynomial_coefficients_from_transcript,
    polynomial_evaluation_product_form_from_transcript,
};
use crate::Error;

use ark_ec::{AffineRepr, VariableBaseMSM};
use ark_ff::Field;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};

pub(crate) fn prove_commitment_v<G: AffineRepr>(
    srs_powers_alpha_table: &[G],
    srs_powers_beta_table: &[G],
    transcript: &[G::ScalarField],
    kzg_challenge: G::ScalarField,
) -> Result<EvaluationProof<G>, Error> {
    // f_v
    let vkey_poly = DensePolynomial::from_coefficients_vec(
        polynomial_coefficients_from_transcript(transcript, G::ScalarField::ONE),
    );

    // f_v(z)
    let vkey_poly_z = polynomial_evaluation_product_form_from_transcript(
        &transcript,
        kzg_challenge,
        G::ScalarField::ONE,
    );
    opening_proof(
        srs_powers_alpha_table,
        srs_powers_beta_table,
        vkey_poly,
        vkey_poly_z,
        kzg_challenge,
    )
}

pub(crate) fn prove_commitment_w<G: AffineRepr>(
    srs_powers_alpha_table: &[G],
    srs_powers_beta_table: &[G],
    transcript: &[G::ScalarField],
    r_shift: G::ScalarField,
    kzg_challenge: G::ScalarField,
) -> Result<EvaluationProof<G>, Error> {
    let n = srs_powers_alpha_table.len();
    // this computes f(X) = \prod (1 + x (rX)^{2^j})
    let mut f_coeffs = polynomial_coefficients_from_transcript(transcript, r_shift);
    // this computes f_w(X) = X^n * f(X) - it simply shifts all coefficients to by n
    let mut fw_coeffs = vec![G::ScalarField::ZERO; f_coeffs.len()];
    fw_coeffs.append(&mut f_coeffs);
    let fw = DensePolynomial::from_coefficients_vec(fw_coeffs);

    par! {
        // this computes f(z)
        let f_at_z = polynomial_evaluation_product_form_from_transcript(&transcript, kzg_challenge, r_shift),
        // this computes the "shift" z^n
        let z_to_n = kzg_challenge.pow(&[n as u64])
    };
    // this computes f_w(z) by multiplying by zn
    let fw_at_z = f_at_z * z_to_n;

    opening_proof(
        srs_powers_alpha_table,
        srs_powers_beta_table,
        fw,
        fw_at_z,
        kzg_challenge,
    )
}

/// Returns the KZG opening proof for the given commitment key. Specifically, it
/// returns $g^{f(alpha) - f(z) / (alpha - z)}$ for $a$ and $b$.
fn opening_proof<G: AffineRepr>(
    srs_powers_alpha_table: &[G], // h^alpha^i
    srs_powers_beta_table: &[G],  // h^beta^i
    poly: DensePolynomial<G::ScalarField>,
    eval_poly: G::ScalarField,
    kzg_challenge: G::ScalarField,
) -> Result<EvaluationProof<G>, Error> {
    let neg_kzg_challenge = -kzg_challenge;

    if poly.coeffs().len() != srs_powers_alpha_table.len() {
        return Err(Error::InvalidSRS(format!(
            "SRS len ({}) != coefficients len ({})",
            srs_powers_alpha_table.len(),
            poly.coeffs().len(),
        )));
    }

    // f_v(X) - f_v(z) / (X - z)
    let quotient_polynomial = &(&poly - &DensePolynomial::from_coefficients_vec(vec![eval_poly]))
        / &(DensePolynomial::from_coefficients_vec(vec![neg_kzg_challenge, G::ScalarField::ONE]));

    let mut quotient_polynomial_coeffs = quotient_polynomial.coeffs;
    quotient_polynomial_coeffs.resize(srs_powers_alpha_table.len(), <G::ScalarField>::ZERO);

    assert_eq!(
        quotient_polynomial_coeffs.len(),
        srs_powers_alpha_table.len()
    );
    assert_eq!(
        quotient_polynomial_coeffs.len(),
        srs_powers_beta_table.len()
    );

    // we do one proof over h^a and one proof over h^b (or g^a and g^b depending
    // on the curve we are on). that's the extra cost of the commitment scheme
    // used which is compatible with Groth16 CRS instead of the scheme
    // defined in [BMMTV19]
    let (a, b) = rayon::join(
        || {
            VariableBaseMSM::msm(&srs_powers_alpha_table, &quotient_polynomial_coeffs)
                .expect("msm for a failed!")
        },
        || {
            VariableBaseMSM::msm(&srs_powers_beta_table, &quotient_polynomial_coeffs)
                .expect("msm for b failed!")
        },
    );
    Ok(EvaluationProof::new_from_proj(a, b))
}
