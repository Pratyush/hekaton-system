//! Contains all the components for an aggregated TinyRAM prover

use crate::transcript_checker::ProcessedTranscriptEntry;

use ark_ff::{FftField, PrimeField};
use ark_poly::polynomial::univariate::DensePolynomial;
use tinyram_emu::word::Word;

// Converts the processed transcript to a polynomial we can commit to
fn transcript_as_polyn<W: Word, F: FftField + PrimeField>(
    transcript: &[ProcessedTranscriptEntry<W>],
) -> DensePolynomial<F> {
    // Define a recursive function that will make a polynomial from the given roots
    fn helper<G: FftField>(roots: &[G]) -> DensePolynomial<G> {
        if roots.len() == 1 {
            DensePolynomial {
                coeffs: vec![-roots[0], G::one()],
            }
        } else {
            let half_len = roots.len() / 2;
            let left_poly = helper(&roots[..half_len]);
            let right_poly = helper(&roots[half_len..]);
            &left_poly * &right_poly
        }
    }

    // Convert the transcript into its field element representation, and compute the polynomial
    // whose roots are exactly that
    let encoded_transcript: Vec<F> = transcript
        .iter()
        .map(ProcessedTranscriptEntry::as_ff::<F>)
        .collect();
    helper(&encoded_transcript)
}
