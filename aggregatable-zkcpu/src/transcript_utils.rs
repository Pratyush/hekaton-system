//! This module contains utilities for building, committing to, and splitting execution transcripts

use crate::transcript_checker::ProcessedTranscriptEntry;
use ark_ff::{FftField, PrimeField};
use ark_poly::polynomial::univariate::DensePolynomial;
use tinyram_emu::{
    interpreter::{MemOp, TranscriptEntry},
    word::Word,
};

/// Given a TinyRAM transcript, constructs the corresponding time- and memory-sorted processed
/// transcripts, in that order, padded such that `time_tx.len() = 2 * mem_tx.len() + 1`.
pub fn sort_and_pad<const NUM_REGS: usize, W: Word>(
    transcript: &[TranscriptEntry<NUM_REGS, W>],
) -> (
    Vec<ProcessedTranscriptEntry<W>>,
    Vec<ProcessedTranscriptEntry<W>>,
) {
    // Create the time-sorted transcript, complete with padding memory ops. This has length 2T,
    // where T is the number of CPU ticks.
    let time_sorted_transcript = transcript
        .iter()
        .flat_map(ProcessedTranscriptEntry::new_pair)
        .collect::<Vec<_>>();

    // Make the mem-sorted trace with `read` ops removed. We have to pad the result out to be
    // sufficiently long. The required length is 2T + 1. The +1 is the initial padding.
    let mem_sorted_transcript: Vec<ProcessedTranscriptEntry<W>> = {
        let mut buf: Vec<ProcessedTranscriptEntry<W>> = time_sorted_transcript
            .iter()
            .filter(|item| item.mem_op.is_ram_op())
            .cloned()
            .collect();
        // Sort by RAM index, followed by timestamp
        buf.sort_by_key(|o| (o.mem_op.location(), o.timestamp));
        // Now pad the mem-sorted transcript with an initial placeholder op. This will just
        // store the value of the true first op. We can use the timestamp 0 because we've
        // reserved it: every witnessed transcript entry has timestamp greater than 0.
        let mut initial_entry = buf.get(0).unwrap().clone();
        initial_entry.timestamp = 0;
        initial_entry.is_padding = true;
        buf.insert(0, initial_entry);

        // Now pad the buffer out to 2T + 1. The padding is derived from the last element of
        // the mem-sorted trace. We take the element, convert it to a load, and increment the
        // timestamp appropriately.
        let base_pad_op = {
            let mut last_elem = buf.get(buf.len() - 1).unwrap().clone();
            // Get the RAM index of the load/store. This must be a load/store because we
            // filtered out the reads above.
            let location = W::from_u64(last_elem.mem_op.location()).unwrap();
            let val = last_elem.mem_op.val();
            last_elem.mem_op = MemOp::Load { location, val };
            last_elem
        };
        // Fill out whatever portion of the 2T + 1 remains
        let padding = (0..time_sorted_transcript.len() + 1 - buf.len()).map(|i| {
            let mut p = base_pad_op.clone();
            p.is_padding = true;
            p.timestamp += i as u64 + 1;
            p
        });

        buf.into_iter().chain(padding).collect()
    };

    (time_sorted_transcript, mem_sorted_transcript)
}

/// Converts the processed transcript to a polynomial of the desired degree. This works by
/// mapping the i-th element of the transcript to a field element vᵢ and returning P(X) =
/// Xʳ · Πᵢ (X - vᵢ), where r is the degree needed to make deg P equal `desired_deg`. Padding and
/// tape operations are mapped to 0 ∈ `F`.
pub fn ram_transcript_to_polyn<W: Word, F: FftField + PrimeField>(
    transcript: &[ProcessedTranscriptEntry<W>],
    desired_deg: usize,
) -> DensePolynomial<F> {
    // Define a recursive function that will make a polynomial from the given roots
    fn helper<G: FftField>(roots: &[G]) -> DensePolynomial<G> {
        if roots.len() == 1 {
            // If there's just 1 root r then return P(X) = X - r
            DensePolynomial {
                coeffs: vec![-roots[0], G::one()],
            }
        } else {
            // If there's more than 1 root, then let P₀(X) be the first half and P₁(X) be the
            // second half and return P₀(X)·P₁(X)
            let half_len = roots.len() / 2;
            let left_poly = helper(&roots[..half_len]);
            let right_poly = helper(&roots[half_len..]);
            &left_poly * &right_poly
        }
    }

    // Convert the transcript into its field element representation, and compute the polynomial
    // whose roots are exactly that (ignoring tape and padding ops). Also pad with enough 0s to
    // make it the desired length.
    let extra_zeros = core::iter::repeat(F::ZERO).take(desired_deg - (transcript.len() - 1));
    let encoded_transcript: Vec<F> = transcript
        .iter()
        .map(|e| {
            if e.is_tape_op() || e.is_padding {
                F::ZERO
            } else {
                e.as_ff::<F>(false)
            }
        })
        .chain(extra_zeros)
        .collect();
    helper(&encoded_transcript)
}
