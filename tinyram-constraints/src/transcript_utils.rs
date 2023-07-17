//! This module contains utilities for building, committing to, and splitting execution transcripts

use crate::{
    transcript_checker::{MemTranscriptEntry, TranscriptCheckerEvals},
    TinyRamExt,
};
use ark_ff::{FftField, PrimeField};
use ark_poly::polynomial::univariate::DensePolynomial;
use tinyram_emu::{word::Word, MemOp, MemOpKind, ExecutionTranscriptEntry};

/// Given a TinyRAM transcript, constructs the corresponding time- and memory-sorted processed
/// transcripts, in that order, padded such that `time_tx.len() = 2 * mem_tx.len() + 1`.
pub fn sort_and_pad<T: TinyRamExt>(
    transcript: &[ExecutionTranscriptEntry<T>],
) -> (
    Vec<MemTranscriptEntry<T>>,
    Vec<MemTranscriptEntry<T>>,
) {
    // Create the time-sorted transcript, complete with padding memory ops. This has length 2T,
    // where T is the number of CPU ticks.
    let time_sorted_transcript = transcript
        .iter()
        .flat_map(MemTranscriptEntry::extract_mem_ops)
        .collect::<Vec<_>>();

    // Make the mem-sorted trace with `read` ops removed. We have to pad the result out to be
    // sufficiently long. The required length is 2T + 1. The +1 is the initial padding.
    let mem_sorted_transcript: Vec<MemTranscriptEntry<T>> = {
        let mut buf: Vec<MemTranscriptEntry<T>> = time_sorted_transcript
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
            let location = T::Word::from_u64(last_elem.mem_op.location());
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
    transcript: &[MemTranscriptEntry<W>],
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
                e.as_fp::<F>(false)
            }
        })
        .chain(extra_zeros)
        .collect();
    helper(&encoded_transcript)
}

impl<F: PrimeField> TranscriptCheckerEvals<F> {
    /// Updates the running evals with the given entries and challenge point. `mem_tr_adj_seq` is a
    /// triple of adjacent entries in the memory-sorted trace
    pub(crate) fn update<W: Word>(
        &mut self,
        chal: F,
        instr_load: &MemTranscriptEntry<W>,
        mem_op: &MemTranscriptEntry<W>,
        mem_tr_adj_seq: &[MemTranscriptEntry<W>],
    ) {
        assert_eq!(mem_tr_adj_seq.len(), 3);

        let process_ram_op = |m: &MemTranscriptEntry<W>| {
            if m.is_tape_op() || m.is_padding {
                F::zero()
            } else {
                m.as_fp(false)
            }
        };
        let process_ram_op_notime = |m: &MemTranscriptEntry<W>| {
            if m.is_tape_op() || m.is_padding {
                F::zero()
            } else {
                m.as_fp_notime(false)
            }
        };

        // Update the time-sorted trace. Recall the polynoimal has factors (X - op). So to do an
        // incremental computation, we calculate `eval *= (chal - op)`
        let instr_ff = process_ram_op(instr_load);
        let mem_op_ff = process_ram_op(mem_op);
        self.time_tr_exec *= chal - instr_ff;
        self.time_tr_exec *= chal - mem_op_ff;

        // Update the mem-sorted and init-accessed traces
        for pair in mem_tr_adj_seq.windows(2) {
            let prev = &pair[0];
            let cur = &pair[1];

            // Some sanity checks
            // The memory-sorted trace should never have a tape op in it
            assert!(prev.is_ram_op());
            assert!(cur.is_ram_op());
            // Do the rest of the checks from transcript_checker():
            let prev_is_load = prev.mem_op.kind() == MemOpKind::Load;
            let cur_is_load = cur.mem_op.kind() == MemOpKind::Load;
            assert!(!prev.is_padding || prev_is_load);
            assert!(!cur.is_padding || cur_is_load);
            let loc_is_eq = prev.mem_op.location() == cur.mem_op.location();
            assert!(!cur.is_padding || loc_is_eq);
            let loc_has_incrd = prev.mem_op.location() < cur.mem_op.location();
            let t_has_incrd = prev.timestamp < cur.timestamp;
            assert!(loc_has_incrd || (loc_is_eq && t_has_incrd));
            let val_is_eq = prev.mem_op.val() == cur.mem_op.val();
            let op_is_store = cur.mem_op.kind() == MemOpKind::Store;
            assert!(!loc_is_eq || val_is_eq || op_is_store);

            // The memory-sorted trace always processes the current memory op since it's a RAM op.
            self.mem_tr_exec *= chal - process_ram_op(cur);

            // The init-accesses trace only gets updated if this is a load from a new location
            let is_new_load = loc_has_incrd && cur_is_load;
            if is_new_load {
                self.tr_init_accessed *= chal - process_ram_op_notime(cur);
            }
        }
    }
}
