use core::borrow::Borrow;

use std::collections::VecDeque;

use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    bits::{uint8::UInt8, ToBytesGadget},
    fields::fp::FpVar,
    R1CSVar,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, Namespace, SynthesisError},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use xxhash_rust::xxh3::xxh3_128;

pub mod aggregation;
pub mod coordinator;
pub mod eval_tree;
pub mod kzg;
pub mod pairing_ops;
pub mod portal_manager;
pub mod poseidon_util;
pub mod subcircuit_circuit;
pub mod tree_hash_circuit;
pub mod util;
pub mod worker;

use portal_manager::PortalManager;

#[macro_export]
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
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub(crate) struct RunningEvals<F: PrimeField> {
    // Stored values that are updated
    pub(crate) time_ordered_eval: F,
    pub(crate) addr_ordered_eval: F,

    // Values specific to the global polynomial. These are need by the update function. Contains
    // `(entry_chal, tr_chal)`.
    challenges: Option<(F, F)>,
}

impl<F: PrimeField> Default for RunningEvals<F> {
    fn default() -> Self {
        RunningEvals {
            time_ordered_eval: F::one(),
            addr_ordered_eval: F::one(),
            challenges: None,
        }
    }
}

impl<F: PrimeField> RunningEvals<F> {
    fn to_bytes(&self) -> Vec<u8> {
        [
            self.time_ordered_eval.into_bigint().to_bytes_le(),
            self.addr_ordered_eval.into_bigint().to_bytes_le(),
        ]
        .concat()
    }

    /// Updates the running evaluation of the time-ordered transcript polyn
    fn update_time_ordered(&mut self, entry: &RomTranscriptEntry<F>) {
        // Unpack challenges
        let (entry_chal, tr_chal) = self
            .challenges
            .expect("RunningEvals.challenges needs to be set in order to run update");

        // The single-field-element representation of a transcript entry is val + entry_chal*addr,
        // where addr is the hash of the name
        let entry_repr = entry.val + entry_chal * &F::from(entry.addr);

        // Now add the entry to the running polynomial eval. The polynomial is Π (X - entryᵢ)
        // evaluated at X=tr_chal
        self.time_ordered_eval *= tr_chal - entry_repr;
    }

    /// Updates the running evaluation of the addr-ordered transcript polyn
    fn update_addr_ordered(&mut self, entry: &RomTranscriptEntry<F>) {
        // Unpack challenges
        let (entry_chal, tr_chal) = self
            .challenges
            .expect("RunningEvals.challenges needs to be set in order to run update");

        // The single-field-element representation of a transcript entry is val + entry_chal*addr,
        // where addr is the hash of the name
        let entry_repr = entry.val + entry_chal * &F::from(entry.addr);

        // Now add the entry to the running polynomial eval. The polynomial is Π (X - entryᵢ)
        // evaluated at X=tr_chal
        self.addr_ordered_eval *= tr_chal - entry_repr;
    }
}

#[derive(Clone)]
pub(crate) struct RunningEvalsVar<F: PrimeField> {
    // Stored values that are updated
    time_ordered_eval: FpVar<F>,
    addr_ordered_eval: FpVar<F>,

    // Values specific to the global polynomial. These are need by the update function.
    // Specifically, this is (entry_chal, tr_chal). These are NOT inputted in the AllocVar impl
    challenges: Option<(FpVar<F>, FpVar<F>)>,
}

impl<F: PrimeField> RunningEvalsVar<F> {
    /// Updates the running evaluation of the time-ordered transcript polyn
    fn update_time_ordered(&mut self, entry: &RomTranscriptEntryVar<F>) {
        let (entry_chal, tr_chal) = self
            .challenges
            .as_ref()
            .expect("RunningEvalsVar.challenges needs to be set in order to run update");

        // The single-field-element representation of a transcript entry is val + entry_chal*addr,
        // where addr is the hash of the name
        let entry_repr = &entry.val + entry_chal * &entry.addr;

        // Now add the entry to the running polynomial eval. The polynomial is Π (X - entryᵢ)
        // evaluated at X=tr_chal
        self.time_ordered_eval *= tr_chal - entry_repr;
    }

    /// Updates the running evaluation of the addr-ordered transcript polyn
    fn update_addr_ordered(&mut self, entry: &RomTranscriptEntryVar<F>) {
        let (entry_chal, tr_chal) = self
            .challenges
            .as_ref()
            .expect("RunningEvalsVar.challenges needs to be set in order to run update");

        // The single-field-element representation of a transcript entry is val + entry_chal*addr,
        // where addr is the hash of the name
        let entry_repr = &entry.val + entry_chal * &entry.addr;

        // Now add the entry to the running polynomial eval. The polynomial is Π (X - entryᵢ)
        // evaluated at X=tr_chal
        self.addr_ordered_eval *= tr_chal - entry_repr;
    }
}

impl<F: PrimeField> R1CSVar<F> for RunningEvalsVar<F> {
    type Value = RunningEvals<F>;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.time_ordered_eval.cs().or(self.addr_ordered_eval.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let challenges = self
            .challenges
            .as_ref()
            .map(|(a, b)| {
                a.value()
                    .and_then(|aa| b.value().and_then(|bb| Ok((aa, bb))))
            })
            .transpose()?;

        Ok(RunningEvals {
            time_ordered_eval: self.time_ordered_eval.value()?,
            addr_ordered_eval: self.addr_ordered_eval.value()?,
            challenges,
        })
    }
}

impl<F: PrimeField> ToBytesGadget<F> for RunningEvalsVar<F> {
    fn to_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        Ok([
            self.time_ordered_eval.to_bytes()?,
            self.addr_ordered_eval.to_bytes()?,
        ]
        .concat())
    }
}

impl<F: PrimeField> AllocVar<RunningEvals<F>, F> for RunningEvalsVar<F> {
    fn new_variable<T: Borrow<RunningEvals<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let res = f();
        let evals = res.as_ref().map(|e| e.borrow()).map_err(|err| *err);

        let time_ordered_eval =
            FpVar::new_variable(ns!(cs, "time"), || evals.map(|e| e.time_ordered_eval), mode)?;
        let addr_ordered_eval =
            FpVar::new_variable(ns!(cs, "addr"), || evals.map(|e| e.addr_ordered_eval), mode)?;

        Ok(RunningEvalsVar {
            time_ordered_eval,
            addr_ordered_eval,
            challenges: None,
        })
    }
}

/// An entry in the transcript of portal wire reads
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RomTranscriptEntry<F: PrimeField> {
    addr: u64,
    val: F,
}

impl<F: PrimeField> RomTranscriptEntry<F> {
    fn to_bytes(&self) -> Vec<u8> {
        [
            self.addr.to_le_bytes().to_vec(),
            self.val.into_bigint().to_bytes_le(),
        ]
        .concat()
    }

    /// Returns an entry that always gets serialized as (0, 0). This is to pad the head of the
    /// address-sorted transcript
    fn padding() -> Self {
        RomTranscriptEntry {
            addr: 0,
            val: F::ZERO,
        }
    }
}

/// An entry in the transcript of portal wire reads
#[derive(Clone)]
pub(crate) struct RomTranscriptEntryVar<F: PrimeField> {
    val: FpVar<F>,
    /// The hash of the variable name
    addr: FpVar<F>,
}

impl<F: PrimeField> R1CSVar<F> for RomTranscriptEntryVar<F> {
    type Value = RomTranscriptEntry<F>;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.val.cs().or(self.addr.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let addr_bytes = self.addr.value()?.into_bigint().to_bytes_le();

        // Check that the address fits into 64 bits
        assert!(addr_bytes.iter().skip(8).all(|&b| b == 0));

        // Copy addr into a fixed-size buffer
        let mut addr_buf = [0u8; 8];
        addr_buf.copy_from_slice(&addr_bytes);

        Ok(RomTranscriptEntry {
            val: self.val.value()?,
            addr: u64::from_le_bytes(addr_buf),
        })
    }
}

impl<F: PrimeField> ToBytesGadget<F> for RomTranscriptEntryVar<F> {
    fn to_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        Ok([self.addr.to_bytes()?, self.val.to_bytes()?].concat())
    }
}

impl<F: PrimeField> AllocVar<RomTranscriptEntry<F>, F> for RomTranscriptEntryVar<F> {
    fn new_variable<T: Borrow<RomTranscriptEntry<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let res = f();
        let entry = res.as_ref().map(|e| e.borrow()).map_err(|err| *err);

        let val = FpVar::new_variable(ns!(cs, "val"), || entry.map(|e| F::from(e.val)), mode)?;
        let addr = FpVar::new_variable(ns!(cs, "addr"), || entry.map(|e| F::from(e.addr)), mode)?;

        Ok(RomTranscriptEntryVar { val, addr })
    }
}

/// A generic trait that any partitionable circuit has to impl
pub trait CircuitWithPortals<F: PrimeField> {
    // Parameters that define this circuit, e.g., number of subcircuits, number of iterations,
    // public constants, etc.
    type Parameters: Clone + CanonicalSerialize + CanonicalDeserialize;

    /// Retreive the set params from the given circuit
    fn get_params(&self) -> Self::Parameters;

    /// Gets all the subtraces of the portal wires used in this circuit instantiation
    fn get_portal_subtraces(&self) -> Vec<VecDeque<RomTranscriptEntry<F>>>;

    /// The number of subcircuits in this circuit
    fn num_subcircuits(&self) -> usize;

    /// Creates an empty copy of this circuit with the given parameters
    fn new(params: &Self::Parameters) -> Self;

    /// Gets the list of witnesses that belong to the given subcircuit
    fn get_serialized_witnesses(&self, subcircuit_idx: usize) -> Vec<u8>;

    /// Sets the list of witnesses that belong to the given subcircuit
    fn set_serialized_witnesses(&mut self, subcircuit_idx: usize, bytes: &[u8]);

    /// Generates constraints for the subcircuit at the given index. At index i, the ONLY witnesses
    /// the circuit may use are ones which would be set with
    /// `self.set_serialized_witnesses(i, ...)`.
    fn generate_constraints<P: PortalManager<F>>(
        &mut self,
        cs: ConstraintSystemRef<F>,
        subcircuit_idx: usize,
        pm: &mut P,
    ) -> Result<(), SynthesisError>;
}

#[cfg(test)]
mod test {
    use super::*;

    use ark_bls12_381::Fr;
    use ark_ff::UniformRand;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
    use ark_std::test_rng;
    use rand::Rng;

    #[test]
    fn running_eval_update_correctness() {
        let mut rng = test_rng();
        let cs = ConstraintSystemRef::<Fr>::new(ConstraintSystem::default());

        let mut re = RunningEvals {
            time_ordered_eval: Fr::rand(&mut rng),
            addr_ordered_eval: Fr::rand(&mut rng),
            challenges: Some((Fr::rand(&mut rng), Fr::rand(&mut rng))),
        };
        let mut re_var = RunningEvalsVar::new_constant(cs.clone(), &re).unwrap();
        re_var.challenges = Some((
            FpVar::new_constant(cs.clone(), re.challenges.unwrap().0).unwrap(),
            FpVar::new_constant(cs.clone(), re.challenges.unwrap().1).unwrap(),
        ));

        let entry = RomTranscriptEntry {
            addr: rng.gen(),
            val: Fr::rand(&mut rng),
        };
        let entry_var = RomTranscriptEntryVar::new_constant(cs.clone(), &entry).unwrap();
        re.update_time_ordered(&entry);
        re_var.update_time_ordered(&entry_var);

        let entry = RomTranscriptEntry {
            addr: rng.gen(),
            val: Fr::rand(&mut rng),
        };
        let entry_var = RomTranscriptEntryVar::new_constant(cs.clone(), &entry).unwrap();
        re.update_addr_ordered(&entry);
        re_var.update_addr_ordered(&entry_var);

        assert_eq!(re, re_var.value().unwrap());
    }
}
