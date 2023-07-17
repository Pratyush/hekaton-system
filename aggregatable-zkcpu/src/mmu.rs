use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{fields::fp::FpVar, prelude::Boolean, select::CondSelectGadget};
use ark_relations::r1cs::SynthesisError;
use derivative::Derivative;
use rand::Rng;
use tinyram_emu::MemOpKind;

use crate::{
    instructions::Instr,
    word::{DoubleWord, Word},
    TinyRam, TinyRamArch, common::RamIdxVar, TinyRamExt,
};

use std::{collections::BTreeMap, ops::Range};

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct DataMemory<W: Word>(BTreeMap<W, u8>);

impl<W: Word> DataMemory<W> {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn new(memory: BTreeMap<W, u8>) -> Self {
        Self(memory)
    }

    pub fn insert(&mut self, index: W, value: u8) -> Option<u8> {
        self.0.insert(index, value)
    }

    pub fn get(&self, index: W) -> Option<&u8> {
        self.0.get(&index)
    }

    pub fn get_mut(&mut self, index: W) -> Option<&mut u8> {
        self.0.get_mut(&index)
    }

    pub fn extend(&mut self, iter: impl IntoIterator<Item = (W, u8)>) {
        self.0.extend(iter)
    }
}

impl<W: Word> std::ops::Index<W> for DataMemory<W> {
    type Output = u8;
    fn index(&self, index: W) -> &Self::Output {
        self.0.index(&index)
    }
}

#[derive(Derivative)]
#[derivative(
    Default(bound = "T: TinyRam"),
    Debug(bound = "T: TinyRam"),
    Clone(bound = "T: TinyRam"),
    PartialEq(bound = "T: TinyRam"),
    Eq(bound = "T: TinyRam")
)]
pub struct ProgramMemory<T: TinyRam>(Vec<Instr<T>>);

impl<T: TinyRam> ProgramMemory<T> {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn new(memory: Vec<Instr<T>>) -> Self {
        Self(memory)
    }

    pub fn get(&self, index: T::Word) -> Option<&Instr<T>> {
        self.0.get(index.into() as usize)
    }
}

impl<T: TinyRam> std::ops::Index<T::Word> for ProgramMemory<T> {
    type Output = Instr<T>;

    fn index(&self, index: T::Word) -> &Self::Output {
        self.get(index).unwrap()
    }
}

/// Contains the RAM, ROM, and tapes necessary to run a program
#[derive(Derivative)]
#[derivative(Default(bound = "T: TinyRam"))]
pub struct MemoryUnit<T: TinyRam> {
    data_ram: DataMemory<T::Word>,
    program_rom: ProgramMemory<T>,
}

impl<T: TinyRam> MemoryUnit<T> {
    pub fn initialize(program: &[Instr<T>]) -> Self {
        let (data_ram, program_rom) = match T::ARCH {
            TinyRamArch::Harvard => {
                // For Harvard we just wrap the given instructions and that's it
                // Make sure the program is word-addressable
                assert!((program.len() as u128) < (1u128 << T::Word::BIT_LENGTH));

                // Return the memory
                (DataMemory::default(), ProgramMemory(program.to_vec()))
            },
            TinyRamArch::VonNeumann => {
                // For von Neumann we're will serialize the program into data memory
                // Every instruction is 2 words
                let serialized_program_bytelen = program.len() * T::SERIALIZED_INSTR_BYTE_LENGTH;
                // Make sure the program is word-addressable
                assert!((serialized_program_bytelen as u128) < (1u128 << T::Word::BIT_LENGTH));

                // The memory is initialized with just the program, starting at address 0. Memory is a
                // sparse map of addr -> byte
                let serialized_program: BTreeMap<T::Word, u8> = program
                    .iter()
                    .flat_map(Instr::to_bytes)
                    .enumerate()
                    .map(|(i, b)| (T::Word::from_u64(i as u64), b))
                    .collect();

                // Return the memory
                (
                    DataMemory::new(serialized_program),
                    ProgramMemory::default(),
                )
            },
        };
        Self {
            data_ram,
            program_rom,
        }
    }

    pub fn get_instruction(&self, pc: T::Word) -> Instr<T> {
        match T::ARCH {
            TinyRamArch::Harvard => {
                let pc_as_usize = pc
                    .try_into()
                    .ok()
                    .expect("program counter exceeds usize::MAX");
                *self
                    .program_rom
                    .0
                    .get(pc_as_usize)
                    .unwrap_or(&Instr::Answer {
                        in1: crate::register::ImmOrRegister::Imm(T::Word::ONE),
                    })
            },
            TinyRamArch::VonNeumann => {
                // Collect 2 words of bytes starting at pc. 16 is the upper bound on the number of
                // bytes
                let encoded_instr: Vec<u8> = (pc.into()..)
                    .take(T::Word::INSTR_BYTE_LENGTH)
                    .map(T::Word::from_u64)
                    .map(|w| {
                        // TODO: Check that `i` didn't overflow Self::Word::MAX
                        *self
                            .data_ram
                            .get(w)
                            .unwrap_or_else(|| panic!("illegal jump to 0x{:08x}", pc.into()))
                    })
                    .collect();
                Instr::from_bytes(&encoded_instr)
            },
        }
    }

    fn calc_addr_and_double_word_addr(loc: T::Word) -> (u64, u64) {
        // Round the byte address down to the nearest word and double word boundary
        let word_addr: u64 = loc.into() - (loc.into() % (T::Word::BYTE_LENGTH as u64));
        let double_word_addr = word_addr - (word_addr % (2 * T::Word::BYTE_LENGTH as u64));
        (word_addr, double_word_addr)
    }

    fn get_bytes_for_double_word(&self, double_word_addr: u64) -> (Range<u64>, Vec<u8>) {
        // Fetch a double word's worth of bytes from memory, using 0 where undefined
        let index_range = double_word_addr..(double_word_addr + 2 * T::Word::BYTE_LENGTH as u64);
        (
            index_range.clone(),
            index_range
                .clone()
                .map(|i| *self.data_ram.get(T::Word::from_u64(i)).unwrap_or(&0))
                .collect(),
        )
    }

    fn bytes_to_words(bytes: &[u8]) -> (T::Word, T::Word) {
        // Now convert the little-endian encoded bytes into words
        let w0 = T::Word::from_le_bytes(&bytes[..T::Word::BYTE_LENGTH]).unwrap();
        let w1 = T::Word::from_le_bytes(&bytes[T::Word::BYTE_LENGTH..]).unwrap();
        (w0, w1)
    }

    pub(crate) fn store_word(&mut self, loc: T::Word, word: T::Word) -> MemOp<T::Word> {
        let (word_addr, double_word_addr) = Self::calc_addr_and_double_word_addr(loc);

        // Fetch a double word's worth of bytes from memory, using 0 where undefined
        let (index_range, mut bytes) = self.get_bytes_for_double_word(double_word_addr);

        // Determine if this word is the low or high word in the double word
        let is_high = word_addr != double_word_addr;
        // Overwrite whatever is being stored.
        // Overwrite the first word if `is_high = false`; else, overwrite the second.
        let start = (is_high as usize) * T::Word::BYTE_LENGTH;
        bytes[start..][..T::Word::BYTE_LENGTH].copy_from_slice(&word.to_le_bytes());

        // Update the memory
        for (i, b) in index_range
            .zip(&bytes)
            .map(|(i, b)| (T::Word::from_u64(i), *b))
        {
            self.data_ram.insert(i, b);
        }

        let (w0, w1) = Self::bytes_to_words(&bytes);

        // Construct the memory operation
        MemOp::Store {
            val: (w0, w1),
            location: loc.align_to_double_word(),
        }
    }

    pub(crate) fn load_word(&self, loc: T::Word) -> (T::Word, MemOp<T::Word>) {
        let (word_addr, double_word_addr) = Self::calc_addr_and_double_word_addr(loc);

        // Fetch a double word's worth of bytes from memory, using 0 where undefined
        let (_, bytes) = self.get_bytes_for_double_word(double_word_addr);

        let (w0, w1) = Self::bytes_to_words(&bytes);
        // Construct the memory operation
        let mem_op = MemOp::Load {
            val: (w0, w1),
            location: loc.align_to_double_word(),
        };
        // Set set the register to the first part of the double word if `is_high == false`.
        // Otherwise use the second word.
        let is_high = word_addr != double_word_addr;
        let result = if is_high { w1 } else { w0 };
        (result, mem_op)
    }
}


/// An `ExecTickMemData` can be a LOAD (= 0) or a STORE (= 1), or no-op (= 2)
#[derive(Clone)]
pub(crate) struct MemOpKindVar<F: PrimeField>(FpVar<F>);

#[allow(non_upper_case_globals)]
impl<F: PrimeField> MemOpKindVar<F> {
    pub const Load: Self = Self(FpVar::Constant(F::ZERO));
    
    pub const Store: Self = Self(FpVar::Constant(F::ONE));

    pub const NoOp: Self = Self(FpVar::Constant(F::from(2u8)));

    /// Checks that this `ExecTickMemDataKind` is one of `Self::Load`, `Self::Store`, or `Self::NoOp`
    pub(crate) fn enforce_well_formed(&self) -> Result<(), SynthesisError> {
        let x = MemOpKindVar::load()
            * (&self.0 - MemOpKindVar::store())
            * (&self.0 - MemOpKindVar::no_mem());
        x.enforce_equal(&FpVar::zero())
    }

    pub(crate) fn no_op() -> FpVar<F> {
        FpVar::constant(F::from(2u8))
    }

    pub(crate) fn is_no_op(&self) -> Result<Boolean<F>, SynthesisError> {
        self.0.is_eq(&MemOpKindVar::no_mem())
    }

    pub(crate) fn is_store(&self) -> Result<Boolean<F>, SynthesisError> {
        self.0.is_eq(&MemOpKindVar::store())
    }
}

impl<T: TinyRamExt> From<MemOpVar<T>> for MemOpKindVar<T::F> {
    fn from(mem_op: MemOpVar<T>) -> Self {
        mem_op.kind
    }
}

impl<'a, T: TinyRamExt> From<&'a MemOpVar<T>> for MemOpKindVar<T::F> {
    fn from(mem_op: MemOpVar<T>) -> Self {
        mem_op.kind
    }
}



/// Represents the decoded instruction and register information used to LOAD or STORE in a small
/// tick. `Load` doesn't carry the thing loaded because that has to come from outside the CPU, from
/// the memory.
#[derive(Clone)]
pub(crate) struct MemOpVar<T: TinyRamExt> {
    /// The kind of data this is. A LOAD, a STORE, or a no-op
    pub(crate) kind: MemOpKindVar<T::F>,
    /// The RAM index loaded from or stored into. This is not checked when kind == no-op
    pub(crate) idx: RamIdxVar<T::WordVar>,
    /// The value stored into RAM. This is not checked when kind == no-op or LOAD
    pub(crate) stored_word: T::WordVar,
}

impl<T: TinyRamExt> MemOpVar<T> {
    pub fn kind(&self) -> &MemOpKindVar<T::F> {
        &self.kind
    }
}

impl<T: TinyRamExt> Default for MemOpVar<T> {
    fn default() -> Self {
        MemOpVar {
            kind: MemOpKindVar(MemOpKindVar::no_op()),
            idx: RamIdxVar::<T::WordVar>::zero(),
            stored_word: T::WordVar::zero(),
        }
    }
}

impl<T: TinyRamExt> CondSelectGadget<T::F> for MemOpVar<T> {
    fn conditionally_select(
        cond: &Boolean<T::F>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        let kind = MemOpKindVar(cond.select(&true_value.kind.0, &false_value.kind.0)?);
        let idx = cond.select(&true_value.idx, &false_value.idx)?;
        let stored_word = cond.select(&true_value.stored_word, &false_value.stored_word)?;

        Ok(MemOpVar {
            kind,
            idx,
            stored_word,
        })
    }
}