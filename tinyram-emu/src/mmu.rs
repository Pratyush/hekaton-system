use ark_ff::Field;
use derivative::Derivative;
use rand::Rng;

use crate::{
    instructions::Instr,
    word::{DoubleWord, Word},
    TinyRam, TinyRamArch,
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

/// A TinyRAM memory operation. This only deals in double words.
///
/// NOTE: A `read` op from an invalid tape index (2 or greater) is converted to an `xor ri ri`,
/// i.e., it is not considered a memory operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemOp<W: Word> {
    /// Load a double word from RAM
    Load {
        /// The double word being loaded
        val: DoubleWord<W>,
        /// The index the value is being loaded from
        location: W,
    },
    /// Store a double word to RAM
    Store {
        /// The double word being stored
        val: DoubleWord<W>,
        /// The index the value is being stored to
        location: W,
    },
}

impl<W: Word> MemOp<W> {
    /// Returns a random `MemOp`. Useful for testing
    pub fn rand(mut rng: impl Rng) -> Self {
        let kind: bool = rng.gen();
        let val = (W::rand(&mut rng), W::rand(&mut rng));
        let location = W::rand(&mut rng);
        match kind {
            true => MemOp::Store { val, location },
            false => MemOp::Load { val, location },
        }
    }
}

/// The kind of memory operation
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemOpKind {
    /// A memory op corresponding to `loadw` or `loadb`
    Load = 0,
    /// A memory op corresponding to `storew` or `storeb`
    Store,
}

impl<W: Word> From<&MemOp<W>> for MemOpKind {
    fn from(op: &MemOp<W>) -> Self {
        match op {
            MemOp::Load { .. } => MemOpKind::Load,
            MemOp::Store { .. } => MemOpKind::Store,
        }
    }
}

impl<W: Word> MemOp<W> {
    pub fn kind(&self) -> MemOpKind {
        MemOpKind::from(self)
    }

    /// Gets the double word being loaded or stored. If it's a valid tape op, then returns the word
    /// being read in the low position, and 0 in the high position. If it's an invalid tape op,
    /// then returns (0, 0)
    pub fn val(&self) -> DoubleWord<W> {
        match self {
            MemOp::Load { val, .. } => val.clone(),
            MemOp::Store { val, .. } => val.clone(),
        }
    }

    /// Returns the location of this memory op if it's a RAM op, and the tape head position if it's
    /// a tape op. If it's an invalid tape op, i.e., `ReadInvalid`, returns 0.
    pub fn location(&self) -> u64 {
        match *self {
            MemOp::Store { location, .. } => location.into(),
            MemOp::Load { location, .. } => location.into(),
        }
    }

    /// Returns this memory operation, packed into the low bits of a field element. Also returns
    /// how many bits are used in the packing.
    pub fn as_fp<F: Field>(&self) -> (F, usize) {
        fn pow_two<G: Field>(n: usize) -> G {
            G::from(2u8).pow([n as u64])
        }

        // We pack this as 0000...000 val || location || kind, where location is padded to u64
        // The format doesn't really matter so long as we're consistent
        let kind = self.kind();
        let val = self.val();
        let loc = self.location();

        // Keep track of the running bitlength
        let mut bitlen = 0;
        let mut out = F::zero();

        // Pack kind into the bottom 1 bit
        out += F::from(kind as u8);
        bitlen += 1;

        // Pack loc as a u64
        out += pow_two::<F>(bitlen) * F::from(loc);
        bitlen += 64;

        // val is a double word, so pack each of its words separately
        out += pow_two::<F>(bitlen) * F::from(val.0.into());
        bitlen += W::BIT_LENGTH;
        out += pow_two::<F>(bitlen) * F::from(val.1.into());
        bitlen += W::BIT_LENGTH;

        (out, bitlen)
    }
}
