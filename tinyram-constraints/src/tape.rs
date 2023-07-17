use crate::{option::OptionVar, word::WordVar, TinyRamExt};
use derivative::Derivative;

/// Contains the RAM, ROM, and tapes necessary to run a program
#[derive(Derivative)]
#[derivative(Debug(bound = "T: TinyRamExt"), Clone(bound = "T: TinyRamExt"))]
pub struct TapesVar<T: TinyRamExt> {
    primary_tape: Vec<T::WordVar>,
    auxiliary_tape: Vec<T::WordVar>,
}

impl<T: TinyRamExt> TapesVar<T> {
    pub fn initialize(primary_tape: Vec<T::WordVar>, auxiliary_tape: Vec<T::WordVar>) -> Self {
        Self {
            primary_tape,
            auxiliary_tape,
        }
    }

    /// Read a double word from the tape specified by `tape_number` at the location specified by
    /// `heads`.
    pub fn read_tape(
        &self,
        tape_number: T::WordVar,
        heads: &mut TapeHeadsVar<T::WordVar>,
    ) -> OptionVar<TapeOp<T::WordVar>, T::F> {
        let tape_number = tape_number.as_fp();
        let is_primary_tape = tape_number.is_zero();
        let is_auxiliary_tape = tape_number.is_one();
        match tape_number.into() {
            0 => self.read_primary_tape(&mut heads.primary),
            1 => self.read_auxiliary_tape(&mut heads.auxiliary),
            _ => None,
        }
    }

    fn read_primary_tape(&self, location: &mut TapeHead<T::WordVar>) -> Option<TapeOp<T::WordVar>> {
        self.primary_tape
            .get((*location).into() as usize)
            .copied()
            .map(|val| {
                *location = location.wrapping_increment();
                TapeOp::ReadPrimary {
                    val,
                    location: *location,
                }
            })
    }

    fn read_auxiliary_tape(
        &self,
        location: &mut TapeHead<T::WordVar>,
    ) -> Option<TapeOp<T::WordVar>> {
        self.auxiliary_tape
            .get((*location).into() as usize)
            .copied()
            .map(|val| {
                *location = location.wrapping_increment();
                TapeOp::ReadAux {
                    val,
                    location: *location,
                }
            })
    }
}

pub type TapeHead<W> = W;

/// A pair of tape heads, one for the primary tape and one for the auxiliary tape.
#[derive(Clone, Copy, Eq, PartialEq, Debug, Default)]
pub struct TapeHeadsVar<W> {
    pub primary: TapeHead<W>,
    pub auxiliary: TapeHead<W>,
}

impl<W: WordVar> Default for TapeHeadsVar<W> {
    fn default() -> Self {
        Self {
            primary: W::zero(),
            auxiliary: W::zero(),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum TapeOp<W: WordVar> {
    ReadPrimary { val: W, location: TapeHead<W> },
    ReadAux { val: W, location: TapeHead<W> },
}

impl<W: WordVar> TapeOp<W> {
    pub fn val(&self) -> W {
        match self {
            TapeOp::ReadPrimary { val, .. } => *val,
            TapeOp::ReadAux { val, .. } => *val,
        }
    }
}
