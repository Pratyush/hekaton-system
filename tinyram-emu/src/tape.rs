use derivative::Derivative;

use crate::{word::Word, TinyRam};

/// Contains the RAM, ROM, and tapes necessary to run a program
#[derive(Derivative)]
#[derivative(
    Default(bound = "T: TinyRam"),
    Debug(bound = "T: TinyRam"),
    Clone(bound = "T: TinyRam"),
    PartialEq(bound = "T: TinyRam"),
    Eq(bound = "T: TinyRam")
)]
pub struct Tapes<T: TinyRam> {
    primary_tape: Vec<T::Word>,
    auxiliary_tape: Vec<T::Word>,
}

impl<T: TinyRam> Tapes<T> {
    pub fn initialize(primary_tape: Vec<T::Word>, auxiliary_tape: Vec<T::Word>) -> Self {
        Self {
            primary_tape,
            auxiliary_tape,
        }
    }

    /// Read a double word from the tape specified by `tape_number` at the location specified by
    /// `heads`.
    pub fn read_tape(
        &self,
        tape_number: T::Word,
        heads: &mut TapeHeads<T::Word>,
    ) -> Option<TapeOp<T::Word>> {
        match tape_number.into() {
            0 => self.read_primary_tape(&mut heads.primary),
            1 => self.read_auxiliary_tape(&mut heads.auxiliary),
            _ => None,
        }
    }

    fn read_primary_tape(&self, location: &mut TapeHead<T::Word>) -> Option<TapeOp<T::Word>> {
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

    fn read_auxiliary_tape(&self, location: &mut TapeHead<T::Word>) -> Option<TapeOp<T::Word>> {
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
pub struct TapeHeads<W> {
    pub primary: TapeHead<W>,
    pub auxiliary: TapeHead<W>,
}

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum TapeOp<W: Word> {
    ReadPrimary { val: W, location: TapeHead<W> },
    ReadAux { val: W, location: TapeHead<W> },
}

impl<W: Word> TapeOp<W> {
    pub fn val(&self) -> W {
        match self {
            TapeOp::ReadPrimary { val, .. } => *val,
            TapeOp::ReadAux { val, .. } => *val,
        }
    }
}
