use crate::word::Word;

pub struct PrimaryInput<W: Word> {
    pub tape: Vec<W>,
    pub pos: usize,
}

pub struct AuxInput<W: Word> {
    pub tape: Vec<W>,
    pub pos: usize,
}
