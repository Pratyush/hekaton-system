use core::fmt::Debug;

pub trait Word: Debug + Eq + Ord + Copy {
    const BIT_SIZE: u32;
}

impl Word for u8 {
    const BIT_SIZE: u32 = 8;
}

impl Word for u16 {
    const BIT_SIZE: u32 = 16;
}

impl Word for u32 {
    const BIT_SIZE: u32 = 32;
}

impl Word for u64 {
    const BIT_SIZE: u32 = 64;
}