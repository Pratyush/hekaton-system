use crate::option::OptionVar;

use super::*;

pub type CpuAnswerVar<T> = OptionVar<<T as TinyRamExt>::WordVar, <T as TinyRamExt>::F>;
