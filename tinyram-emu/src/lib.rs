pub mod encoding;
pub mod instructions;
pub mod interpreter;
pub mod memory;
pub mod parser;
pub mod program_state;
pub mod register;
pub mod word;

#[derive(Clone, Copy, Debug)]
pub enum TinyRamArch {
    Harvard,
    VonNeumann,
}

/// Contains important metadata about the program being run
#[derive(Clone, Copy, Debug)]
pub struct ProgramMetadata {
    /// The architecture of the CPU
    pub arch: TinyRamArch,
    /// The size, in words, of the primary input tape
    pub primary_input_len: u32,
    /// The size, in words, of the aux input tape
    pub aux_input_len: u32,
}
