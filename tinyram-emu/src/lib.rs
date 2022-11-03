pub mod encoding;
pub mod input_tape;
pub mod instructions;
pub mod interpreter;
pub mod memory;
pub mod program_state;
pub mod register;
pub mod word;

#[derive(Clone, Copy, Debug)]
pub enum TinyRamArch {
    Harvard,
    VonNeumann,
}
