use crate::{
    instructions::{opcode::Opcode, Instr},
    register::{ImmOrRegister, RegIdx},
    TinyRam, TinyRamArch,
};

use core::str::FromStr;
use std::{collections::BTreeMap, marker::PhantomData};

use pest::{
    iterators::{Pair, Pairs},
    Parser as PestParser,
};

#[derive(pest_derive::Parser)]
#[grammar = "tinyram.pest"]
pub struct Parser;

/// The context necessary to lower the parsed TinyRAM program, i.e., convert the AST to concrete
/// types and real memory offsets.
pub struct LoweringCtx<'a, T: TinyRam> {
    // This is the line number in the file, ignoring whitespace and header
    // instr_count: usize,
    /// This contains arch information we need in lowering
    header: TinyRamHeader,
    /// A map of all the labels we've seen so far and their corresponding word idx
    label_addrs: BTreeMap<&'a str, u64>,
    _phantom: std::marker::PhantomData<T>,
}

impl<'a, T: TinyRam> LoweringCtx<'a, T> {
    fn label_addr(&self, label: &str) -> u64 {
        match self.label_addrs.get(label) {
            Some(&w) => w,
            None => panic!("unknown label {label}"),
        }
    }
}

#[derive(Debug)]
pub struct TinyRamHeader {
    arch: TinyRamArch,
    word_bitlen: u32,
    num_regs: u32,
}

impl<'a, T: TinyRam> LoweringCtx<'a, T> {
    /// Converts a parse `Pair` to a map from rule -> str
    pub fn parsed_dict(pair: Pair<Rule>) -> BTreeMap<Rule, &str> {
        pair.into_inner()
            .map(|p| (p.as_rule(), p.as_str()))
            .collect()
    }

    /// Lowers a parsed header into a `TinyRamHeader`
    pub fn lower_header(pair: Pair<Rule>) -> TinyRamHeader {
        assert_eq!(pair.as_rule(), Rule::header);
        let dict = Self::parsed_dict(pair);

        let arch = match dict[&Rule::arch] {
            "hv" => TinyRamArch::Harvard,
            "vn" => TinyRamArch::VonNeumann,
            a => panic!("unknown arch: {a}"),
        };
        TinyRamHeader {
            arch,
            word_bitlen: u32::from_str(dict[&Rule::word_bitlen]).unwrap(),
            num_regs: u32::from_str(dict[&Rule::num_regs]).unwrap(),
        }
    }

    /// Lowers a parsed register in a `RegIdx`
    pub fn lower_reg(pair: Pair<Rule>) -> RegIdx {
        assert_eq!(pair.as_rule(), Rule::reg);
        // The first character of a register is 'r'
        let reg_idx_str = &pair.as_str()[1..];
        RegIdx::from_str(reg_idx_str).unwrap()
    }

    /// Lowers a parsed immediate into a word
    pub fn lower_imm(&self, pair: Pair<Rule>) -> T::Word {
        assert_eq!(pair.as_rule(), Rule::imm);
        let val = pair.into_inner().next().unwrap();
        let val_str = val.as_str().trim();

        match val.as_rule() {
            Rule::label => {
                let label_val = self.label_addr(val_str);
                T::Word::try_from(label_val)
                    .map_err(|_| format!("label {val_str} is out of bounds"))
                    .unwrap()
            },
            Rule::dec_num => {
                let dec_val = u64::from_str(val_str)
                    .map_err(|_| format!("invalid number {val_str}"))
                    .unwrap();
                T::Word::try_from(dec_val)
                    .map_err(|_| format!("decimal {val_str} is out of bounds"))
                    .unwrap()
            },
            r => panic!("unexpected rule {:?}", r),
        }
    }

    /// Lowers a parsed immediate-or-register into an `ImmOrRegister`
    pub fn lower_imm_or_reg(&self, pair: Pair<Rule>) -> ImmOrRegister<T> {
        assert_eq!(pair.as_rule(), Rule::imm_or_reg);
        let val = pair.into_inner().next().unwrap();

        match val.as_rule() {
            Rule::imm => {
                let word = self.lower_imm(val);
                ImmOrRegister::Imm(word)
            },
            Rule::reg => {
                let reg_idx = Self::lower_reg(val);
                ImmOrRegister::Register(reg_idx)
            },
            r => panic!("unexpected rule {:?}", r),
        }
    }

    /// Lowers a register-register-immorreg instruction
    pub fn lower_rri_instr(&self, pair: Pair<Rule>) -> Instr<T> {
        assert_eq!(pair.as_rule(), Rule::rri_instr);
        let mut it = pair.into_inner();

        // First parse the rri_instr_begin
        let opcode_str = it.next().unwrap().as_str().trim();
        let op = Opcode::try_from(opcode_str.trim())
            .map_err(|_| format!("unknown instruction {opcode_str}"))
            .unwrap();

        // Step into rri_instr_inputs
        let mut it = it.next().unwrap().into_inner();

        // Parse reg1
        let out_pair = it.next().unwrap();
        let out = Self::lower_reg(out_pair);

        // Parse reg2
        let in1_pair = it.next().unwrap();
        let in1 = Self::lower_reg(in1_pair);

        // Parse imm_or_reg
        let in2_pair = it.next().unwrap();
        let in2 = self.lower_imm_or_reg(in2_pair);

        match op {
            Opcode::And => Instr::And { in1, in2, out },
            Opcode::Or => Instr::Or { in1, in2, out },
            Opcode::Xor => Instr::Xor { in1, in2, out },
            Opcode::Add => Instr::Add { in1, in2, out },
            Opcode::Sub => Instr::Sub { in1, in2, out },
            Opcode::MulL => Instr::MulL { in1, in2, out },
            Opcode::UMulH => Instr::UMulH { in1, in2, out },
            Opcode::SMulH => Instr::SMulH { in1, in2, out },
            Opcode::UDiv => Instr::UDiv { in1, in2, out },
            Opcode::UMod => Instr::UMod { in1, in2, out },
            Opcode::Shl => Instr::Shl { in1, in2, out },
            Opcode::Shr => Instr::Shr { in1, in2, out },
            _ => panic!("Unexpected opcode: {op:?}"),
        }
    }

    /// Lowers a register-immorreg instruction
    pub fn lower_ri_instr(&self, pair: Pair<Rule>) -> Instr<T> {
        assert_eq!(pair.as_rule(), Rule::ri_instr);
        let mut it = pair.into_inner();

        // First parse the ri_instr_begin
        let opcode_str = it.next().unwrap().as_str().trim();
        let op = Opcode::try_from(opcode_str.trim())
            .map_err(|_| format!("unknown instruction {opcode_str}"))
            .unwrap();

        // Step into ri_instr_inputs
        let mut it = it.next().unwrap().into_inner();

        // Parse reg1. This is either in1 or out, depending on the instruction
        let reg1_pair = it.next().unwrap();
        let arg1 = Self::lower_reg(reg1_pair);

        // Parse imm_or_reg. This is either in2 or in1, depending on the instruction
        let imm_or_reg_pair = it.next().unwrap();
        let arg2 = self.lower_imm_or_reg(imm_or_reg_pair);

        match op {
            Opcode::CmpE => Instr::CmpE {
                in1: arg1,
                in2: arg2,
            },
            Opcode::CmpA => Instr::CmpA {
                in1: arg1,
                in2: arg2,
            },
            Opcode::CmpAe => Instr::CmpAE {
                in1: arg1,
                in2: arg2,
            },
            Opcode::CmpG => Instr::CmpG {
                in1: arg1,
                in2: arg2,
            },
            Opcode::CmpGe => Instr::CmpGE {
                in1: arg1,
                in2: arg2,
            },
            Opcode::Mov => Instr::Mov {
                in1: arg2,
                out: arg1,
            },
            Opcode::CMov => Instr::CMov {
                in1: arg2,
                out: arg1,
            },
            Opcode::LoadB => Instr::LoadB {
                out: arg1,
                in1: arg2,
            },
            Opcode::LoadW => Instr::LoadW {
                out: arg1,
                in1: arg2,
            },
            Opcode::Read => Instr::Read {
                out: arg1,
                in1: arg2,
            },
            _ => panic!("Unexpected op {op:?}"),
        }
    }

    /// Lowers an immorreg-register instruction
    pub fn lower_ir_instr(&self, pair: Pair<Rule>) -> Instr<T> {
        assert_eq!(pair.as_rule(), Rule::ir_instr);
        let mut it = pair.into_inner();

        // First parse the ir_instr_begin
        let opcode_str = it.next().unwrap().as_str().trim();
        let op = Opcode::try_from(opcode_str.trim())
            .map_err(|_| format!("unknown instruction {opcode_str}"))
            .unwrap();

        // Step into ir_instr_inputs
        let mut it = it.next().unwrap().into_inner();

        // Parse imm_or_reg. This is the `out` RAM idx
        let imm_or_reg_pair = it.next().unwrap();
        let imm_or_reg = self.lower_imm_or_reg(imm_or_reg_pair);

        // Parse reg1. This is in1
        let reg1_pair = it.next().unwrap();
        let reg1 = Self::lower_reg(reg1_pair);

        match op {
            Opcode::StoreW => Instr::StoreW {
                in1: reg1,
                out: imm_or_reg,
            },
            Opcode::StoreB => Instr::StoreB {
                in1: reg1,
                out: imm_or_reg,
            },
            _ => panic!("Unexpected op {op:?}"),
        }
    }

    /// Lowers an immorreg instruction
    pub fn lower_i_instr(&self, pair: Pair<Rule>) -> Instr<T> {
        assert_eq!(pair.as_rule(), Rule::i_instr);
        let mut it = pair.into_inner();

        // First parse the i_instr_begin
        let opcode_str = it.next().unwrap().as_str().trim();
        let op = Opcode::try_from(opcode_str.trim())
            .map_err(|_| format!("unknown instruction {opcode_str}"))
            .unwrap();

        // Step into i_instr_inputs
        let mut it = it.next().unwrap().into_inner();

        // Parse imm_or_reg
        let in1_pair = it.next().unwrap();
        let in1 = self.lower_imm_or_reg(in1_pair);

        match op {
            Opcode::Jmp => Instr::Jmp { in1 },
            Opcode::CJmp => Instr::CJmp { in1 },
            Opcode::CnJmp => Instr::CNJmp { in1 },
            Opcode::Answer => Instr::Answer { in1 },
            _ => panic!("Unexpected op {:?}", op),
        }
    }

    /// Lowers any instruction
    pub fn lower_any_instr(&self, pair: Pair<Rule>) -> Instr<T> {
        assert_eq!(pair.as_rule(), Rule::any_instr);
        let val = pair.into_inner().next().unwrap();

        match val.as_rule() {
            Rule::i_instr => self.lower_i_instr(val),
            Rule::ir_instr => self.lower_ir_instr(val),
            Rule::ri_instr => self.lower_ri_instr(val),
            Rule::rri_instr => self.lower_rri_instr(val),
            r => panic!("unexpected rule {r:?}"),
        }
    }

    /// Lowers a full instruction, including label defs
    pub fn lower_full_instr(&self, pair: Pair<Rule>) -> Instr<T> {
        assert_eq!(pair.as_rule(), Rule::full_instr);

        // Skip all the label defs. We already processed them.
        let val = pair
            .into_inner()
            .skip_while(|p| p.as_rule() == Rule::label_def)
            .next()
            .unwrap();

        // Now parse the instruction
        self.lower_any_instr(val)
    }

    /// Lowers a code line, which is an optional full instr plus an optional comment
    pub fn lower_line(&self, pair: Pair<Rule>) -> Option<Instr<T>> {
        assert_eq!(pair.as_rule(), Rule::line);

        // The first line item may be a full instruction. If so, lower it. Otherwise do nothing.
        pair.into_inner().find_map(|item| {
            if item.as_rule() == Rule::full_instr {
                Some(self.lower_full_instr(item))
            } else {
                None
            }
        })
    }

    /// Takes a TinyRAM header and the rest of the parsed assembly, and produces an offset table, i.e.,
    /// a map from label to its word (or byte, in von Neumann) offset.
    pub fn build_label_table(
        header: &TinyRamHeader,
        lines: Pairs<'a, Rule>,
    ) -> BTreeMap<&'a str, u64> {
        let mut instr_number = 0;
        let mut table = BTreeMap::new();
        let mut saw_first_instr = false;

        let instr_number_step = match header.arch {
            TinyRamArch::Harvard => 1,
            TinyRamArch::VonNeumann => 2 * (header.word_bitlen as u64) / 8,
        };

        for t in lines.flatten() {
            match t.as_rule() {
                Rule::label_def => {
                    let label = t.into_inner().next().unwrap().as_str();
                    table.insert(label, instr_number);
                },
                Rule::full_instr => {
                    // Make sure we start counting instructions at 0
                    if saw_first_instr {
                        instr_number += instr_number_step;
                    } else {
                        saw_first_instr = true;
                    }
                },
                _ => (),
            }
        }

        table
    }
}

impl Parser {
    pub fn assemble<T: TinyRam>(tinyram_program: &str) -> Vec<Instr<T>> {
        let parse = Self::parse(Rule::file, &tinyram_program).unwrap();
        Self::lower_file(parse)
    }

    /// Lowers a whole file
    pub fn lower_file<T: TinyRam>(mut pairs: Pairs<Rule>) -> Vec<Instr<T>> {
        let mut it = pairs.next().unwrap().into_inner();

        // Parse the header and make the lowering context
        let header = LoweringCtx::<T>::lower_header(it.next().unwrap());
        let rest_of_file = it.clone();
        let label_addrs = LoweringCtx::<T>::build_label_table(&header, rest_of_file);
        let ctx = LoweringCtx {
            header,
            label_addrs,
            _phantom: PhantomData,
        };

        // Now parse all the instructions
        it.flatten()
            .filter_map(|item| {
                if item.as_rule() == Rule::line {
                    ctx.lower_line(item)
                } else {
                    None
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Try to parse a header
    #[test]
    fn test_header() {
        fn header_test<T: TinyRam>() {
            let header = T::header();
            let d = Parser::parse(Rule::header, &header).unwrap();
            println!("d == {:?}", d);
        }
        crate::iter_over_tinyram_configs!(header_test);
    }

    /// Parse a few individual lines, and then a whole (nonsense) program
    #[test]
    fn test_instrs() {
        fn instr_tests<T: TinyRam>() {
            let sample_rri = "xor r1, r3, _loop";
            Parser::parse(Rule::rri_instr, sample_rri).unwrap();

            let sample_ri = "cmpe r12, 1337";
            Parser::parse(Rule::ri_instr, sample_ri).unwrap();

            let sample_i = "jmp _3lite ; hello world";
            Parser::parse(Rule::line, sample_i).unwrap();

            let sample_full = "_loop: not r12, r0";
            Parser::parse(Rule::full_instr, sample_full).unwrap();

            let sample_file = format!(
                "\
            {}\n  \
            jmp _3lite ; hello world \n\n   \
            _loop:   not r12, r0\n\
            cmpe r12, 1337\n\
            _acc:xor r1, r3, _loop\
            ",
                T::header()
            );
            let sample_parsing = Parser::parse(Rule::file, &sample_file).unwrap();
            println!("program parse == {:#?}", sample_parsing);

            let mut p = sample_parsing;
            let mut file = p.next().unwrap().into_inner();
            let header_parse = file.next().unwrap();
            let header = LoweringCtx::<T>::lower_header(header_parse);
            println!("header parse == {:#?}", header,);

            let rest_of_file = file;
            println!("p == {:?}", p);
            let label_table = LoweringCtx::<T>::build_label_table(&header, rest_of_file);
            println!("label table == {:#?}", label_table);
        }

        crate::iter_over_tinyram_configs!(instr_tests);
    }

    fn imm<T: TinyRam>(val: u64) -> ImmOrRegister<T> {
        ImmOrRegister::new(val, true).unwrap()
    }

    // The skip3 program (from interpreter.rs). No header included, so you can prepend whatever you
    // want.
    pub(crate) const SKIP3_CODE: &str = "\
        _loop: add  r0, r0, 1     ; incr i
               add  r2, r2, 1     ; incr mul3_ctr
               cmpe r0, 100       ; if i == 100:
               cjmp _end          ;     jump to end
               cmpe r2, 3         ; else if mul3_ctr == 3:
               cjmp _acc          ;     jump to acc
               jmp  _loop         ; else jump to beginning

         _acc: add r1, r1, r0     ; Accumulate i into acc
               xor r2, r2, r2     ; Clear mul3_ctr
               jmp _loop          ; Jump back to the loop

         _end: answer r1          ; Return acc
        ";

    /// Tests the compilation of the skip3 code from the tests in interpreter.rs
    #[test]
    fn test_skip3() {
        fn skip3_test<T: TinyRam>() {
            // The correct _loop, _acc, and _end jump labels for Harvard and von Neumann, respectively
            let (label_loop, label_acc, label_end) = match T::ARCH {
                TinyRamArch::Harvard => (imm::<T>(0x00), imm(0x07), imm(0x0a)),
                // For VonNeumann, this depends on the word size (since memory is byte addressable)
                TinyRamArch::VonNeumann => {
                    let jump_size = T::SERIALIZED_INSTR_BYTE_LENGTH as u64;
                    (
                        imm::<T>(0x00 * jump_size),
                        imm(0x07 * jump_size),
                        imm(0x0a * jump_size),
                    )
                },
            };

            // The register indices
            let reg0 = RegIdx(0);
            let reg1 = RegIdx(1);
            let reg2 = RegIdx(2);

            let asm = [
                Instr::Add {
                    out: reg0,
                    in1: reg0,
                    in2: imm(1),
                },
                Instr::Add {
                    out: reg2,
                    in1: reg2,
                    in2: imm(1),
                },
                Instr::CmpE {
                    in1: reg0,
                    in2: imm(100),
                },
                Instr::CJmp { in1: label_end },
                Instr::CmpE {
                    in1: reg2,
                    in2: imm(3),
                },
                Instr::CJmp { in1: label_acc },
                Instr::Jmp { in1: label_loop },
                Instr::Add {
                    out: reg1,
                    in1: reg1,
                    in2: ImmOrRegister::Register(reg0),
                },
                Instr::Xor {
                    out: reg2,
                    in1: reg2,
                    in2: ImmOrRegister::Register(reg2),
                },
                Instr::Jmp { in1: label_loop },
                Instr::Answer {
                    in1: ImmOrRegister::Register(reg1),
                },
            ];
            let header = T::header();

            // Put the header and rest of file together, then parse it, then lower it to
            // assembly
            let file = [&header, SKIP3_CODE].concat();
            let parse = Parser::parse(Rule::file, &file).unwrap();
            let lowered_file = Parser::lower_file(parse);

            // Check the equality of the two programs
            pretty_assertions::assert_eq!(lowered_file, asm, "arch = {:?}", T::header())
        }
        crate::iter_over_tinyram_configs!(skip3_test)
    }
}
