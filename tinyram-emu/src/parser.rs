use crate::{
    instructions::{Instr, Opcode},
    register::{ImmOrRegister, RegIdx},
    word::Word,
    TinyRamArch,
};

use core::str::FromStr;
use std::collections::BTreeMap;

use pest::{
    iterators::{Pair, Pairs},
    Parser,
};
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "tinyram.pest"]
pub struct TinyRamParser<const NUM_REGS: usize, const WORD_BITLENGTH: usize>;

/// The context necessary to lower the parsed TinyRAM program, i.e., convert the AST to concrete
/// types and real memory offsets.
struct LoweringCtx<'a> {
    // This is the line number in the file, ignoring whitespace and header
    // instr_count: usize,
    /// This contains arch information we need in lowering
    header: TinyRamHeader,
    /// A map of all the labels we've seen so far and their corresponding word idx
    label_addrs: BTreeMap<&'a str, u64>,
}

impl<'a> LoweringCtx<'a> {
    fn label_addr(&self, label: &str) -> u64 {
        match self.label_addrs.get(label) {
            Some(&w) => w,
            None => panic!("unknown label {label}"),
        }
    }
}

#[derive(Debug)]
struct TinyRamHeader {
    arch: TinyRamArch,
    word_bitlen: u32,
    num_regs: u32,
}

/// Converts a parse `Pair` to a map from rule -> str
fn parsed_dict(pair: Pair<Rule>) -> BTreeMap<Rule, &str> {
    pair.into_inner()
        .map(|p| (p.as_rule(), p.as_str()))
        .collect()
}

/// Lowers a parsed header into a `TinyRamHeader`
fn lower_header(pair: Pair<Rule>) -> TinyRamHeader {
    assert_eq!(pair.as_rule(), Rule::header);
    let dict = parsed_dict(pair);

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
fn lower_reg(pair: Pair<Rule>) -> RegIdx {
    assert_eq!(pair.as_rule(), Rule::reg);
    // The first character of a register is 'r'
    let reg_idx_str = &pair.as_str()[1..];
    RegIdx::from_str(reg_idx_str).unwrap()
}

/// Lowers a parsed immediate into a word
fn lower_imm<W: Word>(ctx: &LoweringCtx, pair: Pair<Rule>) -> W {
    assert_eq!(pair.as_rule(), Rule::imm);
    let val = pair.into_inner().next().unwrap();
    let val_str = val.as_str().trim();

    match val.as_rule() {
        Rule::label => {
            let label_val = ctx.label_addr(val_str);
            W::try_from(label_val)
                .map_err(|_| format!("label {val_str} is out of bounds"))
                .unwrap()
        },
        Rule::dec_num => {
            let dec_val = u64::from_str(val_str)
                .map_err(|_| format!("invalid number {val_str}"))
                .unwrap();
            W::try_from(dec_val)
                .map_err(|_| format!("decimal {val_str} is out of bounds"))
                .unwrap()
        },
        r => panic!("unexpected rule {:?}", r),
    }
}

/// Lowers a parsed immediate-or-register into an `ImmOrRegister`
fn lower_imm_or_reg<W: Word>(ctx: &LoweringCtx, pair: Pair<Rule>) -> ImmOrRegister<W> {
    assert_eq!(pair.as_rule(), Rule::imm_or_reg);
    let val = pair.into_inner().next().unwrap();

    match val.as_rule() {
        Rule::imm => {
            let word = lower_imm(ctx, val);
            ImmOrRegister::Imm(word)
        },
        Rule::reg => {
            let reg_idx = lower_reg(val);
            ImmOrRegister::Register(reg_idx)
        },
        r => panic!("unexpected rule {:?}", r),
    }
}

/// Lowers a register-register-immorreg instruction
fn lower_rri_instr<W: Word>(ctx: &LoweringCtx, pair: Pair<Rule>) -> Instr<W> {
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
    let out = lower_reg(out_pair);

    // Parse reg2
    let in1_pair = it.next().unwrap();
    let in1 = lower_reg(in1_pair);

    // Parse imm_or_reg
    let in2_pair = it.next().unwrap();
    let in2 = lower_imm_or_reg(ctx, in2_pair);

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
fn lower_ri_instr<W: Word>(ctx: &LoweringCtx, pair: Pair<Rule>) -> Instr<W> {
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
    let arg1 = lower_reg(reg1_pair);

    // Parse imm_or_reg. This is either in2 or in1, depending on the instruction
    let imm_or_reg_pair = it.next().unwrap();
    let arg2 = lower_imm_or_reg(ctx, imm_or_reg_pair);

    match op {
        Opcode::CmpE => Instr::CmpE { in1: arg1, in2: arg2, },
        Opcode::CmpA => Instr::CmpA { in1: arg1, in2: arg2, },
        Opcode::CmpAe => Instr::CmpAE { in1: arg1, in2: arg2, },
        Opcode::CmpG => Instr::CmpG { in1: arg1, in2: arg2, },
        Opcode::CmpGe => Instr::CmpGE { in1: arg1, in2: arg2, },
        Opcode::Mov => Instr::Mov { in1: arg2, out: arg1, },
        Opcode::CMov => Instr::CMov { in1: arg2, out: arg1 },
        Opcode::LoadB => Instr::LoadB { out: arg1, in1: arg2, },
        Opcode::LoadW => Instr::LoadW { out: arg1, in1: arg2, },
        Opcode::Read => Instr::Read { out: arg1, in1: arg2, },
        _ => panic!("Unexpected op {op:?}"),
    }
}

/// Lowers an immorreg-register instruction
fn lower_ir_instr<W: Word>(ctx: &LoweringCtx, pair: Pair<Rule>) -> Instr<W> {
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
    let imm_or_reg = lower_imm_or_reg(ctx, imm_or_reg_pair);

    // Parse reg1. This is in1
    let reg1_pair = it.next().unwrap();
    let reg1 = lower_reg(reg1_pair);

    match op {
        Opcode::StoreW => Instr::StoreW { in1: reg1, out: imm_or_reg, },
        Opcode::StoreB => Instr::StoreB { in1: reg1, out: imm_or_reg, },
        _ => panic!("Unexpected op {op:?}"),
    }
}

/// Lowers an immorreg instruction
fn lower_i_instr<W: Word>(ctx: &LoweringCtx, pair: Pair<Rule>) -> Instr<W> {
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
    let in1 = lower_imm_or_reg(ctx, in1_pair);

    match op {
        Opcode::Jmp => Instr::Jmp { in1 },
        Opcode::CJmp => Instr::CJmp { in1 },
        Opcode::CnJmp => Instr::CNJmp { in1 },
        Opcode::Answer => Instr::Answer { in1 },
        _ => panic!("Unexpected op {:?}", op),
    }
}

/// Lowers any instruction
fn lower_any_instr<W: Word>(ctx: &LoweringCtx, pair: Pair<Rule>) -> Instr<W> {
    assert_eq!(pair.as_rule(), Rule::any_instr);
    let val = pair.into_inner().next().unwrap();

    match val.as_rule() {
        Rule::i_instr => lower_i_instr(ctx, val),
        Rule::ir_instr => lower_ir_instr(ctx, val),
        Rule::ri_instr => lower_ri_instr(ctx, val),
        Rule::rri_instr => lower_rri_instr(ctx, val),
        r => panic!("unexpected rule {r:?}"),
    }
}

/// Lowers a full instruction, including label defs
fn lower_full_instr<W: Word>(ctx: &LoweringCtx, pair: Pair<Rule>) -> Instr<W> {
    assert_eq!(pair.as_rule(), Rule::full_instr);

    // Skip all the label defs. We already processed them.
    let val = pair
        .into_inner()
        .skip_while(|p| p.as_rule() == Rule::label_def)
        .next()
        .unwrap();

    // Now parse the instruction
    lower_any_instr(ctx, val)
}

/// Lowers a code line, which is an optional full instr plus an optional comment
fn lower_line<W: Word>(ctx: &LoweringCtx, pair: Pair<Rule>) -> Option<Instr<W>> {
    assert_eq!(pair.as_rule(), Rule::line);

    // The first line item may be a full instruction. If so, lower it. Otherwise do nothing.
    pair.into_inner().find_map(|item| {
        if item.as_rule() == Rule::full_instr {
            Some(lower_full_instr(ctx, item))
        } else {
            None
        }
    })
}

/// Takes a TinyRAM header and the rest of the parsed assembly, and produces an offset table, i.e.,
/// a map from label to its word (or byte, in von Neumann) offset.
fn build_label_table<'a>(header: &TinyRamHeader, lines: Pairs<'a, Rule>) -> BTreeMap<&'a str, u64> {
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

/// Lowers a whole file
fn lower_file<W: Word>(mut pairs: Pairs<Rule>) -> Vec<Instr<W>> {
    let mut it = pairs.next().unwrap().into_inner();

    // Parse the header and make the lowering context
    let header = lower_header(it.next().unwrap());
    let rest_of_file = it.clone();
    let label_addrs = build_label_table(&header, rest_of_file);
    let ctx = LoweringCtx {
        header,
        label_addrs,
    };

    // Now parse all the instructions
    it.flatten()
        .filter_map(|item| {
            if item.as_rule() == Rule::line {
                lower_line(&ctx, item)
            } else {
                None
            }
        })
        .collect()
}

pub fn assemble<W: Word>(tinyram_program: &str) -> Vec<Instr<W>> {
    let parse = TinyRamParser::parse(Rule::file, &tinyram_program).unwrap();
    lower_file(parse)
}

#[cfg(test)]
mod test {
    use super::*;

    use pest::Parser;

    type W = u64;

    /// Try to parse a header
    #[test]
    fn test_header() {
        let sample_header = "; TinyRAM V=2.000 M=vn W=32 K=8";
        let d = TinyRamParser::parse(Rule::header, sample_header).unwrap();
        println!("d == {:?}", d);
    }

    /// Parse a few individual lines, and then a whole (nonsense) program
    #[test]
    fn test_instrs() {
        let sample_rri = "xor r1, r3, _loop";
        TinyRamParser::parse(Rule::rri_instr, sample_rri).unwrap();

        let sample_ri = "cmpe r12, 1337";
        TinyRamParser::parse(Rule::ri_instr, sample_ri).unwrap();

        let sample_i = "jmp _3lite ; hello world";
        TinyRamParser::parse(Rule::line, sample_i).unwrap();

        let sample_full = "_loop: not r12, r0";
        TinyRamParser::parse(Rule::full_instr, sample_full).unwrap();

        let sample_file = "\
        ; TinyRAM V=2.000 M=hv W=32 K=8\n  \
        jmp _3lite ; hello world \n\n   \
        _loop:   not r12, r0\n\
        cmpe r12, 1337\n\
        _acc:xor r1, r3, _loop\
        ";
        let sample_parsing = TinyRamParser::parse(Rule::file, sample_file).unwrap();
        println!("program parse == {:#?}", sample_parsing);

        let mut p = sample_parsing;
        let mut file = p.next().unwrap().into_inner();
        let header_parse = file.next().unwrap();
        let header = lower_header(header_parse);
        println!("header parse == {:#?}", header,);

        let rest_of_file = file;
        println!("p == {:?}", p);
        let label_table = build_label_table(&header, rest_of_file);
        println!("label table == {:#?}", label_table);
    }

    fn imm(val: u64) -> ImmOrRegister<W> {
        ImmOrRegister::new(val, true).unwrap()
    }

    // Headers for the two architectures
    pub(crate) const HV_HEADER: &str = "; TinyRAM V=2.000 M=hv W=32 K=8\n";
    pub(crate) const VN_HEADER: &str = "; TinyRAM V=2.000 M=vn W=32 K=8\n";

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
        // The correct _loop, _acc, and _end jump labels for Harvard and von Neumann, respectively
        let hv_labels = (imm(0x00), imm(0x07), imm(0x0a));
        let vn_labels = (imm(0x00), imm(0x38), imm(0x50));

        // The register indices
        let reg0 = RegIdx(0);
        let reg1 = RegIdx(1);
        let reg2 = RegIdx(2);

        // These are the expected result of assembling the skip3 program, under Harvard and von
        // Neumann arches respectively.
        let expected_assembly: Vec<Vec<Instr<W>>> = [hv_labels, vn_labels]
            .into_iter()
            .map(|(label_loop, label_acc, label_end)| {
                vec![
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
                ]
            })
            .collect();

        // Now make sure that the computed assembly equals the expected assembly
        for (asm, header) in expected_assembly
            .into_iter()
            .zip([HV_HEADER, VN_HEADER].iter())
        {
            // Put the header and rest of file together, then parse it, then lower it to
            // assembly
            let file = [header, SKIP3_CODE].concat();
            let parse = TinyRamParser::parse(Rule::file, &file).unwrap();
            let lowered_file = lower_file::<W>(parse);

            // Check the equality of the two programs
            assert_eq!(lowered_file, asm)
        }
    }
}
