use crate::{register::RegIdx, word::Word, TinyRamArch};

use core::str::FromStr;
use std::collections::BTreeMap;

use pest::iterators::{Pair, Pairs};
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "tinyram.pest"]
pub struct TinyRamParser;

/// The context necessary to lower the parsed TinyRAM program, i.e., convert the AST to concrete
/// types and real memory offsets.
struct LoweringCtx<'a> {
    /// This is the line number in the file, ignoring whitespace and header
    instr_count: usize,
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
    RegIdx::from_str(pair.as_str()).unwrap()
}

/// Lowers a parsed immediate-or-register into an `ImmOrRegister`
fn lower_imm(pair: Pair<Rule>, ctx: &LoweringCtx) -> RegIdx {
    assert_eq!(pair.as_rule(), Rule::imm);
    let val = pair.into_inner().next().unwrap();

    let x = match val.as_rule() {
        Rule::label => {
            let label_val = ctx.label_addr(val.as_str());
        }
        r => panic!("unexpected rule {:?}", r),
    };

    todo!()
}

/// Takes a TinyRAM header and the rest of the parsed assembly, and produces an offset table, i.e.,
/// a map from label to its word (or byte, in von Neumann) offset.
fn build_label_table<'a>(header: &TinyRamHeader, lines: Pairs<'a, Rule>) -> BTreeMap<&'a str, u64> {
    let mut instr_number = 0;
    let mut table = BTreeMap::new();
    let mut saw_first_line = false;

    let instr_number_step = match header.arch {
        TinyRamArch::Harvard => 164,
        TinyRamArch::VonNeumann => 2 * (header.word_bitlen as u64) / 8,
    };

    for t in lines.flatten() {
        println!("t == {:?}", t);
        match t.as_rule() {
            Rule::label_def => {
                let label = t.into_inner().next().unwrap().as_str();
                table.insert(label, instr_number);
            }
            Rule::line => {
                if saw_first_line {
                    instr_number += instr_number_step;
                } else {
                    saw_first_line = true;
                }
            }
            _ => (),
        }
    }

    table
}

#[cfg(test)]
mod test {
    use super::*;

    use pest::Parser;

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

        let sample_i = "jmp _3lite // hello world";
        TinyRamParser::parse(Rule::line, sample_i).unwrap();

        let sample_full = "_loop: not r12, r0";
        TinyRamParser::parse(Rule::full_instr, sample_full).unwrap();

        let sample_file = "\
        ; TinyRAM V=2.000 M=hv W=32 K=8\n  \
        jmp _3lite // hello world \n\n   \
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
}
