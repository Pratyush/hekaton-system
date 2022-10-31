use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "tinyram.pest"]
pub struct TinyRamParser;

#[cfg(test)]
mod test {
    use super::*;

    use pest::Parser;

    #[test]
    fn test_header() {
        let sample_header = "; TinyRAM V=2.000 M=vn W=32 K=8";
        let d = TinyRamParser::parse(Rule::header, sample_header).unwrap();
        println!("d == {:?}", d);
    }

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
        ; TinyRAM V=2.000 M=vn W=32 K=8\n  \
        _loop:   not r12, r0\n\
        jmp _3lite // hello world \n\n   \
        cmpe r12, 1337\n\
        xor r1, r3, _loop\
        ";
        let sample_parsing = TinyRamParser::parse(Rule::file, sample_file).unwrap();
        println!("program parse == {:?}", sample_parsing);
    }
}
