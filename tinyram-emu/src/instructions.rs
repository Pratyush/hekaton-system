use crate::word::Word;
use crate::register::{Register, RegisterOrImm};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inst<W: Word> {
    // Arithmetic instructions
    And {
        in1: Register, 
        in2: RegisterOrImm<W>, 
        out: Register
    },
    Or {
        in1: Register, 
        in2: RegisterOrImm<W>, 
        out: Register
    },
    Xor {
        in1: Register, 
        in2: RegisterOrImm<W>, 
        out: Register
    },
    Not {
        in1: RegisterOrImm<W>, 
        out: Register
    },
    Add {
        in1: Register, 
        in2: RegisterOrImm<W>, 
        out: Register
    },
    Sub {
        in1: Register, 
        in2: RegisterOrImm<W>, 
        out: Register
    },
    MulL {
        in1: Register, 
        in2: RegisterOrImm<W>, 
        out: Register
    },
    UMulH {
        in1: Register, 
        in2: RegisterOrImm<W>, 
        out: Register
    },
    UMulL {
        in1: Register, 
        in2: RegisterOrImm<W>, 
        out: Register
    },
    UDiv {
        in1: Register, 
        in2: RegisterOrImm<W>, 
        out: Register
    },
    UMod {
        in1: Register, 
        in2: RegisterOrImm<W>, 
        out: Register
    },
    Shl {
        in1: Register, 
        in2: RegisterOrImm<W>, 
        out: Register
    },
    Shr {
        in1: Register, 
        in2: RegisterOrImm<W>, 
        out: Register
    },
    // Compare instructions
    CmpE {
        in1: Register, 
        in2: RegisterOrImm<W>,
    },
    CmpA {
        in1: Register, 
        in2: RegisterOrImm<W>,
    },
    CmpAE {
        in1: Register, 
        in2: RegisterOrImm<W>,
    },
    CmpG {
        in1: Register, 
        in2: RegisterOrImm<W>,
    },
    CmpGE {
        in1: Register, 
        in2: RegisterOrImm<W>,
    },
    Mov {
        in1: RegisterOrImm<W>,
        out: Register,
    },
    CMov {
        in1: RegisterOrImm<W>,
        out: Register,
    },
    Jmp {
        in1: RegisterOrImm<W>,
    },
    CJmp {
        in1: RegisterOrImm<W>,
    },
    CNJmp {
        in1: RegisterOrImm<W>,
    },
    StoreB {
        in1: Register,
        out: RegisterOrImm<W>,
    },
    LoadB {
        in1: W,
        out: Register
    },
    StoreW {
        in1: Register,
        out: W,
    },
    LoadW {
        in1: W,
        out: Register,
    },
    Read {
        in1: W,
        out: Register,
    },
    Answer {
        in1: W,
    },
}

// const 

// var instructionToOperation = map[instruction]func(tRam *tinyRAM, r1, r2, r3 uint64) {
// 	AND:    andOperation,
// 	OR:     orOperation,
// 	XOR:    xorOperation,
// 	NOT:    notOperation,
// 	ADD:    addOperation,
// 	SUB:    subOperation,
// 	MULL:   mullOperation,
// 	UMULH:  umulhOperation,
// 	SMULH:  smulhOperation,
// 	UDIV:   udivOperation,
// 	UMOD:   umodOperation,
// 	SHL:    shlOperation,
// 	SHR:    shrOperation,
// 	CMPE:   cmpeOperation,
// 	CMPA:   cmpaOperation,
// 	CMPAE:  cmpaeOperation,
// 	CMPG:   cmpgOperation,
// 	CMPGE:  cmpgeOperation,
// 	MOV:    movOperation,
// 	CMOV:   cmovOperation,
// 	JMP:    jmpOperation,
// 	CJMP:   cjmpOperation,
// 	CNJMP:  cnjmpOperation,
// 	STORE:  storeOperation,
// 	LOAD:   loadOperation,
// 	READ:   readOperation,
// 	ANSWER: answerOperation,
// }

// type instructionToken struct {
// 	inst instruction
// 	r1   uint64
// 	r2   uint64
// 	r3   uint64
// }

// //
// // Bit operations
// //

// func andOperation(tRAM *tinyRAM, r1, r2, r3 uint64) {
// 	tRAM.Register[r1] = tRAM.Register[r2] & r3	
// 	if tRAM.Register[r1] == 0 {
// 		tRAM.ConditionFlag = true
// 	} else {
// 		tRAM.ConditionFlag = false
// 	}
// 	tRAM.Pc++
// }

// func orOperation(tRAM *tinyRAM, r1, r2, r3 uint64) {
// 	tRAM.Register[r1] = tRAM.Register[r2] | r3
// 	if tRAM.Register[r1] == 0 {
// 		tRAM.ConditionFlag = true
// 	} else {
// 		tRAM.ConditionFlag = false
// 	}
// 	tRAM.Pc++
// }

// func xorOperation(tRAM *tinyRAM, r1, r2, r3 uint64) {
// 	tRAM.Register[r1] = tRAM.Register[r2] ^ r3
// 	if tRAM.Register[r1] == 0 {
// 		tRAM.ConditionFlag = true
// 	} else {
// 		tRAM.ConditionFlag = false
// 	}
// 	tRAM.Pc++
// }

// func notOperation(tRAM *tinyRAM, r1, r2, r3 uint64) {
// 	tRAM.Register[r1] = r2 ^ math.MaxUint64
// 	if tRAM.Register[r1] == 0 {
// 		tRAM.ConditionFlag = true
// 	} else {
// 		tRAM.ConditionFlag = false
// 	}
// 	tRAM.Pc++
// }

// //
// // Integer operations
// //

// func addOperation(tRAM *tinyRAM, r1, r2, r3 uint64) {
// 	tRAM.Register[r1] = tRAM.Register[r2] + r3
// 	if (tRAM.Register[r1] >> 63) & 1 == 1 {
// 		tRAM.ConditionFlag = true
// 	} else {
// 		tRAM.ConditionFlag = false
// 	}
// 	tRAM.Pc++
// }

// func subOperation(tRAM *tinyRAM, r1, r2, r3 uint64) {	
// 	tRAM.Register[r1] = uint64(math.Abs(float64(tRAM.Register[r2] - r3)))
// 	if tRAM.Register[r2] <= r3 {		
// 		tRAM.ConditionFlag = true
// 	} else {		
// 		tRAM.ConditionFlag = false
// 	}
// 	tRAM.Pc++
// }

// func mullOperation(tRAM *tinyRAM, r1, r2, r3 uint64) {
// 	tRAM.Register[r1] = tRAM.Register[r2] * r3
// 	if math.IsInf(float64(tRAM.Register[r1]), 1) {
// 		tRAM.ConditionFlag = true
// 	} else {
// 		tRAM.ConditionFlag = false
// 	}
// 	tRAM.Pc++
// }

// func umulhOperation(tRAM *tinyRAM, r1, r2, r3 uint64) {
// 	tRAM.Register[r1] = tRAM.Register[r2] * r3
// 	if math.IsInf(float64(tRAM.Register[r1]), 1) {
// 		tRAM.ConditionFlag = true
// 	} else {
// 		tRAM.ConditionFlag = false
// 	}
// 	tRAM.Pc++
// }

// func smulhOperation(tRAM *tinyRAM, r1, r2, r3 uint64) {
// 	tRAM.Register[r1] = tRAM.Register[r2] * r3
// 	if math.IsInf(float64(tRAM.Register[r1]), 1) {
// 		tRAM.ConditionFlag = true
// 	} else {
// 		tRAM.ConditionFlag = false
// 	}
// 	tRAM.Pc++
// }

// func udivOperation(tRAM *tinyRAM, r1, r2, r3 uint64) {
// 	if r3 == 0 {
// 		tRAM.ConditionFlag = true
// 	} else {
// 		tRAM.Register[r1] = tRAM.Register[r2] / r3
// 		tRAM.ConditionFlag = false
// 	}
// 	tRAM.Pc++
// }

// func umodOperation(tRAM *tinyRAM, r1, r2, r3 uint64) {
// 	if r3 == 0 {
// 		tRAM.ConditionFlag = true
// 	} else {
// 		tRAM.Register[r1] = tRAM.Register[r2] % r3
// 		tRAM.ConditionFlag = false
// 	}
// 	tRAM.Pc++
// }

// //
// // Shift operations
// //

// func shlOperation(tRAM *tinyRAM, r1, r2, r3 uint64) {
// 	tRAM.Register[r1] = tRAM.Register[r2] << r3
// 	if (tRAM.Register[r1] >> 63) & 1 == 1 {
// 		tRAM.ConditionFlag = true
// 	} else {
// 		tRAM.ConditionFlag = false
// 	}
// 	tRAM.Pc++
// }

// func shrOperation(tRAM *tinyRAM, r1, r2, r3 uint64) {
// 	tRAM.Register[r1] = tRAM.Register[r2] >> r3
// 	if tRAM.Register[r1] & 1 == 1 {
// 		tRAM.ConditionFlag = true
// 	} else {
// 		tRAM.ConditionFlag = false
// 	}
// 	tRAM.Pc++
// }

// //
// // Compare operations
// //

// func cmpeOperation(tRAM *tinyRAM, r1, r2, r3 uint64) {
// 	if r1 == r2 {
// 		tRAM.ConditionFlag = true
// 	} else {
// 		tRAM.ConditionFlag = false
// 	}
// 	tRAM.Pc++
// }

// func cmpaOperation(tRAM *tinyRAM, r1, r2, r3 uint64) {
// 	if r1 > r2 {
// 		tRAM.ConditionFlag = true
// 	} else {
// 		tRAM.ConditionFlag = false
// 	}
// 	tRAM.Pc++
// }

// func cmpaeOperation(tRAM *tinyRAM, r1, r2, r3 uint64) {
// 	if r1 >= r2 {
// 		tRAM.ConditionFlag = true
// 	} else {
// 		tRAM.ConditionFlag = false
// 	}
// 	tRAM.Pc++
// }

// func cmpgOperation(tRAM *tinyRAM, r1, r2, r3 uint64) {
// 	if r1 > r2 {
// 		tRAM.ConditionFlag = true
// 	} else {
// 		tRAM.ConditionFlag = false
// 	}
// 	tRAM.Pc++
// }

// func cmpgeOperation(tRAM *tinyRAM, r1, r2, r3 uint64) {
// 	if r1 >= r2 {
// 		tRAM.ConditionFlag = true
// 	} else {
// 		tRAM.ConditionFlag = false
// 	}
// 	tRAM.Pc++
// }

// //
// // Move operations
// //

// func movOperation(tRAM *tinyRAM, r1, r2, r3 uint64) {
// 	tRAM.Register[r1] = r2
// 	tRAM.Pc++
// }

// func cmovOperation(tRAM *tinyRAM, r1, r2, r3 uint64) {
// 	if tRAM.ConditionFlag {
// 		tRAM.Register[r1] = r2
// 	}
// 	tRAM.Pc++
// }

// //
// // Jump operations
// //

// func jmpOperation(tRAM *tinyRAM, r1, r2, r3 uint64) {
// 	tRAM.Pc = r1
// }

// func cjmpOperation(tRAM *tinyRAM, r1, r2, r3 uint64) {
// 	if tRAM.ConditionFlag {
// 		tRAM.Pc = r1
// 	} else {
// 		tRAM.Pc++
// 	}

// }

// func cnjmpOperation(tRAM *tinyRAM, r1, r2, r3 uint64) {
// 	if !tRAM.ConditionFlag {
// 		tRAM.Pc = r1
// 	} else {
// 		tRAM.Pc++
// 	}
// }

// //
// // Memory operations
// //

// func storeOperation(tRAM *tinyRAM, r1, r2, r3 uint64) {
// 	tRAM.Memory[r1] = r2
// 	tRAM.Pc++
// }

// func loadOperation(tRAM *tinyRAM, r1, r2, r3 uint64) {
// 	tRAM.Register[r1] = tRAM.Memory[r2]
// 	tRAM.Pc++
// }

// //
// // Input operations
// //

// func readOperation(tRAM *tinyRAM, r1, r2, r3 uint64) {
// 	if r2 == 0 {
// 		if tRAM.PrimaryInputCount <= uint64(len(tRAM.PrimaryInput)) - 1 {
// 			tRAM.Register[r1] = tRAM.PrimaryInput[tRAM.PrimaryInputCount]
// 			tRAM.PrimaryInputCount++
// 			tRAM.ConditionFlag = false
// 		} else {
// 			tRAM.Register[r1] = 0
// 			tRAM.ConditionFlag = true
// 		}				
// 	} else if r2 == 1 {
// 		if tRAM.AuxiliaryInputCount <= uint64(len(tRAM.AuxiliaryInput)) - 1 {
// 			tRAM.Register[r1] = tRAM.AuxiliaryInput[tRAM.AuxiliaryInputCount]
// 			tRAM.AuxiliaryInputCount++
// 			tRAM.ConditionFlag = false
// 		} else {
// 			tRAM.Register[r1] = 0
// 			tRAM.ConditionFlag = true
// 		}
// 	} else {
// 		tRAM.Register[r1] = 0
// 		tRAM.ConditionFlag = true
// 	}
// 	tRAM.Pc++
// }

// //
// // Answer operations
// //

// // The program accepted if the return value is 0
// func answerOperation(tRAM *tinyRAM, r1, r2, r3 uint64) {
// 	if tRAM.PrimaryInput[tRAM.PrimaryInputCount] == tRAM.Register[r1] {
// 		tRAM.Accept = true
// 	} 
// }