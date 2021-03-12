/* GENERATED FILE */
#include "operations.h"
const char *operation_to_str(enum Operation oper)
{
	switch(oper) {
		case ARM64_ABS: return "abs";
		case ARM64_ADC: return "adc";
		case ARM64_ADCS: return "adcs";
		case ARM64_ADD: return "add";
		case ARM64_ADDG: return "addg";
		case ARM64_ADDHN: return "addhn";
		case ARM64_ADDHN2: return "addhn2";
		case ARM64_ADDP: return "addp";
		case ARM64_ADDPL: return "addpl";
		case ARM64_ADDS: return "adds";
		case ARM64_ADDV: return "addv";
		case ARM64_ADDVL: return "addvl";
		case ARM64_ADR: return "adr";
		case ARM64_ADRP: return "adrp";
		case ARM64_AESD: return "aesd";
		case ARM64_AESE: return "aese";
		case ARM64_AESIMC: return "aesimc";
		case ARM64_AESMC: return "aesmc";
		case ARM64_AND: return "and";
		case ARM64_ANDS: return "ands";
		case ARM64_ANDV: return "andv";
		case ARM64_ASR: return "asr";
		case ARM64_ASRD: return "asrd";
		case ARM64_ASRR: return "asrr";
		case ARM64_ASRV: return "asrv";
		case ARM64_AT: return "at";
		case ARM64_AUTDA: return "autda";
		case ARM64_AUTDB: return "autdb";
		case ARM64_AUTDZA: return "autdza";
		case ARM64_AUTDZB: return "autdzb";
		case ARM64_AUTIA: return "autia";
		case ARM64_AUTIA1716: return "autia1716";
		case ARM64_AUTIASP: return "autiasp";
		case ARM64_AUTIAZ: return "autiaz";
		case ARM64_AUTIB: return "autib";
		case ARM64_AUTIB1716: return "autib1716";
		case ARM64_AUTIBSP: return "autibsp";
		case ARM64_AUTIBZ: return "autibz";
		case ARM64_AUTIZA: return "autiza";
		case ARM64_AUTIZB: return "autizb";
		case ARM64_AXFLAG: return "axflag";
		case ARM64_B: return "b";
		case ARM64_BCAX: return "bcax";
		case ARM64_BFC: return "bfc";
		case ARM64_BFCVT: return "bfcvt";
		case ARM64_BFCVTN: return "bfcvtn";
		case ARM64_BFCVTN2: return "bfcvtn2";
		case ARM64_BFCVTNT: return "bfcvtnt";
		case ARM64_BFDOT: return "bfdot";
		case ARM64_BFI: return "bfi";
		case ARM64_BFM: return "bfm";
		case ARM64_BFMLAL: return "bfmlal";
		case ARM64_BFMLALB: return "bfmlalb";
		case ARM64_BFMLALT: return "bfmlalt";
		case ARM64_BFMMLA: return "bfmmla";
		case ARM64_BFXIL: return "bfxil";
		case ARM64_BIC: return "bic";
		case ARM64_BICS: return "bics";
		case ARM64_BIF: return "bif";
		case ARM64_BIT: return "bit";
		case ARM64_BL: return "bl";
		case ARM64_BLR: return "blr";
		case ARM64_BLRAA: return "blraa";
		case ARM64_BLRAAZ: return "blraaz";
		case ARM64_BLRAB: return "blrab";
		case ARM64_BLRABZ: return "blrabz";
		case ARM64_BR: return "br";
		case ARM64_BRAA: return "braa";
		case ARM64_BRAAZ: return "braaz";
		case ARM64_BRAB: return "brab";
		case ARM64_BRABZ: return "brabz";
		case ARM64_BRK: return "brk";
		case ARM64_BRKA: return "brka";
		case ARM64_BRKAS: return "brkas";
		case ARM64_BRKB: return "brkb";
		case ARM64_BRKBS: return "brkbs";
		case ARM64_BRKN: return "brkn";
		case ARM64_BRKNS: return "brkns";
		case ARM64_BRKPA: return "brkpa";
		case ARM64_BRKPAS: return "brkpas";
		case ARM64_BRKPB: return "brkpb";
		case ARM64_BRKPBS: return "brkpbs";
		case ARM64_BSL: return "bsl";
		case ARM64_BTI: return "bti";
		case ARM64_B_AL: return "b.al";
		case ARM64_B_CC: return "b.lo";
		case ARM64_B_CS: return "b.hs";
		case ARM64_B_EQ: return "b.eq";
		case ARM64_B_GE: return "b.ge";
		case ARM64_B_GT: return "b.gt";
		case ARM64_B_HI: return "b.hi";
		case ARM64_B_LE: return "b.le";
		case ARM64_B_LS: return "b.ls";
		case ARM64_B_LT: return "b.lt";
		case ARM64_B_MI: return "b.mi";
		case ARM64_B_NE: return "b.ne";
		case ARM64_B_NV: return "b.nv";
		case ARM64_B_PL: return "b.pl";
		case ARM64_B_VC: return "b.vc";
		case ARM64_B_VS: return "b.vs";
		case ARM64_CAS: return "cas";
		case ARM64_CASA: return "casa";
		case ARM64_CASAB: return "casab";
		case ARM64_CASAH: return "casah";
		case ARM64_CASAL: return "casal";
		case ARM64_CASALB: return "casalb";
		case ARM64_CASALH: return "casalh";
		case ARM64_CASB: return "casb";
		case ARM64_CASH: return "cash";
		case ARM64_CASL: return "casl";
		case ARM64_CASLB: return "caslb";
		case ARM64_CASLH: return "caslh";
		case ARM64_CASP: return "casp";
		case ARM64_CASPA: return "caspa";
		case ARM64_CASPAL: return "caspal";
		case ARM64_CASPL: return "caspl";
		case ARM64_CBNZ: return "cbnz";
		case ARM64_CBZ: return "cbz";
		case ARM64_CCMN: return "ccmn";
		case ARM64_CCMP: return "ccmp";
		case ARM64_CFINV: return "cfinv";
		case ARM64_CFP: return "cfp";
		case ARM64_CINC: return "cinc";
		case ARM64_CINV: return "cinv";
		case ARM64_CLASTA: return "clasta";
		case ARM64_CLASTB: return "clastb";
		case ARM64_CLREX: return "clrex";
		case ARM64_CLS: return "cls";
		case ARM64_CLZ: return "clz";
		case ARM64_CMEQ: return "cmeq";
		case ARM64_CMGE: return "cmge";
		case ARM64_CMGT: return "cmgt";
		case ARM64_CMHI: return "cmhi";
		case ARM64_CMHS: return "cmhs";
		case ARM64_CMLE: return "cmle";
		case ARM64_CMLT: return "cmlt";
		case ARM64_CMN: return "cmn";
		case ARM64_CMP: return "cmp";
		case ARM64_CMPEQ: return "cmpeq";
		case ARM64_CMPGE: return "cmpge";
		case ARM64_CMPGT: return "cmpgt";
		case ARM64_CMPHI: return "cmphi";
		case ARM64_CMPHS: return "cmphs";
		case ARM64_CMPLE: return "cmple";
		case ARM64_CMPLO: return "cmplo";
		case ARM64_CMPLS: return "cmpls";
		case ARM64_CMPLT: return "cmplt";
		case ARM64_CMPNE: return "cmpne";
		case ARM64_CMPP: return "cmpp";
		case ARM64_CMTST: return "cmtst";
		case ARM64_CNEG: return "cneg";
		case ARM64_CNOT: return "cnot";
		case ARM64_CNT: return "cnt";
		case ARM64_CNTB: return "cntb";
		case ARM64_CNTD: return "cntd";
		case ARM64_CNTH: return "cnth";
		case ARM64_CNTP: return "cntp";
		case ARM64_CNTW: return "cntw";
		case ARM64_COMPACT: return "compact";
		case ARM64_CPP: return "cpp";
		case ARM64_CPY: return "cpy";
		case ARM64_CRC32B: return "crc32b";
		case ARM64_CRC32CB: return "crc32cb";
		case ARM64_CRC32CH: return "crc32ch";
		case ARM64_CRC32CW: return "crc32cw";
		case ARM64_CRC32CX: return "crc32cx";
		case ARM64_CRC32H: return "crc32h";
		case ARM64_CRC32W: return "crc32w";
		case ARM64_CRC32X: return "crc32x";
		case ARM64_CSDB: return "csdb";
		case ARM64_CSEL: return "csel";
		case ARM64_CSET: return "cset";
		case ARM64_CSETM: return "csetm";
		case ARM64_CSINC: return "csinc";
		case ARM64_CSINV: return "csinv";
		case ARM64_CSNEG: return "csneg";
		case ARM64_CTERMEQ: return "ctermeq";
		case ARM64_CTERMNE: return "ctermne";
		case ARM64_DC: return "dc";
		case ARM64_DCPS1: return "dcps1";
		case ARM64_DCPS2: return "dcps2";
		case ARM64_DCPS3: return "dcps3";
		case ARM64_DECB: return "decb";
		case ARM64_DECD: return "decd";
		case ARM64_DECH: return "dech";
		case ARM64_DECP: return "decp";
		case ARM64_DECW: return "decw";
		case ARM64_DGH: return "dgh";
		case ARM64_DMB: return "dmb";
		case ARM64_DRPS: return "drps";
		case ARM64_DSB: return "dsb";
		case ARM64_DUP: return "dup";
		case ARM64_DUPM: return "dupm";
		case ARM64_DVP: return "dvp";
		case ARM64_EON: return "eon";
		case ARM64_EOR: return "eor";
		case ARM64_EOR3: return "eor3";
		case ARM64_EORS: return "eors";
		case ARM64_EORV: return "eorv";
		case ARM64_ERET: return "eret";
		case ARM64_ERETAA: return "eretaa";
		case ARM64_ERETAB: return "eretab";
		case ARM64_ESB: return "esb";
		case ARM64_EXT: return "ext";
		case ARM64_EXTR: return "extr";
		case ARM64_FABD: return "fabd";
		case ARM64_FABS: return "fabs";
		case ARM64_FACGE: return "facge";
		case ARM64_FACGT: return "facgt";
		case ARM64_FACLE: return "facle";
		case ARM64_FACLT: return "faclt";
		case ARM64_FADD: return "fadd";
		case ARM64_FADDA: return "fadda";
		case ARM64_FADDP: return "faddp";
		case ARM64_FADDV: return "faddv";
		case ARM64_FCADD: return "fcadd";
		case ARM64_FCCMP: return "fccmp";
		case ARM64_FCCMPE: return "fccmpe";
		case ARM64_FCMEQ: return "fcmeq";
		case ARM64_FCMGE: return "fcmge";
		case ARM64_FCMGT: return "fcmgt";
		case ARM64_FCMLA: return "fcmla";
		case ARM64_FCMLE: return "fcmle";
		case ARM64_FCMLT: return "fcmlt";
		case ARM64_FCMNE: return "fcmne";
		case ARM64_FCMP: return "fcmp";
		case ARM64_FCMPE: return "fcmpe";
		case ARM64_FCMUO: return "fcmuo";
		case ARM64_FCPY: return "fcpy";
		case ARM64_FCSEL: return "fcsel";
		case ARM64_FCVT: return "fcvt";
		case ARM64_FCVTAS: return "fcvtas";
		case ARM64_FCVTAU: return "fcvtau";
		case ARM64_FCVTL: return "fcvtl";
		case ARM64_FCVTL2: return "fcvtl2";
		case ARM64_FCVTMS: return "fcvtms";
		case ARM64_FCVTMU: return "fcvtmu";
		case ARM64_FCVTN: return "fcvtn";
		case ARM64_FCVTN2: return "fcvtn2";
		case ARM64_FCVTNS: return "fcvtns";
		case ARM64_FCVTNU: return "fcvtnu";
		case ARM64_FCVTPS: return "fcvtps";
		case ARM64_FCVTPU: return "fcvtpu";
		case ARM64_FCVTXN: return "fcvtxn";
		case ARM64_FCVTXN2: return "fcvtxn2";
		case ARM64_FCVTZS: return "fcvtzs";
		case ARM64_FCVTZU: return "fcvtzu";
		case ARM64_FDIV: return "fdiv";
		case ARM64_FDIVR: return "fdivr";
		case ARM64_FDUP: return "fdup";
		case ARM64_FEXPA: return "fexpa";
		case ARM64_FJCVTZS: return "fjcvtzs";
		case ARM64_FMAD: return "fmad";
		case ARM64_FMADD: return "fmadd";
		case ARM64_FMAX: return "fmax";
		case ARM64_FMAXNM: return "fmaxnm";
		case ARM64_FMAXNMP: return "fmaxnmp";
		case ARM64_FMAXNMV: return "fmaxnmv";
		case ARM64_FMAXP: return "fmaxp";
		case ARM64_FMAXV: return "fmaxv";
		case ARM64_FMIN: return "fmin";
		case ARM64_FMINNM: return "fminnm";
		case ARM64_FMINNMP: return "fminnmp";
		case ARM64_FMINNMV: return "fminnmv";
		case ARM64_FMINP: return "fminp";
		case ARM64_FMINV: return "fminv";
		case ARM64_FMLA: return "fmla";
		case ARM64_FMLAL: return "fmlal";
		case ARM64_FMLAL2: return "fmlal2";
		case ARM64_FMLS: return "fmls";
		case ARM64_FMLSL: return "fmlsl";
		case ARM64_FMLSL2: return "fmlsl2";
		case ARM64_FMMLA: return "fmmla";
		case ARM64_FMOV: return "fmov";
		case ARM64_FMSB: return "fmsb";
		case ARM64_FMSUB: return "fmsub";
		case ARM64_FMUL: return "fmul";
		case ARM64_FMULX: return "fmulx";
		case ARM64_FNEG: return "fneg";
		case ARM64_FNMAD: return "fnmad";
		case ARM64_FNMADD: return "fnmadd";
		case ARM64_FNMLA: return "fnmla";
		case ARM64_FNMLS: return "fnmls";
		case ARM64_FNMSB: return "fnmsb";
		case ARM64_FNMSUB: return "fnmsub";
		case ARM64_FNMUL: return "fnmul";
		case ARM64_FRECPE: return "frecpe";
		case ARM64_FRECPS: return "frecps";
		case ARM64_FRECPX: return "frecpx";
		case ARM64_FRINT32X: return "frint32x";
		case ARM64_FRINT32Z: return "frint32z";
		case ARM64_FRINT64X: return "frint64x";
		case ARM64_FRINT64Z: return "frint64z";
		case ARM64_FRINTA: return "frinta";
		case ARM64_FRINTI: return "frinti";
		case ARM64_FRINTM: return "frintm";
		case ARM64_FRINTN: return "frintn";
		case ARM64_FRINTP: return "frintp";
		case ARM64_FRINTX: return "frintx";
		case ARM64_FRINTZ: return "frintz";
		case ARM64_FRSQRTE: return "frsqrte";
		case ARM64_FRSQRTS: return "frsqrts";
		case ARM64_FSCALE: return "fscale";
		case ARM64_FSQRT: return "fsqrt";
		case ARM64_FSUB: return "fsub";
		case ARM64_FSUBR: return "fsubr";
		case ARM64_FTMAD: return "ftmad";
		case ARM64_FTSMUL: return "ftsmul";
		case ARM64_FTSSEL: return "ftssel";
		case ARM64_GMI: return "gmi";
		case ARM64_HINT: return "hint";
		case ARM64_HLT: return "hlt";
		case ARM64_HVC: return "hvc";
		case ARM64_IC: return "ic";
		case ARM64_INCB: return "incb";
		case ARM64_INCD: return "incd";
		case ARM64_INCH: return "inch";
		case ARM64_INCP: return "incp";
		case ARM64_INCW: return "incw";
		case ARM64_INDEX: return "index";
		case ARM64_INS: return "ins";
		case ARM64_INSR: return "insr";
		case ARM64_IRG: return "irg";
		case ARM64_ISB: return "isb";
		case ARM64_LASTA: return "lasta";
		case ARM64_LASTB: return "lastb";
		case ARM64_LD1: return "ld1";
		case ARM64_LD1B: return "ld1b";
		case ARM64_LD1D: return "ld1d";
		case ARM64_LD1H: return "ld1h";
		case ARM64_LD1R: return "ld1r";
		case ARM64_LD1RB: return "ld1rb";
		case ARM64_LD1RD: return "ld1rd";
		case ARM64_LD1RH: return "ld1rh";
		case ARM64_LD1ROB: return "ld1rob";
		case ARM64_LD1ROD: return "ld1rod";
		case ARM64_LD1ROH: return "ld1roh";
		case ARM64_LD1ROW: return "ld1row";
		case ARM64_LD1RQB: return "ld1rqb";
		case ARM64_LD1RQD: return "ld1rqd";
		case ARM64_LD1RQH: return "ld1rqh";
		case ARM64_LD1RQW: return "ld1rqw";
		case ARM64_LD1RSB: return "ld1rsb";
		case ARM64_LD1RSH: return "ld1rsh";
		case ARM64_LD1RSW: return "ld1rsw";
		case ARM64_LD1RW: return "ld1rw";
		case ARM64_LD1SB: return "ld1sb";
		case ARM64_LD1SH: return "ld1sh";
		case ARM64_LD1SW: return "ld1sw";
		case ARM64_LD1W: return "ld1w";
		case ARM64_LD2: return "ld2";
		case ARM64_LD2B: return "ld2b";
		case ARM64_LD2D: return "ld2d";
		case ARM64_LD2H: return "ld2h";
		case ARM64_LD2R: return "ld2r";
		case ARM64_LD2W: return "ld2w";
		case ARM64_LD3: return "ld3";
		case ARM64_LD3B: return "ld3b";
		case ARM64_LD3D: return "ld3d";
		case ARM64_LD3H: return "ld3h";
		case ARM64_LD3R: return "ld3r";
		case ARM64_LD3W: return "ld3w";
		case ARM64_LD4: return "ld4";
		case ARM64_LD4B: return "ld4b";
		case ARM64_LD4D: return "ld4d";
		case ARM64_LD4H: return "ld4h";
		case ARM64_LD4R: return "ld4r";
		case ARM64_LD4W: return "ld4w";
		case ARM64_LD64B: return "ld64b";
		case ARM64_LDADD: return "ldadd";
		case ARM64_LDADDA: return "ldadda";
		case ARM64_LDADDAB: return "ldaddab";
		case ARM64_LDADDAH: return "ldaddah";
		case ARM64_LDADDAL: return "ldaddal";
		case ARM64_LDADDALB: return "ldaddalb";
		case ARM64_LDADDALH: return "ldaddalh";
		case ARM64_LDADDB: return "ldaddb";
		case ARM64_LDADDH: return "ldaddh";
		case ARM64_LDADDL: return "ldaddl";
		case ARM64_LDADDLB: return "ldaddlb";
		case ARM64_LDADDLH: return "ldaddlh";
		case ARM64_LDAPR: return "ldapr";
		case ARM64_LDAPRB: return "ldaprb";
		case ARM64_LDAPRH: return "ldaprh";
		case ARM64_LDAPUR: return "ldapur";
		case ARM64_LDAPURB: return "ldapurb";
		case ARM64_LDAPURH: return "ldapurh";
		case ARM64_LDAPURSB: return "ldapursb";
		case ARM64_LDAPURSH: return "ldapursh";
		case ARM64_LDAPURSW: return "ldapursw";
		case ARM64_LDAR: return "ldar";
		case ARM64_LDARB: return "ldarb";
		case ARM64_LDARH: return "ldarh";
		case ARM64_LDAXP: return "ldaxp";
		case ARM64_LDAXR: return "ldaxr";
		case ARM64_LDAXRB: return "ldaxrb";
		case ARM64_LDAXRH: return "ldaxrh";
		case ARM64_LDCLR: return "ldclr";
		case ARM64_LDCLRA: return "ldclra";
		case ARM64_LDCLRAB: return "ldclrab";
		case ARM64_LDCLRAH: return "ldclrah";
		case ARM64_LDCLRAL: return "ldclral";
		case ARM64_LDCLRALB: return "ldclralb";
		case ARM64_LDCLRALH: return "ldclralh";
		case ARM64_LDCLRB: return "ldclrb";
		case ARM64_LDCLRH: return "ldclrh";
		case ARM64_LDCLRL: return "ldclrl";
		case ARM64_LDCLRLB: return "ldclrlb";
		case ARM64_LDCLRLH: return "ldclrlh";
		case ARM64_LDEOR: return "ldeor";
		case ARM64_LDEORA: return "ldeora";
		case ARM64_LDEORAB: return "ldeorab";
		case ARM64_LDEORAH: return "ldeorah";
		case ARM64_LDEORAL: return "ldeoral";
		case ARM64_LDEORALB: return "ldeoralb";
		case ARM64_LDEORALH: return "ldeoralh";
		case ARM64_LDEORB: return "ldeorb";
		case ARM64_LDEORH: return "ldeorh";
		case ARM64_LDEORL: return "ldeorl";
		case ARM64_LDEORLB: return "ldeorlb";
		case ARM64_LDEORLH: return "ldeorlh";
		case ARM64_LDFF1B: return "ldff1b";
		case ARM64_LDFF1D: return "ldff1d";
		case ARM64_LDFF1H: return "ldff1h";
		case ARM64_LDFF1SB: return "ldff1sb";
		case ARM64_LDFF1SH: return "ldff1sh";
		case ARM64_LDFF1SW: return "ldff1sw";
		case ARM64_LDFF1W: return "ldff1w";
		case ARM64_LDG: return "ldg";
		case ARM64_LDGM: return "ldgm";
		case ARM64_LDLAR: return "ldlar";
		case ARM64_LDLARB: return "ldlarb";
		case ARM64_LDLARH: return "ldlarh";
		case ARM64_LDNF1B: return "ldnf1b";
		case ARM64_LDNF1D: return "ldnf1d";
		case ARM64_LDNF1H: return "ldnf1h";
		case ARM64_LDNF1SB: return "ldnf1sb";
		case ARM64_LDNF1SH: return "ldnf1sh";
		case ARM64_LDNF1SW: return "ldnf1sw";
		case ARM64_LDNF1W: return "ldnf1w";
		case ARM64_LDNP: return "ldnp";
		case ARM64_LDNT1B: return "ldnt1b";
		case ARM64_LDNT1D: return "ldnt1d";
		case ARM64_LDNT1H: return "ldnt1h";
		case ARM64_LDNT1W: return "ldnt1w";
		case ARM64_LDP: return "ldp";
		case ARM64_LDPSW: return "ldpsw";
		case ARM64_LDR: return "ldr";
		case ARM64_LDRAA: return "ldraa";
		case ARM64_LDRAB: return "ldrab";
		case ARM64_LDRB: return "ldrb";
		case ARM64_LDRH: return "ldrh";
		case ARM64_LDRSB: return "ldrsb";
		case ARM64_LDRSH: return "ldrsh";
		case ARM64_LDRSW: return "ldrsw";
		case ARM64_LDSET: return "ldset";
		case ARM64_LDSETA: return "ldseta";
		case ARM64_LDSETAB: return "ldsetab";
		case ARM64_LDSETAH: return "ldsetah";
		case ARM64_LDSETAL: return "ldsetal";
		case ARM64_LDSETALB: return "ldsetalb";
		case ARM64_LDSETALH: return "ldsetalh";
		case ARM64_LDSETB: return "ldsetb";
		case ARM64_LDSETH: return "ldseth";
		case ARM64_LDSETL: return "ldsetl";
		case ARM64_LDSETLB: return "ldsetlb";
		case ARM64_LDSETLH: return "ldsetlh";
		case ARM64_LDSMAX: return "ldsmax";
		case ARM64_LDSMAXA: return "ldsmaxa";
		case ARM64_LDSMAXAB: return "ldsmaxab";
		case ARM64_LDSMAXAH: return "ldsmaxah";
		case ARM64_LDSMAXAL: return "ldsmaxal";
		case ARM64_LDSMAXALB: return "ldsmaxalb";
		case ARM64_LDSMAXALH: return "ldsmaxalh";
		case ARM64_LDSMAXB: return "ldsmaxb";
		case ARM64_LDSMAXH: return "ldsmaxh";
		case ARM64_LDSMAXL: return "ldsmaxl";
		case ARM64_LDSMAXLB: return "ldsmaxlb";
		case ARM64_LDSMAXLH: return "ldsmaxlh";
		case ARM64_LDSMIN: return "ldsmin";
		case ARM64_LDSMINA: return "ldsmina";
		case ARM64_LDSMINAB: return "ldsminab";
		case ARM64_LDSMINAH: return "ldsminah";
		case ARM64_LDSMINAL: return "ldsminal";
		case ARM64_LDSMINALB: return "ldsminalb";
		case ARM64_LDSMINALH: return "ldsminalh";
		case ARM64_LDSMINB: return "ldsminb";
		case ARM64_LDSMINH: return "ldsminh";
		case ARM64_LDSMINL: return "ldsminl";
		case ARM64_LDSMINLB: return "ldsminlb";
		case ARM64_LDSMINLH: return "ldsminlh";
		case ARM64_LDTR: return "ldtr";
		case ARM64_LDTRB: return "ldtrb";
		case ARM64_LDTRH: return "ldtrh";
		case ARM64_LDTRSB: return "ldtrsb";
		case ARM64_LDTRSH: return "ldtrsh";
		case ARM64_LDTRSW: return "ldtrsw";
		case ARM64_LDUMAX: return "ldumax";
		case ARM64_LDUMAXA: return "ldumaxa";
		case ARM64_LDUMAXAB: return "ldumaxab";
		case ARM64_LDUMAXAH: return "ldumaxah";
		case ARM64_LDUMAXAL: return "ldumaxal";
		case ARM64_LDUMAXALB: return "ldumaxalb";
		case ARM64_LDUMAXALH: return "ldumaxalh";
		case ARM64_LDUMAXB: return "ldumaxb";
		case ARM64_LDUMAXH: return "ldumaxh";
		case ARM64_LDUMAXL: return "ldumaxl";
		case ARM64_LDUMAXLB: return "ldumaxlb";
		case ARM64_LDUMAXLH: return "ldumaxlh";
		case ARM64_LDUMIN: return "ldumin";
		case ARM64_LDUMINA: return "ldumina";
		case ARM64_LDUMINAB: return "lduminab";
		case ARM64_LDUMINAH: return "lduminah";
		case ARM64_LDUMINAL: return "lduminal";
		case ARM64_LDUMINALB: return "lduminalb";
		case ARM64_LDUMINALH: return "lduminalh";
		case ARM64_LDUMINB: return "lduminb";
		case ARM64_LDUMINH: return "lduminh";
		case ARM64_LDUMINL: return "lduminl";
		case ARM64_LDUMINLB: return "lduminlb";
		case ARM64_LDUMINLH: return "lduminlh";
		case ARM64_LDUR: return "ldur";
		case ARM64_LDURB: return "ldurb";
		case ARM64_LDURH: return "ldurh";
		case ARM64_LDURSB: return "ldursb";
		case ARM64_LDURSH: return "ldursh";
		case ARM64_LDURSW: return "ldursw";
		case ARM64_LDXP: return "ldxp";
		case ARM64_LDXR: return "ldxr";
		case ARM64_LDXRB: return "ldxrb";
		case ARM64_LDXRH: return "ldxrh";
		case ARM64_LSL: return "lsl";
		case ARM64_LSLR: return "lslr";
		case ARM64_LSLV: return "lslv";
		case ARM64_LSR: return "lsr";
		case ARM64_LSRR: return "lsrr";
		case ARM64_LSRV: return "lsrv";
		case ARM64_MAD: return "mad";
		case ARM64_MADD: return "madd";
		case ARM64_MLA: return "mla";
		case ARM64_MLS: return "mls";
		case ARM64_MNEG: return "mneg";
		case ARM64_MOV: return "mov";
		case ARM64_MOVI: return "movi";
		case ARM64_MOVK: return "movk";
		case ARM64_MOVN: return "movn";
		case ARM64_MOVPRFX: return "movprfx";
		case ARM64_MOVS: return "movs";
		case ARM64_MOVZ: return "movz";
		case ARM64_MRS: return "mrs";
		case ARM64_MSB: return "msb";
		case ARM64_MSR: return "msr";
		case ARM64_MSUB: return "msub";
		case ARM64_MUL: return "mul";
		case ARM64_MVN: return "mvn";
		case ARM64_MVNI: return "mvni";
		case ARM64_NAND: return "nand";
		case ARM64_NANDS: return "nands";
		case ARM64_NEG: return "neg";
		case ARM64_NEGS: return "negs";
		case ARM64_NGC: return "ngc";
		case ARM64_NGCS: return "ngcs";
		case ARM64_NOP: return "nop";
		case ARM64_NOR: return "nor";
		case ARM64_NORS: return "nors";
		case ARM64_NOT: return "not";
		case ARM64_NOTS: return "nots";
		case ARM64_ORN: return "orn";
		case ARM64_ORNS: return "orns";
		case ARM64_ORR: return "orr";
		case ARM64_ORRS: return "orrs";
		case ARM64_ORV: return "orv";
		case ARM64_PACDA: return "pacda";
		case ARM64_PACDB: return "pacdb";
		case ARM64_PACDZA: return "pacdza";
		case ARM64_PACDZB: return "pacdzb";
		case ARM64_PACGA: return "pacga";
		case ARM64_PACIA: return "pacia";
		case ARM64_PACIA1716: return "pacia1716";
		case ARM64_PACIASP: return "paciasp";
		case ARM64_PACIAZ: return "paciaz";
		case ARM64_PACIB: return "pacib";
		case ARM64_PACIB1716: return "pacib1716";
		case ARM64_PACIBSP: return "pacibsp";
		case ARM64_PACIBZ: return "pacibz";
		case ARM64_PACIZA: return "paciza";
		case ARM64_PACIZB: return "pacizb";
		case ARM64_PFALSE: return "pfalse";
		case ARM64_PFIRST: return "pfirst";
		case ARM64_PMUL: return "pmul";
		case ARM64_PMULL: return "pmull";
		case ARM64_PMULL2: return "pmull2";
		case ARM64_PNEXT: return "pnext";
		case ARM64_PRFB: return "prfb";
		case ARM64_PRFD: return "prfd";
		case ARM64_PRFH: return "prfh";
		case ARM64_PRFM: return "prfm";
		case ARM64_PRFUM: return "prfum";
		case ARM64_PRFW: return "prfw";
		case ARM64_PSB: return "psb";
		case ARM64_PSSBB: return "pssbb";
		case ARM64_PTEST: return "ptest";
		case ARM64_PTRUE: return "ptrue";
		case ARM64_PTRUES: return "ptrues";
		case ARM64_PUNPKHI: return "punpkhi";
		case ARM64_PUNPKLO: return "punpklo";
		case ARM64_RADDHN: return "raddhn";
		case ARM64_RADDHN2: return "raddhn2";
		case ARM64_RAX1: return "rax1";
		case ARM64_RBIT: return "rbit";
		case ARM64_RDFFR: return "rdffr";
		case ARM64_RDFFRS: return "rdffrs";
		case ARM64_RDVL: return "rdvl";
		case ARM64_RET: return "ret";
		case ARM64_RETAA: return "retaa";
		case ARM64_RETAB: return "retab";
		case ARM64_REV: return "rev";
		case ARM64_REV16: return "rev16";
		case ARM64_REV32: return "rev32";
		case ARM64_REV64: return "rev64";
		case ARM64_REVB: return "revb";
		case ARM64_REVH: return "revh";
		case ARM64_REVW: return "revw";
		case ARM64_RMIF: return "rmif";
		case ARM64_ROR: return "ror";
		case ARM64_RORV: return "rorv";
		case ARM64_RSHRN: return "rshrn";
		case ARM64_RSHRN2: return "rshrn2";
		case ARM64_RSUBHN: return "rsubhn";
		case ARM64_RSUBHN2: return "rsubhn2";
		case ARM64_SABA: return "saba";
		case ARM64_SABAL: return "sabal";
		case ARM64_SABAL2: return "sabal2";
		case ARM64_SABD: return "sabd";
		case ARM64_SABDL: return "sabdl";
		case ARM64_SABDL2: return "sabdl2";
		case ARM64_SADALP: return "sadalp";
		case ARM64_SADDL: return "saddl";
		case ARM64_SADDL2: return "saddl2";
		case ARM64_SADDLP: return "saddlp";
		case ARM64_SADDLV: return "saddlv";
		case ARM64_SADDV: return "saddv";
		case ARM64_SADDW: return "saddw";
		case ARM64_SADDW2: return "saddw2";
		case ARM64_SB: return "sb";
		case ARM64_SBC: return "sbc";
		case ARM64_SBCS: return "sbcs";
		case ARM64_SBFIZ: return "sbfiz";
		case ARM64_SBFM: return "sbfm";
		case ARM64_SBFX: return "sbfx";
		case ARM64_SCVTF: return "scvtf";
		case ARM64_SDIV: return "sdiv";
		case ARM64_SDIVR: return "sdivr";
		case ARM64_SDOT: return "sdot";
		case ARM64_SEL: return "sel";
		case ARM64_SETF16: return "setf16";
		case ARM64_SETF8: return "setf8";
		case ARM64_SETFFR: return "setffr";
		case ARM64_SEV: return "sev";
		case ARM64_SEVL: return "sevl";
		case ARM64_SHA1C: return "sha1c";
		case ARM64_SHA1H: return "sha1h";
		case ARM64_SHA1M: return "sha1m";
		case ARM64_SHA1P: return "sha1p";
		case ARM64_SHA1SU0: return "sha1su0";
		case ARM64_SHA1SU1: return "sha1su1";
		case ARM64_SHA256H: return "sha256h";
		case ARM64_SHA256H2: return "sha256h2";
		case ARM64_SHA256SU0: return "sha256su0";
		case ARM64_SHA256SU1: return "sha256su1";
		case ARM64_SHA512H: return "sha512h";
		case ARM64_SHA512H2: return "sha512h2";
		case ARM64_SHA512SU0: return "sha512su0";
		case ARM64_SHA512SU1: return "sha512su1";
		case ARM64_SHADD: return "shadd";
		case ARM64_SHL: return "shl";
		case ARM64_SHLL: return "shll";
		case ARM64_SHLL2: return "shll2";
		case ARM64_SHRN: return "shrn";
		case ARM64_SHRN2: return "shrn2";
		case ARM64_SHSUB: return "shsub";
		case ARM64_SLI: return "sli";
		case ARM64_SM3PARTW1: return "sm3partw1";
		case ARM64_SM3PARTW2: return "sm3partw2";
		case ARM64_SM3SS1: return "sm3ss1";
		case ARM64_SM3TT1A: return "sm3tt1a";
		case ARM64_SM3TT1B: return "sm3tt1b";
		case ARM64_SM3TT2A: return "sm3tt2a";
		case ARM64_SM3TT2B: return "sm3tt2b";
		case ARM64_SM4E: return "sm4e";
		case ARM64_SM4EKEY: return "sm4ekey";
		case ARM64_SMADDL: return "smaddl";
		case ARM64_SMAX: return "smax";
		case ARM64_SMAXP: return "smaxp";
		case ARM64_SMAXV: return "smaxv";
		case ARM64_SMC: return "smc";
		case ARM64_SMIN: return "smin";
		case ARM64_SMINP: return "sminp";
		case ARM64_SMINV: return "sminv";
		case ARM64_SMLAL: return "smlal";
		case ARM64_SMLAL2: return "smlal2";
		case ARM64_SMLSL: return "smlsl";
		case ARM64_SMLSL2: return "smlsl2";
		case ARM64_SMMLA: return "smmla";
		case ARM64_SMNEGL: return "smnegl";
		case ARM64_SMOV: return "smov";
		case ARM64_SMSUBL: return "smsubl";
		case ARM64_SMULH: return "smulh";
		case ARM64_SMULL: return "smull";
		case ARM64_SMULL2: return "smull2";
		case ARM64_SPLICE: return "splice";
		case ARM64_SQABS: return "sqabs";
		case ARM64_SQADD: return "sqadd";
		case ARM64_SQDECB: return "sqdecb";
		case ARM64_SQDECD: return "sqdecd";
		case ARM64_SQDECH: return "sqdech";
		case ARM64_SQDECP: return "sqdecp";
		case ARM64_SQDECW: return "sqdecw";
		case ARM64_SQDMLAL: return "sqdmlal";
		case ARM64_SQDMLAL2: return "sqdmlal2";
		case ARM64_SQDMLSL: return "sqdmlsl";
		case ARM64_SQDMLSL2: return "sqdmlsl2";
		case ARM64_SQDMULH: return "sqdmulh";
		case ARM64_SQDMULL: return "sqdmull";
		case ARM64_SQDMULL2: return "sqdmull2";
		case ARM64_SQINCB: return "sqincb";
		case ARM64_SQINCD: return "sqincd";
		case ARM64_SQINCH: return "sqinch";
		case ARM64_SQINCP: return "sqincp";
		case ARM64_SQINCW: return "sqincw";
		case ARM64_SQNEG: return "sqneg";
		case ARM64_SQRDMLAH: return "sqrdmlah";
		case ARM64_SQRDMLSH: return "sqrdmlsh";
		case ARM64_SQRDMULH: return "sqrdmulh";
		case ARM64_SQRSHL: return "sqrshl";
		case ARM64_SQRSHRN: return "sqrshrn";
		case ARM64_SQRSHRN2: return "sqrshrn2";
		case ARM64_SQRSHRUN: return "sqrshrun";
		case ARM64_SQRSHRUN2: return "sqrshrun2";
		case ARM64_SQSHL: return "sqshl";
		case ARM64_SQSHLU: return "sqshlu";
		case ARM64_SQSHRN: return "sqshrn";
		case ARM64_SQSHRN2: return "sqshrn2";
		case ARM64_SQSHRUN: return "sqshrun";
		case ARM64_SQSHRUN2: return "sqshrun2";
		case ARM64_SQSUB: return "sqsub";
		case ARM64_SQXTN: return "sqxtn";
		case ARM64_SQXTN2: return "sqxtn2";
		case ARM64_SQXTUN: return "sqxtun";
		case ARM64_SQXTUN2: return "sqxtun2";
		case ARM64_SRHADD: return "srhadd";
		case ARM64_SRI: return "sri";
		case ARM64_SRSHL: return "srshl";
		case ARM64_SRSHR: return "srshr";
		case ARM64_SRSRA: return "srsra";
		case ARM64_SSBB: return "ssbb";
		case ARM64_SSHL: return "sshl";
		case ARM64_SSHLL: return "sshll";
		case ARM64_SSHLL2: return "sshll2";
		case ARM64_SSHR: return "sshr";
		case ARM64_SSRA: return "ssra";
		case ARM64_SSUBL: return "ssubl";
		case ARM64_SSUBL2: return "ssubl2";
		case ARM64_SSUBW: return "ssubw";
		case ARM64_SSUBW2: return "ssubw2";
		case ARM64_ST1: return "st1";
		case ARM64_ST1B: return "st1b";
		case ARM64_ST1D: return "st1d";
		case ARM64_ST1H: return "st1h";
		case ARM64_ST1W: return "st1w";
		case ARM64_ST2: return "st2";
		case ARM64_ST2B: return "st2b";
		case ARM64_ST2D: return "st2d";
		case ARM64_ST2G: return "st2g";
		case ARM64_ST2H: return "st2h";
		case ARM64_ST2W: return "st2w";
		case ARM64_ST3: return "st3";
		case ARM64_ST3B: return "st3b";
		case ARM64_ST3D: return "st3d";
		case ARM64_ST3H: return "st3h";
		case ARM64_ST3W: return "st3w";
		case ARM64_ST4: return "st4";
		case ARM64_ST4B: return "st4b";
		case ARM64_ST4D: return "st4d";
		case ARM64_ST4H: return "st4h";
		case ARM64_ST4W: return "st4w";
		case ARM64_ST64B: return "st64b";
		case ARM64_ST64BV: return "st64bv";
		case ARM64_ST64BV0: return "st64bv0";
		case ARM64_STADD: return "stadd";
		case ARM64_STADDB: return "staddb";
		case ARM64_STADDH: return "staddh";
		case ARM64_STADDL: return "staddl";
		case ARM64_STADDLB: return "staddlb";
		case ARM64_STADDLH: return "staddlh";
		case ARM64_STCLR: return "stclr";
		case ARM64_STCLRB: return "stclrb";
		case ARM64_STCLRH: return "stclrh";
		case ARM64_STCLRL: return "stclrl";
		case ARM64_STCLRLB: return "stclrlb";
		case ARM64_STCLRLH: return "stclrlh";
		case ARM64_STEOR: return "steor";
		case ARM64_STEORB: return "steorb";
		case ARM64_STEORH: return "steorh";
		case ARM64_STEORL: return "steorl";
		case ARM64_STEORLB: return "steorlb";
		case ARM64_STEORLH: return "steorlh";
		case ARM64_STG: return "stg";
		case ARM64_STGM: return "stgm";
		case ARM64_STGP: return "stgp";
		case ARM64_STLLR: return "stllr";
		case ARM64_STLLRB: return "stllrb";
		case ARM64_STLLRH: return "stllrh";
		case ARM64_STLR: return "stlr";
		case ARM64_STLRB: return "stlrb";
		case ARM64_STLRH: return "stlrh";
		case ARM64_STLUR: return "stlur";
		case ARM64_STLURB: return "stlurb";
		case ARM64_STLURH: return "stlurh";
		case ARM64_STLXP: return "stlxp";
		case ARM64_STLXR: return "stlxr";
		case ARM64_STLXRB: return "stlxrb";
		case ARM64_STLXRH: return "stlxrh";
		case ARM64_STNP: return "stnp";
		case ARM64_STNT1B: return "stnt1b";
		case ARM64_STNT1D: return "stnt1d";
		case ARM64_STNT1H: return "stnt1h";
		case ARM64_STNT1W: return "stnt1w";
		case ARM64_STP: return "stp";
		case ARM64_STR: return "str";
		case ARM64_STRB: return "strb";
		case ARM64_STRH: return "strh";
		case ARM64_STSET: return "stset";
		case ARM64_STSETB: return "stsetb";
		case ARM64_STSETH: return "stseth";
		case ARM64_STSETL: return "stsetl";
		case ARM64_STSETLB: return "stsetlb";
		case ARM64_STSETLH: return "stsetlh";
		case ARM64_STSMAX: return "stsmax";
		case ARM64_STSMAXB: return "stsmaxb";
		case ARM64_STSMAXH: return "stsmaxh";
		case ARM64_STSMAXL: return "stsmaxl";
		case ARM64_STSMAXLB: return "stsmaxlb";
		case ARM64_STSMAXLH: return "stsmaxlh";
		case ARM64_STSMIN: return "stsmin";
		case ARM64_STSMINB: return "stsminb";
		case ARM64_STSMINH: return "stsminh";
		case ARM64_STSMINL: return "stsminl";
		case ARM64_STSMINLB: return "stsminlb";
		case ARM64_STSMINLH: return "stsminlh";
		case ARM64_STTR: return "sttr";
		case ARM64_STTRB: return "sttrb";
		case ARM64_STTRH: return "sttrh";
		case ARM64_STUMAX: return "stumax";
		case ARM64_STUMAXB: return "stumaxb";
		case ARM64_STUMAXH: return "stumaxh";
		case ARM64_STUMAXL: return "stumaxl";
		case ARM64_STUMAXLB: return "stumaxlb";
		case ARM64_STUMAXLH: return "stumaxlh";
		case ARM64_STUMIN: return "stumin";
		case ARM64_STUMINB: return "stuminb";
		case ARM64_STUMINH: return "stuminh";
		case ARM64_STUMINL: return "stuminl";
		case ARM64_STUMINLB: return "stuminlb";
		case ARM64_STUMINLH: return "stuminlh";
		case ARM64_STUR: return "stur";
		case ARM64_STURB: return "sturb";
		case ARM64_STURH: return "sturh";
		case ARM64_STXP: return "stxp";
		case ARM64_STXR: return "stxr";
		case ARM64_STXRB: return "stxrb";
		case ARM64_STXRH: return "stxrh";
		case ARM64_STZ2G: return "stz2g";
		case ARM64_STZG: return "stzg";
		case ARM64_STZGM: return "stzgm";
		case ARM64_SUB: return "sub";
		case ARM64_SUBG: return "subg";
		case ARM64_SUBHN: return "subhn";
		case ARM64_SUBHN2: return "subhn2";
		case ARM64_SUBP: return "subp";
		case ARM64_SUBPS: return "subps";
		case ARM64_SUBR: return "subr";
		case ARM64_SUBS: return "subs";
		case ARM64_SUDOT: return "sudot";
		case ARM64_SUNPKHI: return "sunpkhi";
		case ARM64_SUNPKLO: return "sunpklo";
		case ARM64_SUQADD: return "suqadd";
		case ARM64_SVC: return "svc";
		case ARM64_SWP: return "swp";
		case ARM64_SWPA: return "swpa";
		case ARM64_SWPAB: return "swpab";
		case ARM64_SWPAH: return "swpah";
		case ARM64_SWPAL: return "swpal";
		case ARM64_SWPALB: return "swpalb";
		case ARM64_SWPALH: return "swpalh";
		case ARM64_SWPB: return "swpb";
		case ARM64_SWPH: return "swph";
		case ARM64_SWPL: return "swpl";
		case ARM64_SWPLB: return "swplb";
		case ARM64_SWPLH: return "swplh";
		case ARM64_SXTB: return "sxtb";
		case ARM64_SXTH: return "sxth";
		case ARM64_SXTL: return "sxtl";
		case ARM64_SXTL2: return "sxtl2";
		case ARM64_SXTW: return "sxtw";
		case ARM64_SYS: return "sys";
		case ARM64_SYSL: return "sysl";
		case ARM64_TBL: return "tbl";
		case ARM64_TBNZ: return "tbnz";
		case ARM64_TBX: return "tbx";
		case ARM64_TBZ: return "tbz";
		case ARM64_TLBI: return "tlbi";
		case ARM64_TRN1: return "trn1";
		case ARM64_TRN2: return "trn2";
		case ARM64_TSB: return "tsb";
		case ARM64_TST: return "tst";
		case ARM64_UABA: return "uaba";
		case ARM64_UABAL: return "uabal";
		case ARM64_UABAL2: return "uabal2";
		case ARM64_UABD: return "uabd";
		case ARM64_UABDL: return "uabdl";
		case ARM64_UABDL2: return "uabdl2";
		case ARM64_UADALP: return "uadalp";
		case ARM64_UADDL: return "uaddl";
		case ARM64_UADDL2: return "uaddl2";
		case ARM64_UADDLP: return "uaddlp";
		case ARM64_UADDLV: return "uaddlv";
		case ARM64_UADDV: return "uaddv";
		case ARM64_UADDW: return "uaddw";
		case ARM64_UADDW2: return "uaddw2";
		case ARM64_UBFIZ: return "ubfiz";
		case ARM64_UBFM: return "ubfm";
		case ARM64_UBFX: return "ubfx";
		case ARM64_UCVTF: return "ucvtf";
		case ARM64_UDF: return "udf";
		case ARM64_UDIV: return "udiv";
		case ARM64_UDIVR: return "udivr";
		case ARM64_UDOT: return "udot";
		case ARM64_UHADD: return "uhadd";
		case ARM64_UHSUB: return "uhsub";
		case ARM64_UMADDL: return "umaddl";
		case ARM64_UMAX: return "umax";
		case ARM64_UMAXP: return "umaxp";
		case ARM64_UMAXV: return "umaxv";
		case ARM64_UMIN: return "umin";
		case ARM64_UMINP: return "uminp";
		case ARM64_UMINV: return "uminv";
		case ARM64_UMLAL: return "umlal";
		case ARM64_UMLAL2: return "umlal2";
		case ARM64_UMLSL: return "umlsl";
		case ARM64_UMLSL2: return "umlsl2";
		case ARM64_UMMLA: return "ummla";
		case ARM64_UMNEGL: return "umnegl";
		case ARM64_UMOV: return "umov";
		case ARM64_UMSUBL: return "umsubl";
		case ARM64_UMULH: return "umulh";
		case ARM64_UMULL: return "umull";
		case ARM64_UMULL2: return "umull2";
		case ARM64_UQADD: return "uqadd";
		case ARM64_UQDECB: return "uqdecb";
		case ARM64_UQDECD: return "uqdecd";
		case ARM64_UQDECH: return "uqdech";
		case ARM64_UQDECP: return "uqdecp";
		case ARM64_UQDECW: return "uqdecw";
		case ARM64_UQINCB: return "uqincb";
		case ARM64_UQINCD: return "uqincd";
		case ARM64_UQINCH: return "uqinch";
		case ARM64_UQINCP: return "uqincp";
		case ARM64_UQINCW: return "uqincw";
		case ARM64_UQRSHL: return "uqrshl";
		case ARM64_UQRSHRN: return "uqrshrn";
		case ARM64_UQRSHRN2: return "uqrshrn2";
		case ARM64_UQSHL: return "uqshl";
		case ARM64_UQSHRN: return "uqshrn";
		case ARM64_UQSHRN2: return "uqshrn2";
		case ARM64_UQSUB: return "uqsub";
		case ARM64_UQXTN: return "uqxtn";
		case ARM64_UQXTN2: return "uqxtn2";
		case ARM64_URECPE: return "urecpe";
		case ARM64_URHADD: return "urhadd";
		case ARM64_URSHL: return "urshl";
		case ARM64_URSHR: return "urshr";
		case ARM64_URSQRTE: return "ursqrte";
		case ARM64_URSRA: return "ursra";
		case ARM64_USDOT: return "usdot";
		case ARM64_USHL: return "ushl";
		case ARM64_USHLL: return "ushll";
		case ARM64_USHLL2: return "ushll2";
		case ARM64_USHR: return "ushr";
		case ARM64_USMMLA: return "usmmla";
		case ARM64_USQADD: return "usqadd";
		case ARM64_USRA: return "usra";
		case ARM64_USUBL: return "usubl";
		case ARM64_USUBL2: return "usubl2";
		case ARM64_USUBW: return "usubw";
		case ARM64_USUBW2: return "usubw2";
		case ARM64_UUNPKHI: return "uunpkhi";
		case ARM64_UUNPKLO: return "uunpklo";
		case ARM64_UXTB: return "uxtb";
		case ARM64_UXTH: return "uxth";
		case ARM64_UXTL: return "uxtl";
		case ARM64_UXTL2: return "uxtl2";
		case ARM64_UXTW: return "uxtw";
		case ARM64_UZP1: return "uzp1";
		case ARM64_UZP2: return "uzp2";
		case ARM64_WFE: return "wfe";
		case ARM64_WFET: return "wfet";
		case ARM64_WFI: return "wfi";
		case ARM64_WFIT: return "wfit";
		case ARM64_WHILELE: return "whilele";
		case ARM64_WHILELO: return "whilelo";
		case ARM64_WHILELS: return "whilels";
		case ARM64_WHILELT: return "whilelt";
		case ARM64_WRFFR: return "wrffr";
		case ARM64_XAFLAG: return "xaflag";
		case ARM64_XAR: return "xar";
		case ARM64_XPACD: return "xpacd";
		case ARM64_XPACI: return "xpaci";
		case ARM64_XPACLRI: return "xpaclri";
		case ARM64_XTN: return "xtn";
		case ARM64_XTN2: return "xtn2";
		case ARM64_YIELD: return "yield";
		case ARM64_ZIP1: return "zip1";
		case ARM64_ZIP2: return "zip2";
		case ARM64_ERROR:
		default:
			return "error";
	}
}
