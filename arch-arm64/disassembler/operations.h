/* GENERATED FILE */
#pragma once

enum Operation {
ARM64_ERROR=0,
ARM64_ABS=1,
ARM64_ADC=2,
ARM64_ADCLB=3,
ARM64_ADCLT=4,
ARM64_ADCS=5,
ARM64_ADD=6,
ARM64_ADDG=7,
ARM64_ADDHN=8,
ARM64_ADDHN2=9,
ARM64_ADDHNB=10,
ARM64_ADDHNT=11,
ARM64_ADDP=12,
ARM64_ADDPL=13,
ARM64_ADDS=14,
ARM64_ADDV=15,
ARM64_ADDVL=16,
ARM64_ADR=17,
ARM64_ADRP=18,
ARM64_AESD=19,
ARM64_AESE=20,
ARM64_AESIMC=21,
ARM64_AESMC=22,
ARM64_AND=23,
ARM64_ANDS=24,
ARM64_ANDV=25,
ARM64_ASR=26,
ARM64_ASRD=27,
ARM64_ASRR=28,
ARM64_ASRV=29,
ARM64_AT=30,
ARM64_AUTDA=31,
ARM64_AUTDB=32,
ARM64_AUTDZA=33,
ARM64_AUTDZB=34,
ARM64_AUTIA=35,
ARM64_AUTIA1716=36,
ARM64_AUTIASP=37,
ARM64_AUTIAZ=38,
ARM64_AUTIB=39,
ARM64_AUTIB1716=40,
ARM64_AUTIBSP=41,
ARM64_AUTIBZ=42,
ARM64_AUTIZA=43,
ARM64_AUTIZB=44,
ARM64_AXFLAG=45,
ARM64_B=46,
ARM64_BCAX=47,
ARM64_BDEP=48,
ARM64_BEXT=49,
ARM64_BFC=50,
ARM64_BFCVT=51,
ARM64_BFCVTN=52,
ARM64_BFCVTN2=53,
ARM64_BFCVTNT=54,
ARM64_BFDOT=55,
ARM64_BFI=56,
ARM64_BFM=57,
ARM64_BFMLAL=58,
ARM64_BFMLALB=59,
ARM64_BFMLALT=60,
ARM64_BFMMLA=61,
ARM64_BFXIL=62,
ARM64_BGRP=63,
ARM64_BIC=64,
ARM64_BICS=65,
ARM64_BIF=66,
ARM64_BIT=67,
ARM64_BL=68,
ARM64_BLR=69,
ARM64_BLRAA=70,
ARM64_BLRAAZ=71,
ARM64_BLRAB=72,
ARM64_BLRABZ=73,
ARM64_BR=74,
ARM64_BRAA=75,
ARM64_BRAAZ=76,
ARM64_BRAB=77,
ARM64_BRABZ=78,
ARM64_BRK=79,
ARM64_BRKA=80,
ARM64_BRKAS=81,
ARM64_BRKB=82,
ARM64_BRKBS=83,
ARM64_BRKN=84,
ARM64_BRKNS=85,
ARM64_BRKPA=86,
ARM64_BRKPAS=87,
ARM64_BRKPB=88,
ARM64_BRKPBS=89,
ARM64_BSL=90,
ARM64_BSL1N=91,
ARM64_BSL2N=92,
ARM64_BTI=93,
ARM64_B_AL=94,
ARM64_B_CC=95,
ARM64_B_CS=96,
ARM64_B_EQ=97,
ARM64_B_GE=98,
ARM64_B_GT=99,
ARM64_B_HI=100,
ARM64_B_LE=101,
ARM64_B_LS=102,
ARM64_B_LT=103,
ARM64_B_MI=104,
ARM64_B_NE=105,
ARM64_B_NV=106,
ARM64_B_PL=107,
ARM64_B_VC=108,
ARM64_B_VS=109,
ARM64_CADD=110,
ARM64_CAS=111,
ARM64_CASA=112,
ARM64_CASAB=113,
ARM64_CASAH=114,
ARM64_CASAL=115,
ARM64_CASALB=116,
ARM64_CASALH=117,
ARM64_CASB=118,
ARM64_CASH=119,
ARM64_CASL=120,
ARM64_CASLB=121,
ARM64_CASLH=122,
ARM64_CASP=123,
ARM64_CASPA=124,
ARM64_CASPAL=125,
ARM64_CASPL=126,
ARM64_CBNZ=127,
ARM64_CBZ=128,
ARM64_CCMN=129,
ARM64_CCMP=130,
ARM64_CDOT=131,
ARM64_CFINV=132,
ARM64_CFP=133,
ARM64_CINC=134,
ARM64_CINV=135,
ARM64_CLASTA=136,
ARM64_CLASTB=137,
ARM64_CLREX=138,
ARM64_CLS=139,
ARM64_CLZ=140,
ARM64_CMEQ=141,
ARM64_CMGE=142,
ARM64_CMGT=143,
ARM64_CMHI=144,
ARM64_CMHS=145,
ARM64_CMLA=146,
ARM64_CMLE=147,
ARM64_CMLT=148,
ARM64_CMN=149,
ARM64_CMP=150,
ARM64_CMPEQ=151,
ARM64_CMPGE=152,
ARM64_CMPGT=153,
ARM64_CMPHI=154,
ARM64_CMPHS=155,
ARM64_CMPLE=156,
ARM64_CMPLO=157,
ARM64_CMPLS=158,
ARM64_CMPLT=159,
ARM64_CMPNE=160,
ARM64_CMPP=161,
ARM64_CMTST=162,
ARM64_CNEG=163,
ARM64_CNOT=164,
ARM64_CNT=165,
ARM64_CNTB=166,
ARM64_CNTD=167,
ARM64_CNTH=168,
ARM64_CNTP=169,
ARM64_CNTW=170,
ARM64_COMPACT=171,
ARM64_CPP=172,
ARM64_CPY=173,
ARM64_CRC32B=174,
ARM64_CRC32CB=175,
ARM64_CRC32CH=176,
ARM64_CRC32CW=177,
ARM64_CRC32CX=178,
ARM64_CRC32H=179,
ARM64_CRC32W=180,
ARM64_CRC32X=181,
ARM64_CSDB=182,
ARM64_CSEL=183,
ARM64_CSET=184,
ARM64_CSETM=185,
ARM64_CSINC=186,
ARM64_CSINV=187,
ARM64_CSNEG=188,
ARM64_CTERMEQ=189,
ARM64_CTERMNE=190,
ARM64_DC=191,
ARM64_DCPS1=192,
ARM64_DCPS2=193,
ARM64_DCPS3=194,
ARM64_DECB=195,
ARM64_DECD=196,
ARM64_DECH=197,
ARM64_DECP=198,
ARM64_DECW=199,
ARM64_DGH=200,
ARM64_DMB=201,
ARM64_DRPS=202,
ARM64_DSB=203,
ARM64_DUP=204,
ARM64_DUPM=205,
ARM64_DVP=206,
ARM64_EON=207,
ARM64_EOR=208,
ARM64_EOR3=209,
ARM64_EORBT=210,
ARM64_EORS=211,
ARM64_EORTB=212,
ARM64_EORV=213,
ARM64_ERET=214,
ARM64_ERETAA=215,
ARM64_ERETAB=216,
ARM64_ESB=217,
ARM64_EXT=218,
ARM64_EXTR=219,
ARM64_FABD=220,
ARM64_FABS=221,
ARM64_FACGE=222,
ARM64_FACGT=223,
ARM64_FACLE=224,
ARM64_FACLT=225,
ARM64_FADD=226,
ARM64_FADDA=227,
ARM64_FADDP=228,
ARM64_FADDV=229,
ARM64_FCADD=230,
ARM64_FCCMP=231,
ARM64_FCCMPE=232,
ARM64_FCMEQ=233,
ARM64_FCMGE=234,
ARM64_FCMGT=235,
ARM64_FCMLA=236,
ARM64_FCMLE=237,
ARM64_FCMLT=238,
ARM64_FCMNE=239,
ARM64_FCMP=240,
ARM64_FCMPE=241,
ARM64_FCMUO=242,
ARM64_FCPY=243,
ARM64_FCSEL=244,
ARM64_FCVT=245,
ARM64_FCVTAS=246,
ARM64_FCVTAU=247,
ARM64_FCVTL=248,
ARM64_FCVTL2=249,
ARM64_FCVTLT=250,
ARM64_FCVTMS=251,
ARM64_FCVTMU=252,
ARM64_FCVTN=253,
ARM64_FCVTN2=254,
ARM64_FCVTNS=255,
ARM64_FCVTNT=256,
ARM64_FCVTNU=257,
ARM64_FCVTPS=258,
ARM64_FCVTPU=259,
ARM64_FCVTX=260,
ARM64_FCVTXN=261,
ARM64_FCVTXN2=262,
ARM64_FCVTXNT=263,
ARM64_FCVTZS=264,
ARM64_FCVTZU=265,
ARM64_FDIV=266,
ARM64_FDIVR=267,
ARM64_FDUP=268,
ARM64_FEXPA=269,
ARM64_FJCVTZS=270,
ARM64_FLOGB=271,
ARM64_FMAD=272,
ARM64_FMADD=273,
ARM64_FMAX=274,
ARM64_FMAXNM=275,
ARM64_FMAXNMP=276,
ARM64_FMAXNMV=277,
ARM64_FMAXP=278,
ARM64_FMAXV=279,
ARM64_FMIN=280,
ARM64_FMINNM=281,
ARM64_FMINNMP=282,
ARM64_FMINNMV=283,
ARM64_FMINP=284,
ARM64_FMINV=285,
ARM64_FMLA=286,
ARM64_FMLAL=287,
ARM64_FMLAL2=288,
ARM64_FMLALB=289,
ARM64_FMLALT=290,
ARM64_FMLS=291,
ARM64_FMLSL=292,
ARM64_FMLSL2=293,
ARM64_FMLSLB=294,
ARM64_FMLSLT=295,
ARM64_FMMLA=296,
ARM64_FMOV=297,
ARM64_FMSB=298,
ARM64_FMSUB=299,
ARM64_FMUL=300,
ARM64_FMULX=301,
ARM64_FNEG=302,
ARM64_FNMAD=303,
ARM64_FNMADD=304,
ARM64_FNMLA=305,
ARM64_FNMLS=306,
ARM64_FNMSB=307,
ARM64_FNMSUB=308,
ARM64_FNMUL=309,
ARM64_FRECPE=310,
ARM64_FRECPS=311,
ARM64_FRECPX=312,
ARM64_FRINT32X=313,
ARM64_FRINT32Z=314,
ARM64_FRINT64X=315,
ARM64_FRINT64Z=316,
ARM64_FRINTA=317,
ARM64_FRINTI=318,
ARM64_FRINTM=319,
ARM64_FRINTN=320,
ARM64_FRINTP=321,
ARM64_FRINTX=322,
ARM64_FRINTZ=323,
ARM64_FRSQRTE=324,
ARM64_FRSQRTS=325,
ARM64_FSCALE=326,
ARM64_FSQRT=327,
ARM64_FSUB=328,
ARM64_FSUBR=329,
ARM64_FTMAD=330,
ARM64_FTSMUL=331,
ARM64_FTSSEL=332,
ARM64_GMI=333,
ARM64_HINT=334,
ARM64_HISTCNT=335,
ARM64_HISTSEG=336,
ARM64_HLT=337,
ARM64_HVC=338,
ARM64_IC=339,
ARM64_INCB=340,
ARM64_INCD=341,
ARM64_INCH=342,
ARM64_INCP=343,
ARM64_INCW=344,
ARM64_INDEX=345,
ARM64_INS=346,
ARM64_INSR=347,
ARM64_IRG=348,
ARM64_ISB=349,
ARM64_LASTA=350,
ARM64_LASTB=351,
ARM64_LD1=352,
ARM64_LD1B=353,
ARM64_LD1D=354,
ARM64_LD1H=355,
ARM64_LD1R=356,
ARM64_LD1RB=357,
ARM64_LD1RD=358,
ARM64_LD1RH=359,
ARM64_LD1ROB=360,
ARM64_LD1ROD=361,
ARM64_LD1ROH=362,
ARM64_LD1ROW=363,
ARM64_LD1RQB=364,
ARM64_LD1RQD=365,
ARM64_LD1RQH=366,
ARM64_LD1RQW=367,
ARM64_LD1RSB=368,
ARM64_LD1RSH=369,
ARM64_LD1RSW=370,
ARM64_LD1RW=371,
ARM64_LD1SB=372,
ARM64_LD1SH=373,
ARM64_LD1SW=374,
ARM64_LD1W=375,
ARM64_LD2=376,
ARM64_LD2B=377,
ARM64_LD2D=378,
ARM64_LD2H=379,
ARM64_LD2R=380,
ARM64_LD2W=381,
ARM64_LD3=382,
ARM64_LD3B=383,
ARM64_LD3D=384,
ARM64_LD3H=385,
ARM64_LD3R=386,
ARM64_LD3W=387,
ARM64_LD4=388,
ARM64_LD4B=389,
ARM64_LD4D=390,
ARM64_LD4H=391,
ARM64_LD4R=392,
ARM64_LD4W=393,
ARM64_LD64B=394,
ARM64_LDADD=395,
ARM64_LDADDA=396,
ARM64_LDADDAB=397,
ARM64_LDADDAH=398,
ARM64_LDADDAL=399,
ARM64_LDADDALB=400,
ARM64_LDADDALH=401,
ARM64_LDADDB=402,
ARM64_LDADDH=403,
ARM64_LDADDL=404,
ARM64_LDADDLB=405,
ARM64_LDADDLH=406,
ARM64_LDAPR=407,
ARM64_LDAPRB=408,
ARM64_LDAPRH=409,
ARM64_LDAPUR=410,
ARM64_LDAPURB=411,
ARM64_LDAPURH=412,
ARM64_LDAPURSB=413,
ARM64_LDAPURSH=414,
ARM64_LDAPURSW=415,
ARM64_LDAR=416,
ARM64_LDARB=417,
ARM64_LDARH=418,
ARM64_LDAXP=419,
ARM64_LDAXR=420,
ARM64_LDAXRB=421,
ARM64_LDAXRH=422,
ARM64_LDCLR=423,
ARM64_LDCLRA=424,
ARM64_LDCLRAB=425,
ARM64_LDCLRAH=426,
ARM64_LDCLRAL=427,
ARM64_LDCLRALB=428,
ARM64_LDCLRALH=429,
ARM64_LDCLRB=430,
ARM64_LDCLRH=431,
ARM64_LDCLRL=432,
ARM64_LDCLRLB=433,
ARM64_LDCLRLH=434,
ARM64_LDEOR=435,
ARM64_LDEORA=436,
ARM64_LDEORAB=437,
ARM64_LDEORAH=438,
ARM64_LDEORAL=439,
ARM64_LDEORALB=440,
ARM64_LDEORALH=441,
ARM64_LDEORB=442,
ARM64_LDEORH=443,
ARM64_LDEORL=444,
ARM64_LDEORLB=445,
ARM64_LDEORLH=446,
ARM64_LDFF1B=447,
ARM64_LDFF1D=448,
ARM64_LDFF1H=449,
ARM64_LDFF1SB=450,
ARM64_LDFF1SH=451,
ARM64_LDFF1SW=452,
ARM64_LDFF1W=453,
ARM64_LDG=454,
ARM64_LDGM=455,
ARM64_LDLAR=456,
ARM64_LDLARB=457,
ARM64_LDLARH=458,
ARM64_LDNF1B=459,
ARM64_LDNF1D=460,
ARM64_LDNF1H=461,
ARM64_LDNF1SB=462,
ARM64_LDNF1SH=463,
ARM64_LDNF1SW=464,
ARM64_LDNF1W=465,
ARM64_LDNP=466,
ARM64_LDNT1B=467,
ARM64_LDNT1D=468,
ARM64_LDNT1H=469,
ARM64_LDNT1SB=470,
ARM64_LDNT1SH=471,
ARM64_LDNT1SW=472,
ARM64_LDNT1W=473,
ARM64_LDP=474,
ARM64_LDPSW=475,
ARM64_LDR=476,
ARM64_LDRAA=477,
ARM64_LDRAB=478,
ARM64_LDRB=479,
ARM64_LDRH=480,
ARM64_LDRSB=481,
ARM64_LDRSH=482,
ARM64_LDRSW=483,
ARM64_LDSET=484,
ARM64_LDSETA=485,
ARM64_LDSETAB=486,
ARM64_LDSETAH=487,
ARM64_LDSETAL=488,
ARM64_LDSETALB=489,
ARM64_LDSETALH=490,
ARM64_LDSETB=491,
ARM64_LDSETH=492,
ARM64_LDSETL=493,
ARM64_LDSETLB=494,
ARM64_LDSETLH=495,
ARM64_LDSMAX=496,
ARM64_LDSMAXA=497,
ARM64_LDSMAXAB=498,
ARM64_LDSMAXAH=499,
ARM64_LDSMAXAL=500,
ARM64_LDSMAXALB=501,
ARM64_LDSMAXALH=502,
ARM64_LDSMAXB=503,
ARM64_LDSMAXH=504,
ARM64_LDSMAXL=505,
ARM64_LDSMAXLB=506,
ARM64_LDSMAXLH=507,
ARM64_LDSMIN=508,
ARM64_LDSMINA=509,
ARM64_LDSMINAB=510,
ARM64_LDSMINAH=511,
ARM64_LDSMINAL=512,
ARM64_LDSMINALB=513,
ARM64_LDSMINALH=514,
ARM64_LDSMINB=515,
ARM64_LDSMINH=516,
ARM64_LDSMINL=517,
ARM64_LDSMINLB=518,
ARM64_LDSMINLH=519,
ARM64_LDTR=520,
ARM64_LDTRB=521,
ARM64_LDTRH=522,
ARM64_LDTRSB=523,
ARM64_LDTRSH=524,
ARM64_LDTRSW=525,
ARM64_LDUMAX=526,
ARM64_LDUMAXA=527,
ARM64_LDUMAXAB=528,
ARM64_LDUMAXAH=529,
ARM64_LDUMAXAL=530,
ARM64_LDUMAXALB=531,
ARM64_LDUMAXALH=532,
ARM64_LDUMAXB=533,
ARM64_LDUMAXH=534,
ARM64_LDUMAXL=535,
ARM64_LDUMAXLB=536,
ARM64_LDUMAXLH=537,
ARM64_LDUMIN=538,
ARM64_LDUMINA=539,
ARM64_LDUMINAB=540,
ARM64_LDUMINAH=541,
ARM64_LDUMINAL=542,
ARM64_LDUMINALB=543,
ARM64_LDUMINALH=544,
ARM64_LDUMINB=545,
ARM64_LDUMINH=546,
ARM64_LDUMINL=547,
ARM64_LDUMINLB=548,
ARM64_LDUMINLH=549,
ARM64_LDUR=550,
ARM64_LDURB=551,
ARM64_LDURH=552,
ARM64_LDURSB=553,
ARM64_LDURSH=554,
ARM64_LDURSW=555,
ARM64_LDXP=556,
ARM64_LDXR=557,
ARM64_LDXRB=558,
ARM64_LDXRH=559,
ARM64_LSL=560,
ARM64_LSLR=561,
ARM64_LSLV=562,
ARM64_LSR=563,
ARM64_LSRR=564,
ARM64_LSRV=565,
ARM64_MAD=566,
ARM64_MADD=567,
ARM64_MATCH=568,
ARM64_MLA=569,
ARM64_MLS=570,
ARM64_MNEG=571,
ARM64_MOV=572,
ARM64_MOVI=573,
ARM64_MOVK=574,
ARM64_MOVN=575,
ARM64_MOVPRFX=576,
ARM64_MOVS=577,
ARM64_MOVZ=578,
ARM64_MRS=579,
ARM64_MSB=580,
ARM64_MSR=581,
ARM64_MSUB=582,
ARM64_MUL=583,
ARM64_MVN=584,
ARM64_MVNI=585,
ARM64_NAND=586,
ARM64_NANDS=587,
ARM64_NBSL=588,
ARM64_NEG=589,
ARM64_NEGS=590,
ARM64_NGC=591,
ARM64_NGCS=592,
ARM64_NMATCH=593,
ARM64_NOP=594,
ARM64_NOR=595,
ARM64_NORS=596,
ARM64_NOT=597,
ARM64_NOTS=598,
ARM64_ORN=599,
ARM64_ORNS=600,
ARM64_ORR=601,
ARM64_ORRS=602,
ARM64_ORV=603,
ARM64_PACDA=604,
ARM64_PACDB=605,
ARM64_PACDZA=606,
ARM64_PACDZB=607,
ARM64_PACGA=608,
ARM64_PACIA=609,
ARM64_PACIA1716=610,
ARM64_PACIASP=611,
ARM64_PACIAZ=612,
ARM64_PACIB=613,
ARM64_PACIB1716=614,
ARM64_PACIBSP=615,
ARM64_PACIBZ=616,
ARM64_PACIZA=617,
ARM64_PACIZB=618,
ARM64_PFALSE=619,
ARM64_PFIRST=620,
ARM64_PMUL=621,
ARM64_PMULL=622,
ARM64_PMULL2=623,
ARM64_PMULLB=624,
ARM64_PMULLT=625,
ARM64_PNEXT=626,
ARM64_PRFB=627,
ARM64_PRFD=628,
ARM64_PRFH=629,
ARM64_PRFM=630,
ARM64_PRFUM=631,
ARM64_PRFW=632,
ARM64_PSB=633,
ARM64_PSSBB=634,
ARM64_PTEST=635,
ARM64_PTRUE=636,
ARM64_PTRUES=637,
ARM64_PUNPKHI=638,
ARM64_PUNPKLO=639,
ARM64_RADDHN=640,
ARM64_RADDHN2=641,
ARM64_RADDHNB=642,
ARM64_RADDHNT=643,
ARM64_RAX1=644,
ARM64_RBIT=645,
ARM64_RDFFR=646,
ARM64_RDFFRS=647,
ARM64_RDVL=648,
ARM64_RET=649,
ARM64_RETAA=650,
ARM64_RETAB=651,
ARM64_REV=652,
ARM64_REV16=653,
ARM64_REV32=654,
ARM64_REV64=655,
ARM64_REVB=656,
ARM64_REVH=657,
ARM64_REVW=658,
ARM64_RMIF=659,
ARM64_ROR=660,
ARM64_RORV=661,
ARM64_RSHRN=662,
ARM64_RSHRN2=663,
ARM64_RSHRNB=664,
ARM64_RSHRNT=665,
ARM64_RSUBHN=666,
ARM64_RSUBHN2=667,
ARM64_RSUBHNB=668,
ARM64_RSUBHNT=669,
ARM64_SABA=670,
ARM64_SABAL=671,
ARM64_SABAL2=672,
ARM64_SABALB=673,
ARM64_SABALT=674,
ARM64_SABD=675,
ARM64_SABDL=676,
ARM64_SABDL2=677,
ARM64_SABDLB=678,
ARM64_SABDLT=679,
ARM64_SADALP=680,
ARM64_SADDL=681,
ARM64_SADDL2=682,
ARM64_SADDLB=683,
ARM64_SADDLBT=684,
ARM64_SADDLP=685,
ARM64_SADDLT=686,
ARM64_SADDLV=687,
ARM64_SADDV=688,
ARM64_SADDW=689,
ARM64_SADDW2=690,
ARM64_SADDWB=691,
ARM64_SADDWT=692,
ARM64_SB=693,
ARM64_SBC=694,
ARM64_SBCLB=695,
ARM64_SBCLT=696,
ARM64_SBCS=697,
ARM64_SBFIZ=698,
ARM64_SBFM=699,
ARM64_SBFX=700,
ARM64_SCVTF=701,
ARM64_SDIV=702,
ARM64_SDIVR=703,
ARM64_SDOT=704,
ARM64_SEL=705,
ARM64_SETF16=706,
ARM64_SETF8=707,
ARM64_SETFFR=708,
ARM64_SEV=709,
ARM64_SEVL=710,
ARM64_SHA1C=711,
ARM64_SHA1H=712,
ARM64_SHA1M=713,
ARM64_SHA1P=714,
ARM64_SHA1SU0=715,
ARM64_SHA1SU1=716,
ARM64_SHA256H=717,
ARM64_SHA256H2=718,
ARM64_SHA256SU0=719,
ARM64_SHA256SU1=720,
ARM64_SHA512H=721,
ARM64_SHA512H2=722,
ARM64_SHA512SU0=723,
ARM64_SHA512SU1=724,
ARM64_SHADD=725,
ARM64_SHL=726,
ARM64_SHLL=727,
ARM64_SHLL2=728,
ARM64_SHRN=729,
ARM64_SHRN2=730,
ARM64_SHRNB=731,
ARM64_SHRNT=732,
ARM64_SHSUB=733,
ARM64_SHSUBR=734,
ARM64_SLI=735,
ARM64_SM3PARTW1=736,
ARM64_SM3PARTW2=737,
ARM64_SM3SS1=738,
ARM64_SM3TT1A=739,
ARM64_SM3TT1B=740,
ARM64_SM3TT2A=741,
ARM64_SM3TT2B=742,
ARM64_SM4E=743,
ARM64_SM4EKEY=744,
ARM64_SMADDL=745,
ARM64_SMAX=746,
ARM64_SMAXP=747,
ARM64_SMAXV=748,
ARM64_SMC=749,
ARM64_SMIN=750,
ARM64_SMINP=751,
ARM64_SMINV=752,
ARM64_SMLAL=753,
ARM64_SMLAL2=754,
ARM64_SMLALB=755,
ARM64_SMLALT=756,
ARM64_SMLSL=757,
ARM64_SMLSL2=758,
ARM64_SMLSLB=759,
ARM64_SMLSLT=760,
ARM64_SMMLA=761,
ARM64_SMNEGL=762,
ARM64_SMOV=763,
ARM64_SMSUBL=764,
ARM64_SMULH=765,
ARM64_SMULL=766,
ARM64_SMULL2=767,
ARM64_SMULLB=768,
ARM64_SMULLT=769,
ARM64_SPLICE=770,
ARM64_SQABS=771,
ARM64_SQADD=772,
ARM64_SQCADD=773,
ARM64_SQDECB=774,
ARM64_SQDECD=775,
ARM64_SQDECH=776,
ARM64_SQDECP=777,
ARM64_SQDECW=778,
ARM64_SQDMLAL=779,
ARM64_SQDMLAL2=780,
ARM64_SQDMLALB=781,
ARM64_SQDMLALBT=782,
ARM64_SQDMLALT=783,
ARM64_SQDMLSL=784,
ARM64_SQDMLSL2=785,
ARM64_SQDMLSLB=786,
ARM64_SQDMLSLBT=787,
ARM64_SQDMLSLT=788,
ARM64_SQDMULH=789,
ARM64_SQDMULL=790,
ARM64_SQDMULL2=791,
ARM64_SQDMULLB=792,
ARM64_SQDMULLT=793,
ARM64_SQINCB=794,
ARM64_SQINCD=795,
ARM64_SQINCH=796,
ARM64_SQINCP=797,
ARM64_SQINCW=798,
ARM64_SQNEG=799,
ARM64_SQRDCMLAH=800,
ARM64_SQRDMLAH=801,
ARM64_SQRDMLSH=802,
ARM64_SQRDMULH=803,
ARM64_SQRSHL=804,
ARM64_SQRSHLR=805,
ARM64_SQRSHRN=806,
ARM64_SQRSHRN2=807,
ARM64_SQRSHRNB=808,
ARM64_SQRSHRNT=809,
ARM64_SQRSHRUN=810,
ARM64_SQRSHRUN2=811,
ARM64_SQRSHRUNB=812,
ARM64_SQRSHRUNT=813,
ARM64_SQSHL=814,
ARM64_SQSHLR=815,
ARM64_SQSHLU=816,
ARM64_SQSHRN=817,
ARM64_SQSHRN2=818,
ARM64_SQSHRNB=819,
ARM64_SQSHRNT=820,
ARM64_SQSHRUN=821,
ARM64_SQSHRUN2=822,
ARM64_SQSHRUNB=823,
ARM64_SQSHRUNT=824,
ARM64_SQSUB=825,
ARM64_SQSUBR=826,
ARM64_SQXTN=827,
ARM64_SQXTN2=828,
ARM64_SQXTNB=829,
ARM64_SQXTNT=830,
ARM64_SQXTUN=831,
ARM64_SQXTUN2=832,
ARM64_SQXTUNB=833,
ARM64_SQXTUNT=834,
ARM64_SRHADD=835,
ARM64_SRI=836,
ARM64_SRSHL=837,
ARM64_SRSHLR=838,
ARM64_SRSHR=839,
ARM64_SRSRA=840,
ARM64_SSBB=841,
ARM64_SSHL=842,
ARM64_SSHLL=843,
ARM64_SSHLL2=844,
ARM64_SSHLLB=845,
ARM64_SSHLLT=846,
ARM64_SSHR=847,
ARM64_SSRA=848,
ARM64_SSUBL=849,
ARM64_SSUBL2=850,
ARM64_SSUBLB=851,
ARM64_SSUBLBT=852,
ARM64_SSUBLT=853,
ARM64_SSUBLTB=854,
ARM64_SSUBW=855,
ARM64_SSUBW2=856,
ARM64_SSUBWB=857,
ARM64_SSUBWT=858,
ARM64_ST1=859,
ARM64_ST1B=860,
ARM64_ST1D=861,
ARM64_ST1H=862,
ARM64_ST1W=863,
ARM64_ST2=864,
ARM64_ST2B=865,
ARM64_ST2D=866,
ARM64_ST2G=867,
ARM64_ST2H=868,
ARM64_ST2W=869,
ARM64_ST3=870,
ARM64_ST3B=871,
ARM64_ST3D=872,
ARM64_ST3H=873,
ARM64_ST3W=874,
ARM64_ST4=875,
ARM64_ST4B=876,
ARM64_ST4D=877,
ARM64_ST4H=878,
ARM64_ST4W=879,
ARM64_ST64B=880,
ARM64_ST64BV=881,
ARM64_ST64BV0=882,
ARM64_STADD=883,
ARM64_STADDB=884,
ARM64_STADDH=885,
ARM64_STADDL=886,
ARM64_STADDLB=887,
ARM64_STADDLH=888,
ARM64_STCLR=889,
ARM64_STCLRB=890,
ARM64_STCLRH=891,
ARM64_STCLRL=892,
ARM64_STCLRLB=893,
ARM64_STCLRLH=894,
ARM64_STEOR=895,
ARM64_STEORB=896,
ARM64_STEORH=897,
ARM64_STEORL=898,
ARM64_STEORLB=899,
ARM64_STEORLH=900,
ARM64_STG=901,
ARM64_STGM=902,
ARM64_STGP=903,
ARM64_STLLR=904,
ARM64_STLLRB=905,
ARM64_STLLRH=906,
ARM64_STLR=907,
ARM64_STLRB=908,
ARM64_STLRH=909,
ARM64_STLUR=910,
ARM64_STLURB=911,
ARM64_STLURH=912,
ARM64_STLXP=913,
ARM64_STLXR=914,
ARM64_STLXRB=915,
ARM64_STLXRH=916,
ARM64_STNP=917,
ARM64_STNT1B=918,
ARM64_STNT1D=919,
ARM64_STNT1H=920,
ARM64_STNT1W=921,
ARM64_STP=922,
ARM64_STR=923,
ARM64_STRB=924,
ARM64_STRH=925,
ARM64_STSET=926,
ARM64_STSETB=927,
ARM64_STSETH=928,
ARM64_STSETL=929,
ARM64_STSETLB=930,
ARM64_STSETLH=931,
ARM64_STSMAX=932,
ARM64_STSMAXB=933,
ARM64_STSMAXH=934,
ARM64_STSMAXL=935,
ARM64_STSMAXLB=936,
ARM64_STSMAXLH=937,
ARM64_STSMIN=938,
ARM64_STSMINB=939,
ARM64_STSMINH=940,
ARM64_STSMINL=941,
ARM64_STSMINLB=942,
ARM64_STSMINLH=943,
ARM64_STTR=944,
ARM64_STTRB=945,
ARM64_STTRH=946,
ARM64_STUMAX=947,
ARM64_STUMAXB=948,
ARM64_STUMAXH=949,
ARM64_STUMAXL=950,
ARM64_STUMAXLB=951,
ARM64_STUMAXLH=952,
ARM64_STUMIN=953,
ARM64_STUMINB=954,
ARM64_STUMINH=955,
ARM64_STUMINL=956,
ARM64_STUMINLB=957,
ARM64_STUMINLH=958,
ARM64_STUR=959,
ARM64_STURB=960,
ARM64_STURH=961,
ARM64_STXP=962,
ARM64_STXR=963,
ARM64_STXRB=964,
ARM64_STXRH=965,
ARM64_STZ2G=966,
ARM64_STZG=967,
ARM64_STZGM=968,
ARM64_SUB=969,
ARM64_SUBG=970,
ARM64_SUBHN=971,
ARM64_SUBHN2=972,
ARM64_SUBHNB=973,
ARM64_SUBHNT=974,
ARM64_SUBP=975,
ARM64_SUBPS=976,
ARM64_SUBR=977,
ARM64_SUBS=978,
ARM64_SUDOT=979,
ARM64_SUNPKHI=980,
ARM64_SUNPKLO=981,
ARM64_SUQADD=982,
ARM64_SVC=983,
ARM64_SWP=984,
ARM64_SWPA=985,
ARM64_SWPAB=986,
ARM64_SWPAH=987,
ARM64_SWPAL=988,
ARM64_SWPALB=989,
ARM64_SWPALH=990,
ARM64_SWPB=991,
ARM64_SWPH=992,
ARM64_SWPL=993,
ARM64_SWPLB=994,
ARM64_SWPLH=995,
ARM64_SXTB=996,
ARM64_SXTH=997,
ARM64_SXTL=998,
ARM64_SXTL2=999,
ARM64_SXTW=1000,
ARM64_SYS=1001,
ARM64_SYSL=1002,
ARM64_TBL=1003,
ARM64_TBNZ=1004,
ARM64_TBX=1005,
ARM64_TBZ=1006,
ARM64_TCANCEL=1007,
ARM64_TCOMMIT=1008,
ARM64_TLBI=1009,
ARM64_TRN1=1010,
ARM64_TRN2=1011,
ARM64_TSB=1012,
ARM64_TST=1013,
ARM64_TSTART=1014,
ARM64_TTEST=1015,
ARM64_UABA=1016,
ARM64_UABAL=1017,
ARM64_UABAL2=1018,
ARM64_UABALB=1019,
ARM64_UABALT=1020,
ARM64_UABD=1021,
ARM64_UABDL=1022,
ARM64_UABDL2=1023,
ARM64_UABDLB=1024,
ARM64_UABDLT=1025,
ARM64_UADALP=1026,
ARM64_UADDL=1027,
ARM64_UADDL2=1028,
ARM64_UADDLB=1029,
ARM64_UADDLP=1030,
ARM64_UADDLT=1031,
ARM64_UADDLV=1032,
ARM64_UADDV=1033,
ARM64_UADDW=1034,
ARM64_UADDW2=1035,
ARM64_UADDWB=1036,
ARM64_UADDWT=1037,
ARM64_UBFIZ=1038,
ARM64_UBFM=1039,
ARM64_UBFX=1040,
ARM64_UCVTF=1041,
ARM64_UDF=1042,
ARM64_UDIV=1043,
ARM64_UDIVR=1044,
ARM64_UDOT=1045,
ARM64_UHADD=1046,
ARM64_UHSUB=1047,
ARM64_UHSUBR=1048,
ARM64_UMADDL=1049,
ARM64_UMAX=1050,
ARM64_UMAXP=1051,
ARM64_UMAXV=1052,
ARM64_UMIN=1053,
ARM64_UMINP=1054,
ARM64_UMINV=1055,
ARM64_UMLAL=1056,
ARM64_UMLAL2=1057,
ARM64_UMLALB=1058,
ARM64_UMLALT=1059,
ARM64_UMLSL=1060,
ARM64_UMLSL2=1061,
ARM64_UMLSLB=1062,
ARM64_UMLSLT=1063,
ARM64_UMMLA=1064,
ARM64_UMNEGL=1065,
ARM64_UMOV=1066,
ARM64_UMSUBL=1067,
ARM64_UMULH=1068,
ARM64_UMULL=1069,
ARM64_UMULL2=1070,
ARM64_UMULLB=1071,
ARM64_UMULLT=1072,
ARM64_UQADD=1073,
ARM64_UQDECB=1074,
ARM64_UQDECD=1075,
ARM64_UQDECH=1076,
ARM64_UQDECP=1077,
ARM64_UQDECW=1078,
ARM64_UQINCB=1079,
ARM64_UQINCD=1080,
ARM64_UQINCH=1081,
ARM64_UQINCP=1082,
ARM64_UQINCW=1083,
ARM64_UQRSHL=1084,
ARM64_UQRSHLR=1085,
ARM64_UQRSHRN=1086,
ARM64_UQRSHRN2=1087,
ARM64_UQRSHRNB=1088,
ARM64_UQRSHRNT=1089,
ARM64_UQSHL=1090,
ARM64_UQSHLR=1091,
ARM64_UQSHRN=1092,
ARM64_UQSHRN2=1093,
ARM64_UQSHRNB=1094,
ARM64_UQSHRNT=1095,
ARM64_UQSUB=1096,
ARM64_UQSUBR=1097,
ARM64_UQXTN=1098,
ARM64_UQXTN2=1099,
ARM64_UQXTNB=1100,
ARM64_UQXTNT=1101,
ARM64_URECPE=1102,
ARM64_URHADD=1103,
ARM64_URSHL=1104,
ARM64_URSHLR=1105,
ARM64_URSHR=1106,
ARM64_URSQRTE=1107,
ARM64_URSRA=1108,
ARM64_USDOT=1109,
ARM64_USHL=1110,
ARM64_USHLL=1111,
ARM64_USHLL2=1112,
ARM64_USHLLB=1113,
ARM64_USHLLT=1114,
ARM64_USHR=1115,
ARM64_USMMLA=1116,
ARM64_USQADD=1117,
ARM64_USRA=1118,
ARM64_USUBL=1119,
ARM64_USUBL2=1120,
ARM64_USUBLB=1121,
ARM64_USUBLT=1122,
ARM64_USUBW=1123,
ARM64_USUBW2=1124,
ARM64_USUBWB=1125,
ARM64_USUBWT=1126,
ARM64_UUNPKHI=1127,
ARM64_UUNPKLO=1128,
ARM64_UXTB=1129,
ARM64_UXTH=1130,
ARM64_UXTL=1131,
ARM64_UXTL2=1132,
ARM64_UXTW=1133,
ARM64_UZP1=1134,
ARM64_UZP2=1135,
ARM64_WFE=1136,
ARM64_WFET=1137,
ARM64_WFI=1138,
ARM64_WFIT=1139,
ARM64_WHILEGE=1140,
ARM64_WHILEGT=1141,
ARM64_WHILEHI=1142,
ARM64_WHILEHS=1143,
ARM64_WHILELE=1144,
ARM64_WHILELO=1145,
ARM64_WHILELS=1146,
ARM64_WHILELT=1147,
ARM64_WHILERW=1148,
ARM64_WHILEWR=1149,
ARM64_WRFFR=1150,
ARM64_XAFLAG=1151,
ARM64_XAR=1152,
ARM64_XPACD=1153,
ARM64_XPACI=1154,
ARM64_XPACLRI=1155,
ARM64_XTN=1156,
ARM64_XTN2=1157,
ARM64_YIELD=1158,
ARM64_ZIP1=1159,
ARM64_ZIP2=1160,
};
const char *operation_to_str(enum Operation oper);
