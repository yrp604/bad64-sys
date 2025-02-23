/* GENERATED FILE */
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "decode.h"

void decode_fields32(enum ENCODING enc, context *ctx, Instruction *instr)
{
	uint32_t insword = instr->insword;
	instr->encoding = enc; /* record current path of decoding */
	switch(enc) {
		case ENC_FMADD_H_FLOATDP3:
		case ENC_FMADD_S_FLOATDP3:
		case ENC_FMADD_D_FLOATDP3:
		case ENC_FMSUB_H_FLOATDP3:
		case ENC_FMSUB_S_FLOATDP3:
		case ENC_FMSUB_D_FLOATDP3:
		case ENC_FNMADD_H_FLOATDP3:
		case ENC_FNMADD_S_FLOATDP3:
		case ENC_FNMADD_D_FLOATDP3:
		case ENC_FNMSUB_H_FLOATDP3:
		case ENC_FNMSUB_S_FLOATDP3:
		case ENC_FNMSUB_D_FLOATDP3:
			// M=x|x|S=x|xxxxx|ftype=xx|o1=x|Rm=xxxxx|o0=x|Ra=xxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->M = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ftype = (insword>>22)&3;
			ctx->o1 = (insword>>21)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->o0 = (insword>>15)&1;
			ctx->Ra = (insword>>10)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCSEL_H_FLOATSEL:
		case ENC_FCSEL_S_FLOATSEL:
		case ENC_FCSEL_D_FLOATSEL:
			// M=x|x|S=x|xxxxx|ftype=xx|x|Rm=xxxxx|cond=xxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->M = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ftype = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->cond = (insword>>12)&15;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCCMPE_H_FLOATCCMP:
		case ENC_FCCMPE_S_FLOATCCMP:
		case ENC_FCCMPE_D_FLOATCCMP:
		case ENC_FCCMP_H_FLOATCCMP:
		case ENC_FCCMP_S_FLOATCCMP:
		case ENC_FCCMP_D_FLOATCCMP:
			// M=x|x|S=x|xxxxx|ftype=xx|x|Rm=xxxxx|cond=xxxx|xx|Rn=xxxxx|op=x|nzcv=xxxx
			ctx->M = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ftype = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->cond = (insword>>12)&15;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->op = (insword>>4)&1;
			ctx->nzcv = insword&15;
			break;
		case ENC_FCMPE_H_FLOATCMP:
		case ENC_FCMPE_HZ_FLOATCMP:
		case ENC_FCMPE_S_FLOATCMP:
		case ENC_FCMPE_SZ_FLOATCMP:
		case ENC_FCMPE_D_FLOATCMP:
		case ENC_FCMPE_DZ_FLOATCMP:
		case ENC_FCMP_H_FLOATCMP:
		case ENC_FCMP_HZ_FLOATCMP:
		case ENC_FCMP_S_FLOATCMP:
		case ENC_FCMP_SZ_FLOATCMP:
		case ENC_FCMP_D_FLOATCMP:
		case ENC_FCMP_DZ_FLOATCMP:
			// M=x|x|S=x|xxxxx|ftype=xx|x|Rm=xxxxx|op=xx|xxxx|Rn=xxxxx|opc=xx|opcode2[2:0]=xxx
			ctx->M = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ftype = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->op = (insword>>14)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->opc = (insword>>3)&3;
			ctx->opcode2 = insword&7;
			break;
		case ENC_FMUL_H_FLOATDP2:
		case ENC_FMUL_S_FLOATDP2:
		case ENC_FMUL_D_FLOATDP2:
		case ENC_FNMUL_H_FLOATDP2:
		case ENC_FNMUL_S_FLOATDP2:
		case ENC_FNMUL_D_FLOATDP2:
			// M=x|x|S=x|xxxxx|ftype=xx|x|Rm=xxxxx|op=x|opcode[2:0]=xxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->M = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ftype = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->op = (insword>>15)&1;
			ctx->opcode = (insword>>12)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FDIV_H_FLOATDP2:
		case ENC_FDIV_S_FLOATDP2:
		case ENC_FDIV_D_FLOATDP2:
			// M=x|x|S=x|xxxxx|ftype=xx|x|Rm=xxxxx|opcode=xxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->M = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ftype = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>12)&15;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FADD_H_FLOATDP2:
		case ENC_FADD_S_FLOATDP2:
		case ENC_FADD_D_FLOATDP2:
		case ENC_FSUB_H_FLOATDP2:
		case ENC_FSUB_S_FLOATDP2:
		case ENC_FSUB_D_FLOATDP2:
			// M=x|x|S=x|xxxxx|ftype=xx|x|Rm=xxxxx|opcode[3:1]=xxx|op=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->M = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ftype = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>13)&7;
			ctx->op = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMAXNM_H_FLOATDP2:
		case ENC_FMAXNM_S_FLOATDP2:
		case ENC_FMAXNM_D_FLOATDP2:
		case ENC_FMAX_H_FLOATDP2:
		case ENC_FMAX_S_FLOATDP2:
		case ENC_FMAX_D_FLOATDP2:
		case ENC_FMINNM_H_FLOATDP2:
		case ENC_FMINNM_S_FLOATDP2:
		case ENC_FMINNM_D_FLOATDP2:
		case ENC_FMIN_H_FLOATDP2:
		case ENC_FMIN_S_FLOATDP2:
		case ENC_FMIN_D_FLOATDP2:
			// M=x|x|S=x|xxxxx|ftype=xx|x|Rm=xxxxx|opcode[3:2]=xx|op=xx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->M = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ftype = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>14)&3;
			ctx->op = (insword>>12)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMOV_H_FLOATIMM:
		case ENC_FMOV_S_FLOATIMM:
		case ENC_FMOV_D_FLOATIMM:
			// M=x|x|S=x|xxxxx|ftype=xx|x|imm8=xxxxxxxx|xxx|imm5=xxxxx|Rd=xxxxx
			ctx->M = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ftype = (insword>>22)&3;
			ctx->imm8 = (insword>>13)&0xff;
			ctx->imm5 = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FABS_H_FLOATDP1:
		case ENC_FABS_S_FLOATDP1:
		case ENC_FABS_D_FLOATDP1:
		case ENC_FCVT_SH_FLOATDP1:
		case ENC_FCVT_DH_FLOATDP1:
		case ENC_FCVT_HS_FLOATDP1:
		case ENC_FCVT_DS_FLOATDP1:
		case ENC_FCVT_HD_FLOATDP1:
		case ENC_FCVT_SD_FLOATDP1:
		case ENC_FMOV_H_FLOATDP1:
		case ENC_FMOV_S_FLOATDP1:
		case ENC_FMOV_D_FLOATDP1:
		case ENC_FNEG_H_FLOATDP1:
		case ENC_FNEG_S_FLOATDP1:
		case ENC_FNEG_D_FLOATDP1:
		case ENC_FSQRT_H_FLOATDP1:
		case ENC_FSQRT_S_FLOATDP1:
		case ENC_FSQRT_D_FLOATDP1:
			// M=x|x|S=x|xxxxx|ftype=xx|x|opcode[5:2]=xxxx|opc=xx|xxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->M = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ftype = (insword>>22)&3;
			ctx->opcode = (insword>>17)&15;
			ctx->opc = (insword>>15)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FRINTA_H_FLOATDP1:
		case ENC_FRINTA_S_FLOATDP1:
		case ENC_FRINTA_D_FLOATDP1:
		case ENC_FRINTI_H_FLOATDP1:
		case ENC_FRINTI_S_FLOATDP1:
		case ENC_FRINTI_D_FLOATDP1:
		case ENC_FRINTM_H_FLOATDP1:
		case ENC_FRINTM_S_FLOATDP1:
		case ENC_FRINTM_D_FLOATDP1:
		case ENC_FRINTN_H_FLOATDP1:
		case ENC_FRINTN_S_FLOATDP1:
		case ENC_FRINTN_D_FLOATDP1:
		case ENC_FRINTP_H_FLOATDP1:
		case ENC_FRINTP_S_FLOATDP1:
		case ENC_FRINTP_D_FLOATDP1:
		case ENC_FRINTX_H_FLOATDP1:
		case ENC_FRINTX_S_FLOATDP1:
		case ENC_FRINTX_D_FLOATDP1:
		case ENC_FRINTZ_H_FLOATDP1:
		case ENC_FRINTZ_S_FLOATDP1:
		case ENC_FRINTZ_D_FLOATDP1:
			// M=x|x|S=x|xxxxx|ftype=xx|x|opcode[5:3]=xxx|rmode=xxx|xxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->M = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ftype = (insword>>22)&3;
			ctx->opcode = (insword>>18)&7;
			ctx->rmode = (insword>>15)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FRINT32X_S_FLOATDP1:
		case ENC_FRINT32X_D_FLOATDP1:
		case ENC_FRINT32Z_S_FLOATDP1:
		case ENC_FRINT32Z_D_FLOATDP1:
		case ENC_FRINT64X_S_FLOATDP1:
		case ENC_FRINT64X_D_FLOATDP1:
		case ENC_FRINT64Z_S_FLOATDP1:
		case ENC_FRINT64Z_D_FLOATDP1:
			// M=x|x|S=x|xxxxx|ftype=xx|x|xxxx|op=xx|xxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->M = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ftype = (insword>>22)&3;
			ctx->op = (insword>>15)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_BFCVT_BS_FLOATDP1:
			// M=x|x|S=x|xxxxx|ptype=xx|x|opcode=xxxxxx|xxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->M = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ptype = (insword>>22)&3;
			ctx->opcode = (insword>>15)&0x3f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_TBNZ_ONLY_TESTBRANCH:
		case ENC_TBZ_ONLY_TESTBRANCH:
			// b5=x|xxxxxx|op=x|b40=xxxxx|imm14=xxxxxxxxxxxxxx|Rt=xxxxx
			ctx->b5 = insword>>31;
			ctx->op = (insword>>24)&1;
			ctx->b40 = (insword>>19)&0x1f;
			ctx->imm14 = (insword>>5)&0x3fff;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_ADR_ONLY_PCRELADDR:
		case ENC_ADRP_ONLY_PCRELADDR:
			// op=x|immlo=xx|xxxxx|immhi=xxxxxxxxxxxxxxxxxxx|Rd=xxxxx
			ctx->op = insword>>31;
			ctx->immlo = (insword>>29)&3;
			ctx->immhi = (insword>>5)&0x7ffff;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_BL_ONLY_BRANCH_IMM:
		case ENC_B_ONLY_BRANCH_IMM:
			// op=x|xxxxx|imm26=xxxxxxxxxxxxxxxxxxxxxxxxxx
			ctx->op = insword>>31;
			ctx->imm26 = insword&0x3ffffff;
			break;
		case ENC_LDNP_S_LDSTNAPAIR_OFFS:
		case ENC_LDNP_D_LDSTNAPAIR_OFFS:
		case ENC_LDNP_Q_LDSTNAPAIR_OFFS:
		case ENC_LDNP_32_LDSTNAPAIR_OFFS:
		case ENC_LDNP_64_LDSTNAPAIR_OFFS:
		case ENC_LDPSW_64_LDSTPAIR_POST:
		case ENC_LDPSW_64_LDSTPAIR_PRE:
		case ENC_LDPSW_64_LDSTPAIR_OFF:
		case ENC_LDP_S_LDSTPAIR_POST:
		case ENC_LDP_D_LDSTPAIR_POST:
		case ENC_LDP_Q_LDSTPAIR_POST:
		case ENC_LDP_S_LDSTPAIR_PRE:
		case ENC_LDP_D_LDSTPAIR_PRE:
		case ENC_LDP_Q_LDSTPAIR_PRE:
		case ENC_LDP_S_LDSTPAIR_OFF:
		case ENC_LDP_D_LDSTPAIR_OFF:
		case ENC_LDP_Q_LDSTPAIR_OFF:
		case ENC_LDP_32_LDSTPAIR_POST:
		case ENC_LDP_64_LDSTPAIR_POST:
		case ENC_LDP_32_LDSTPAIR_PRE:
		case ENC_LDP_64_LDSTPAIR_PRE:
		case ENC_LDP_32_LDSTPAIR_OFF:
		case ENC_LDP_64_LDSTPAIR_OFF:
		case ENC_STNP_S_LDSTNAPAIR_OFFS:
		case ENC_STNP_D_LDSTNAPAIR_OFFS:
		case ENC_STNP_Q_LDSTNAPAIR_OFFS:
		case ENC_STNP_32_LDSTNAPAIR_OFFS:
		case ENC_STNP_64_LDSTNAPAIR_OFFS:
		case ENC_STP_S_LDSTPAIR_POST:
		case ENC_STP_D_LDSTPAIR_POST:
		case ENC_STP_Q_LDSTPAIR_POST:
		case ENC_STP_S_LDSTPAIR_PRE:
		case ENC_STP_D_LDSTPAIR_PRE:
		case ENC_STP_Q_LDSTPAIR_PRE:
		case ENC_STP_S_LDSTPAIR_OFF:
		case ENC_STP_D_LDSTPAIR_OFF:
		case ENC_STP_Q_LDSTPAIR_OFF:
		case ENC_STP_32_LDSTPAIR_POST:
		case ENC_STP_64_LDSTPAIR_POST:
		case ENC_STP_32_LDSTPAIR_PRE:
		case ENC_STP_64_LDSTPAIR_PRE:
		case ENC_STP_32_LDSTPAIR_OFF:
		case ENC_STP_64_LDSTPAIR_OFF:
			// opc=xx|xxx|V=x|xxx|L=x|imm7=xxxxxxx|Rt2=xxxxx|Rn=xxxxx|Rt=xxxxx
			ctx->opc = insword>>30;
			ctx->V = (insword>>26)&1;
			ctx->L = (insword>>22)&1;
			ctx->imm7 = (insword>>15)&0x7f;
			ctx->Rt2 = (insword>>10)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_STGP_64_LDSTPAIR_POST:
		case ENC_STGP_64_LDSTPAIR_PRE:
		case ENC_STGP_64_LDSTPAIR_OFF:
			// opc=xx|xxx|V=x|xxx|L=x|simm7=xxxxxxx|Xt2=xxxxx|Xn=xxxxx|Xt=xxxxx
			ctx->opc = insword>>30;
			ctx->V = (insword>>26)&1;
			ctx->L = (insword>>22)&1;
			ctx->simm7 = (insword>>15)&0x7f;
			ctx->Xt2 = (insword>>10)&0x1f;
			ctx->Xn = (insword>>5)&0x1f;
			ctx->Xt = insword&0x1f;
			break;
		case ENC_LDRSW_64_LOADLIT:
		case ENC_LDR_S_LOADLIT:
		case ENC_LDR_D_LOADLIT:
		case ENC_LDR_Q_LOADLIT:
		case ENC_LDR_32_LOADLIT:
		case ENC_LDR_64_LOADLIT:
		case ENC_PRFM_P_LOADLIT:
			// opc=xx|xxx|V=x|xx|imm19=xxxxxxxxxxxxxxxxxxx|Rt=xxxxx
			ctx->opc = insword>>30;
			ctx->V = (insword>>26)&1;
			ctx->imm19 = (insword>>5)&0x7ffff;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_EXTR_32_EXTRACT:
		case ENC_EXTR_64_EXTRACT:
		case ENC_ROR_EXTR_32_EXTRACT:
		case ENC_ROR_EXTR_64_EXTRACT:
			// sf=x|op21=xx|xxxxxx|N=x|o0=x|Rm=xxxxx|imms=xxxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->op21 = (insword>>29)&3;
			ctx->N = (insword>>22)&1;
			ctx->o0 = (insword>>21)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->imms = (insword>>10)&0x3f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SMADDL_64WA_DP_3SRC:
		case ENC_SMNEGL_SMSUBL_64WA_DP_3SRC:
		case ENC_SMSUBL_64WA_DP_3SRC:
		case ENC_SMULH_64_DP_3SRC:
		case ENC_SMULL_SMADDL_64WA_DP_3SRC:
		case ENC_UMADDL_64WA_DP_3SRC:
		case ENC_UMNEGL_UMSUBL_64WA_DP_3SRC:
		case ENC_UMSUBL_64WA_DP_3SRC:
		case ENC_UMULH_64_DP_3SRC:
		case ENC_UMULL_UMADDL_64WA_DP_3SRC:
			// sf=x|op54=xx|xxxxx|U=x|op31[1:0]=xx|Rm=xxxxx|o0=x|Ra=xxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->op54 = (insword>>29)&3;
			ctx->U = (insword>>23)&1;
			ctx->op31 = (insword>>21)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->o0 = (insword>>15)&1;
			ctx->Ra = (insword>>10)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_MADD_32A_DP_3SRC:
		case ENC_MADD_64A_DP_3SRC:
		case ENC_MNEG_MSUB_32A_DP_3SRC:
		case ENC_MNEG_MSUB_64A_DP_3SRC:
		case ENC_MSUB_32A_DP_3SRC:
		case ENC_MSUB_64A_DP_3SRC:
		case ENC_MUL_MADD_32A_DP_3SRC:
		case ENC_MUL_MADD_64A_DP_3SRC:
			// sf=x|op54=xx|xxxxx|op31=xxx|Rm=xxxxx|o0=x|Ra=xxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->op54 = (insword>>29)&3;
			ctx->op31 = (insword>>21)&7;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->o0 = (insword>>15)&1;
			ctx->Ra = (insword>>10)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_CINC_CSINC_32_CONDSEL:
		case ENC_CINC_CSINC_64_CONDSEL:
		case ENC_CINV_CSINV_32_CONDSEL:
		case ENC_CINV_CSINV_64_CONDSEL:
		case ENC_CNEG_CSNEG_32_CONDSEL:
		case ENC_CNEG_CSNEG_64_CONDSEL:
		case ENC_CSEL_32_CONDSEL:
		case ENC_CSEL_64_CONDSEL:
		case ENC_CSETM_CSINV_32_CONDSEL:
		case ENC_CSETM_CSINV_64_CONDSEL:
		case ENC_CSET_CSINC_32_CONDSEL:
		case ENC_CSET_CSINC_64_CONDSEL:
		case ENC_CSINC_32_CONDSEL:
		case ENC_CSINC_64_CONDSEL:
		case ENC_CSINV_32_CONDSEL:
		case ENC_CSINV_64_CONDSEL:
		case ENC_CSNEG_32_CONDSEL:
		case ENC_CSNEG_64_CONDSEL:
			// sf=x|op=x|S=x|xxxxxxxx|Rm=xxxxx|cond=xxxx|op2[1]=x|o2=x|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->op = (insword>>30)&1;
			ctx->S = (insword>>29)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->cond = (insword>>12)&15;
			ctx->op2 = (insword>>11)&1;
			ctx->o2 = (insword>>10)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_CCMN_32_CONDCMP_REG:
		case ENC_CCMN_64_CONDCMP_REG:
		case ENC_CCMP_32_CONDCMP_REG:
		case ENC_CCMP_64_CONDCMP_REG:
			// sf=x|op=x|S=x|xxxxxxxx|Rm=xxxxx|cond=xxxx|x|o2=x|Rn=xxxxx|o3=x|nzcv=xxxx
			ctx->sf = insword>>31;
			ctx->op = (insword>>30)&1;
			ctx->S = (insword>>29)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->cond = (insword>>12)&15;
			ctx->o2 = (insword>>10)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->o3 = (insword>>4)&1;
			ctx->nzcv = insword&15;
			break;
		case ENC_PACGA_64P_DP_2SRC:
			// sf=x|op=x|S=x|xxxxxxxx|Rm=xxxxx|opcode2=xxxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->op = (insword>>30)&1;
			ctx->S = (insword>>29)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode2 = (insword>>10)&0x3f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SDIV_32_DP_2SRC:
		case ENC_SDIV_64_DP_2SRC:
		case ENC_UDIV_32_DP_2SRC:
		case ENC_UDIV_64_DP_2SRC:
			// sf=x|op=x|S=x|xxxxxxxx|Rm=xxxxx|opcode2[5:1]=xxxxx|o1=x|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->op = (insword>>30)&1;
			ctx->S = (insword>>29)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode2 = (insword>>11)&0x1f;
			ctx->o1 = (insword>>10)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_ASRV_32_DP_2SRC:
		case ENC_ASRV_64_DP_2SRC:
		case ENC_ASR_ASRV_32_DP_2SRC:
		case ENC_ASR_ASRV_64_DP_2SRC:
		case ENC_LSLV_32_DP_2SRC:
		case ENC_LSLV_64_DP_2SRC:
		case ENC_LSL_LSLV_32_DP_2SRC:
		case ENC_LSL_LSLV_64_DP_2SRC:
		case ENC_LSRV_32_DP_2SRC:
		case ENC_LSRV_64_DP_2SRC:
		case ENC_LSR_LSRV_32_DP_2SRC:
		case ENC_LSR_LSRV_64_DP_2SRC:
		case ENC_RORV_32_DP_2SRC:
		case ENC_RORV_64_DP_2SRC:
		case ENC_ROR_RORV_32_DP_2SRC:
		case ENC_ROR_RORV_64_DP_2SRC:
			// sf=x|op=x|S=x|xxxxxxxx|Rm=xxxxx|opcode2[5:2]=xxxx|op2=xx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->op = (insword>>30)&1;
			ctx->S = (insword>>29)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode2 = (insword>>12)&15;
			ctx->op2 = (insword>>10)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_CRC32B_32C_DP_2SRC:
		case ENC_CRC32H_32C_DP_2SRC:
		case ENC_CRC32W_32C_DP_2SRC:
		case ENC_CRC32X_64C_DP_2SRC:
		case ENC_CRC32CB_32C_DP_2SRC:
		case ENC_CRC32CH_32C_DP_2SRC:
		case ENC_CRC32CW_32C_DP_2SRC:
		case ENC_CRC32CX_64C_DP_2SRC:
			// sf=x|op=x|S=x|xxxxxxxx|Rm=xxxxx|opcode2[5:3]=xxx|C=x|sz=xx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->op = (insword>>30)&1;
			ctx->S = (insword>>29)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode2 = (insword>>13)&7;
			ctx->C = (insword>>12)&1;
			ctx->sz = (insword>>10)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_ADC_32_ADDSUB_CARRY:
		case ENC_ADC_64_ADDSUB_CARRY:
		case ENC_ADCS_32_ADDSUB_CARRY:
		case ENC_ADCS_64_ADDSUB_CARRY:
		case ENC_NGCS_SBCS_32_ADDSUB_CARRY:
		case ENC_NGCS_SBCS_64_ADDSUB_CARRY:
		case ENC_NGC_SBC_32_ADDSUB_CARRY:
		case ENC_NGC_SBC_64_ADDSUB_CARRY:
		case ENC_SBC_32_ADDSUB_CARRY:
		case ENC_SBC_64_ADDSUB_CARRY:
		case ENC_SBCS_32_ADDSUB_CARRY:
		case ENC_SBCS_64_ADDSUB_CARRY:
			// sf=x|op=x|S=x|xxxxxxxx|Rm=xxxxx|xxxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->op = (insword>>30)&1;
			ctx->S = (insword>>29)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_CCMN_32_CONDCMP_IMM:
		case ENC_CCMN_64_CONDCMP_IMM:
		case ENC_CCMP_32_CONDCMP_IMM:
		case ENC_CCMP_64_CONDCMP_IMM:
			// sf=x|op=x|S=x|xxxxxxxx|imm5=xxxxx|cond=xxxx|x|o2=x|Rn=xxxxx|o3=x|nzcv=xxxx
			ctx->sf = insword>>31;
			ctx->op = (insword>>30)&1;
			ctx->S = (insword>>29)&1;
			ctx->imm5 = (insword>>16)&0x1f;
			ctx->cond = (insword>>12)&15;
			ctx->o2 = (insword>>10)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->o3 = (insword>>4)&1;
			ctx->nzcv = insword&15;
			break;
		case ENC_RMIF_ONLY_RMIF:
			// sf=x|op=x|S=x|xxxxxxxx|imm6=xxxxxx|xxxxx|Rn=xxxxx|o2=x|mask=xxxx
			ctx->sf = insword>>31;
			ctx->op = (insword>>30)&1;
			ctx->S = (insword>>29)&1;
			ctx->imm6 = (insword>>15)&0x3f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->o2 = (insword>>4)&1;
			ctx->mask = insword&15;
			break;
		case ENC_SETF8_ONLY_SETF:
		case ENC_SETF16_ONLY_SETF:
			// sf=x|op=x|S=x|xxxxxxxx|opcode2=xxxxxx|sz=x|xxxx|Rn=xxxxx|o3=x|mask=xxxx
			ctx->sf = insword>>31;
			ctx->op = (insword>>30)&1;
			ctx->S = (insword>>29)&1;
			ctx->opcode2 = (insword>>15)&0x3f;
			ctx->sz = (insword>>14)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->o3 = (insword>>4)&1;
			ctx->mask = insword&15;
			break;
		case ENC_ADDG_64_ADDSUB_IMMTAGS:
		case ENC_SUBG_64_ADDSUB_IMMTAGS:
			// sf=x|op=x|S=x|xxxxxx|o2=x|uimm6=xxxxxx|op3=xx|uimm4=xxxx|Xn=xxxxx|Xd=xxxxx
			ctx->sf = insword>>31;
			ctx->op = (insword>>30)&1;
			ctx->S = (insword>>29)&1;
			ctx->o2 = (insword>>22)&1;
			ctx->uimm6 = (insword>>16)&0x3f;
			ctx->op3 = (insword>>14)&3;
			ctx->uimm4 = (insword>>10)&15;
			ctx->Xn = (insword>>5)&0x1f;
			ctx->Xd = insword&0x1f;
			break;
		case ENC_ADDS_32S_ADDSUB_IMM:
		case ENC_ADDS_64S_ADDSUB_IMM:
		case ENC_ADD_32_ADDSUB_IMM:
		case ENC_ADD_64_ADDSUB_IMM:
		case ENC_CMN_ADDS_32S_ADDSUB_IMM:
		case ENC_CMN_ADDS_64S_ADDSUB_IMM:
		case ENC_CMP_SUBS_32S_ADDSUB_IMM:
		case ENC_CMP_SUBS_64S_ADDSUB_IMM:
		case ENC_MOV_ADD_32_ADDSUB_IMM:
		case ENC_MOV_ADD_64_ADDSUB_IMM:
		case ENC_SUBS_32S_ADDSUB_IMM:
		case ENC_SUBS_64S_ADDSUB_IMM:
		case ENC_SUB_32_ADDSUB_IMM:
		case ENC_SUB_64_ADDSUB_IMM:
			// sf=x|op=x|S=x|xxxxxx|sh=x|imm12=xxxxxxxxxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->op = (insword>>30)&1;
			ctx->S = (insword>>29)&1;
			ctx->sh = (insword>>22)&1;
			ctx->imm12 = (insword>>10)&0xfff;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_ADDS_32S_ADDSUB_EXT:
		case ENC_ADDS_64S_ADDSUB_EXT:
		case ENC_ADD_32_ADDSUB_EXT:
		case ENC_ADD_64_ADDSUB_EXT:
		case ENC_CMN_ADDS_32S_ADDSUB_EXT:
		case ENC_CMN_ADDS_64S_ADDSUB_EXT:
		case ENC_CMP_SUBS_32S_ADDSUB_EXT:
		case ENC_CMP_SUBS_64S_ADDSUB_EXT:
		case ENC_SUBS_32S_ADDSUB_EXT:
		case ENC_SUBS_64S_ADDSUB_EXT:
		case ENC_SUB_32_ADDSUB_EXT:
		case ENC_SUB_64_ADDSUB_EXT:
			// sf=x|op=x|S=x|xxxxx|opt=xx|x|Rm=xxxxx|option=xxx|imm3=xxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->op = (insword>>30)&1;
			ctx->S = (insword>>29)&1;
			ctx->opt = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->option = (insword>>13)&7;
			ctx->imm3 = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_ADDS_32_ADDSUB_SHIFT:
		case ENC_ADDS_64_ADDSUB_SHIFT:
		case ENC_ADD_32_ADDSUB_SHIFT:
		case ENC_ADD_64_ADDSUB_SHIFT:
		case ENC_CMN_ADDS_32_ADDSUB_SHIFT:
		case ENC_CMN_ADDS_64_ADDSUB_SHIFT:
		case ENC_CMP_SUBS_32_ADDSUB_SHIFT:
		case ENC_CMP_SUBS_64_ADDSUB_SHIFT:
		case ENC_NEGS_SUBS_32_ADDSUB_SHIFT:
		case ENC_NEGS_SUBS_64_ADDSUB_SHIFT:
		case ENC_NEG_SUB_32_ADDSUB_SHIFT:
		case ENC_NEG_SUB_64_ADDSUB_SHIFT:
		case ENC_SUBS_32_ADDSUB_SHIFT:
		case ENC_SUBS_64_ADDSUB_SHIFT:
		case ENC_SUB_32_ADDSUB_SHIFT:
		case ENC_SUB_64_ADDSUB_SHIFT:
			// sf=x|op=x|S=x|xxxxx|shift=xx|x|Rm=xxxxx|imm6=xxxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->op = (insword>>30)&1;
			ctx->S = (insword>>29)&1;
			ctx->shift = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->imm6 = (insword>>10)&0x3f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_ANDS_32S_LOG_IMM:
		case ENC_ANDS_64S_LOG_IMM:
		case ENC_AND_32_LOG_IMM:
		case ENC_AND_64_LOG_IMM:
		case ENC_ASR_SBFM_32M_BITFIELD:
		case ENC_ASR_SBFM_64M_BITFIELD:
		case ENC_BFC_BFM_32M_BITFIELD:
		case ENC_BFC_BFM_64M_BITFIELD:
		case ENC_BFI_BFM_32M_BITFIELD:
		case ENC_BFI_BFM_64M_BITFIELD:
		case ENC_BFM_32M_BITFIELD:
		case ENC_BFM_64M_BITFIELD:
		case ENC_BFXIL_BFM_32M_BITFIELD:
		case ENC_BFXIL_BFM_64M_BITFIELD:
		case ENC_EOR_32_LOG_IMM:
		case ENC_EOR_64_LOG_IMM:
		case ENC_LSL_UBFM_32M_BITFIELD:
		case ENC_LSL_UBFM_64M_BITFIELD:
		case ENC_LSR_UBFM_32M_BITFIELD:
		case ENC_LSR_UBFM_64M_BITFIELD:
		case ENC_MOV_ORR_32_LOG_IMM:
		case ENC_MOV_ORR_64_LOG_IMM:
		case ENC_ORR_32_LOG_IMM:
		case ENC_ORR_64_LOG_IMM:
		case ENC_SBFIZ_SBFM_32M_BITFIELD:
		case ENC_SBFIZ_SBFM_64M_BITFIELD:
		case ENC_SBFM_32M_BITFIELD:
		case ENC_SBFM_64M_BITFIELD:
		case ENC_SBFX_SBFM_32M_BITFIELD:
		case ENC_SBFX_SBFM_64M_BITFIELD:
		case ENC_SXTB_SBFM_32M_BITFIELD:
		case ENC_SXTB_SBFM_64M_BITFIELD:
		case ENC_SXTH_SBFM_32M_BITFIELD:
		case ENC_SXTH_SBFM_64M_BITFIELD:
		case ENC_SXTW_SBFM_64M_BITFIELD:
		case ENC_TST_ANDS_32S_LOG_IMM:
		case ENC_TST_ANDS_64S_LOG_IMM:
		case ENC_UBFIZ_UBFM_32M_BITFIELD:
		case ENC_UBFIZ_UBFM_64M_BITFIELD:
		case ENC_UBFM_32M_BITFIELD:
		case ENC_UBFM_64M_BITFIELD:
		case ENC_UBFX_UBFM_32M_BITFIELD:
		case ENC_UBFX_UBFM_64M_BITFIELD:
		case ENC_UXTB_UBFM_32M_BITFIELD:
		case ENC_UXTH_UBFM_32M_BITFIELD:
			// sf=x|opc=xx|xxxxxx|N=x|immr=xxxxxx|imms=xxxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->opc = (insword>>29)&3;
			ctx->N = (insword>>22)&1;
			ctx->immr = (insword>>16)&0x3f;
			ctx->imms = (insword>>10)&0x3f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_MOVK_32_MOVEWIDE:
		case ENC_MOVK_64_MOVEWIDE:
		case ENC_MOVN_32_MOVEWIDE:
		case ENC_MOVN_64_MOVEWIDE:
		case ENC_MOVZ_32_MOVEWIDE:
		case ENC_MOVZ_64_MOVEWIDE:
		case ENC_MOV_MOVN_32_MOVEWIDE:
		case ENC_MOV_MOVN_64_MOVEWIDE:
		case ENC_MOV_MOVZ_32_MOVEWIDE:
		case ENC_MOV_MOVZ_64_MOVEWIDE:
			// sf=x|opc=xx|xxxxxx|hw=xx|imm16=xxxxxxxxxxxxxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->opc = (insword>>29)&3;
			ctx->hw = (insword>>21)&3;
			ctx->imm16 = (insword>>5)&0xffff;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_ANDS_32_LOG_SHIFT:
		case ENC_ANDS_64_LOG_SHIFT:
		case ENC_AND_32_LOG_SHIFT:
		case ENC_AND_64_LOG_SHIFT:
		case ENC_BICS_32_LOG_SHIFT:
		case ENC_BICS_64_LOG_SHIFT:
		case ENC_BIC_32_LOG_SHIFT:
		case ENC_BIC_64_LOG_SHIFT:
		case ENC_EON_32_LOG_SHIFT:
		case ENC_EON_64_LOG_SHIFT:
		case ENC_EOR_32_LOG_SHIFT:
		case ENC_EOR_64_LOG_SHIFT:
		case ENC_MOV_ORR_32_LOG_SHIFT:
		case ENC_MOV_ORR_64_LOG_SHIFT:
		case ENC_MVN_ORN_32_LOG_SHIFT:
		case ENC_MVN_ORN_64_LOG_SHIFT:
		case ENC_ORN_32_LOG_SHIFT:
		case ENC_ORN_64_LOG_SHIFT:
		case ENC_ORR_32_LOG_SHIFT:
		case ENC_ORR_64_LOG_SHIFT:
		case ENC_TST_ANDS_32_LOG_SHIFT:
		case ENC_TST_ANDS_64_LOG_SHIFT:
			// sf=x|opc=xx|xxxxx|shift=xx|N=x|Rm=xxxxx|imm6=xxxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->opc = (insword>>29)&3;
			ctx->shift = (insword>>22)&3;
			ctx->N = (insword>>21)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->imm6 = (insword>>10)&0x3f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_CBNZ_32_COMPBRANCH:
		case ENC_CBNZ_64_COMPBRANCH:
		case ENC_CBZ_32_COMPBRANCH:
		case ENC_CBZ_64_COMPBRANCH:
			// sf=x|xxxxxx|op=x|imm19=xxxxxxxxxxxxxxxxxxx|Rt=xxxxx
			ctx->sf = insword>>31;
			ctx->op = (insword>>24)&1;
			ctx->imm19 = (insword>>5)&0x7ffff;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_CMPP_SUBPS_64S_DP_2SRC:
		case ENC_GMI_64G_DP_2SRC:
		case ENC_IRG_64I_DP_2SRC:
		case ENC_SUBP_64S_DP_2SRC:
		case ENC_SUBPS_64S_DP_2SRC:
			// sf=x|x|S=x|xxxxxxxx|Xm=xxxxx|opcode=xxxxxx|Xn=xxxxx|Xd=xxxxx
			ctx->sf = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->Xm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>10)&0x3f;
			ctx->Xn = (insword>>5)&0x1f;
			ctx->Xd = insword&0x1f;
			break;
		case ENC_CLS_32_DP_1SRC:
		case ENC_CLS_64_DP_1SRC:
		case ENC_CLZ_32_DP_1SRC:
		case ENC_CLZ_64_DP_1SRC:
			// sf=x|x|S=x|xxxxxxxx|opcode2=xxxxx|opcode[5:1]=xxxxx|op=x|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->opcode2 = (insword>>16)&0x1f;
			ctx->opcode = (insword>>11)&0x1f;
			ctx->op = (insword>>10)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_REV_32_DP_1SRC:
		case ENC_REV_64_DP_1SRC:
		case ENC_REV16_32_DP_1SRC:
		case ENC_REV16_64_DP_1SRC:
		case ENC_REV32_64_DP_1SRC:
		case ENC_REV64_REV_64_DP_1SRC:
			// sf=x|x|S=x|xxxxxxxx|opcode2=xxxxx|opcode[5:2]=xxxx|opc=xx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->opcode2 = (insword>>16)&0x1f;
			ctx->opcode = (insword>>12)&15;
			ctx->opc = (insword>>10)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_RBIT_32_DP_1SRC:
		case ENC_RBIT_64_DP_1SRC:
			// sf=x|x|S=x|xxxxxxxx|opcode2=xxxxx|opcode[5:2]=xxxx|opcode[1:0]=xx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->opcode2 = (insword>>16)&0x1f;
			ctx->opcode = (insword>>12)&15;
			ctx->opcode = (insword>>10)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_AUTDA_64P_DP_1SRC:
		case ENC_AUTDZA_64Z_DP_1SRC:
		case ENC_AUTDB_64P_DP_1SRC:
		case ENC_AUTDZB_64Z_DP_1SRC:
		case ENC_AUTIA_64P_DP_1SRC:
		case ENC_AUTIZA_64Z_DP_1SRC:
		case ENC_AUTIB_64P_DP_1SRC:
		case ENC_AUTIZB_64Z_DP_1SRC:
		case ENC_PACDA_64P_DP_1SRC:
		case ENC_PACDZA_64Z_DP_1SRC:
		case ENC_PACDB_64P_DP_1SRC:
		case ENC_PACDZB_64Z_DP_1SRC:
		case ENC_PACIA_64P_DP_1SRC:
		case ENC_PACIZA_64Z_DP_1SRC:
		case ENC_PACIB_64P_DP_1SRC:
		case ENC_PACIZB_64Z_DP_1SRC:
			// sf=x|x|S=x|xxxxxxxx|opcode2=xxxxx|opcode[5]=x|opcode[4]=x|Z=x|opcode[2:0]=xxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->opcode2 = (insword>>16)&0x1f;
			ctx->opcode = (insword>>15)&1;
			ctx->opcode = (insword>>14)&1;
			ctx->Z = (insword>>13)&1;
			ctx->opcode = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_XPACD_64Z_DP_1SRC:
		case ENC_XPACI_64Z_DP_1SRC:
			// sf=x|x|S=x|xxxxxxxx|opcode2=xxxxx|opcode[5]=x|opcode[4]=x|opcode[3:1]=xxx|D=x|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->opcode2 = (insword>>16)&0x1f;
			ctx->opcode = (insword>>15)&1;
			ctx->opcode = (insword>>14)&1;
			ctx->opcode = (insword>>11)&7;
			ctx->D = (insword>>10)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCVTZS_32H_FLOAT2FIX:
		case ENC_FCVTZS_64H_FLOAT2FIX:
		case ENC_FCVTZS_32S_FLOAT2FIX:
		case ENC_FCVTZS_64S_FLOAT2FIX:
		case ENC_FCVTZS_32D_FLOAT2FIX:
		case ENC_FCVTZS_64D_FLOAT2FIX:
		case ENC_FCVTZU_32H_FLOAT2FIX:
		case ENC_FCVTZU_64H_FLOAT2FIX:
		case ENC_FCVTZU_32S_FLOAT2FIX:
		case ENC_FCVTZU_64S_FLOAT2FIX:
		case ENC_FCVTZU_32D_FLOAT2FIX:
		case ENC_FCVTZU_64D_FLOAT2FIX:
		case ENC_SCVTF_H32_FLOAT2FIX:
		case ENC_SCVTF_S32_FLOAT2FIX:
		case ENC_SCVTF_D32_FLOAT2FIX:
		case ENC_SCVTF_H64_FLOAT2FIX:
		case ENC_SCVTF_S64_FLOAT2FIX:
		case ENC_SCVTF_D64_FLOAT2FIX:
		case ENC_UCVTF_H32_FLOAT2FIX:
		case ENC_UCVTF_S32_FLOAT2FIX:
		case ENC_UCVTF_D32_FLOAT2FIX:
		case ENC_UCVTF_H64_FLOAT2FIX:
		case ENC_UCVTF_S64_FLOAT2FIX:
		case ENC_UCVTF_D64_FLOAT2FIX:
			// sf=x|x|S=x|xxxxx|ftype=xx|x|rmode=xx|opcode=xxx|scale=xxxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ftype = (insword>>22)&3;
			ctx->rmode = (insword>>19)&3;
			ctx->opcode = (insword>>16)&7;
			ctx->scale = (insword>>10)&0x3f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCVTAS_32H_FLOAT2INT:
		case ENC_FCVTAS_64H_FLOAT2INT:
		case ENC_FCVTAS_32S_FLOAT2INT:
		case ENC_FCVTAS_64S_FLOAT2INT:
		case ENC_FCVTAS_32D_FLOAT2INT:
		case ENC_FCVTAS_64D_FLOAT2INT:
		case ENC_FCVTAU_32H_FLOAT2INT:
		case ENC_FCVTAU_64H_FLOAT2INT:
		case ENC_FCVTAU_32S_FLOAT2INT:
		case ENC_FCVTAU_64S_FLOAT2INT:
		case ENC_FCVTAU_32D_FLOAT2INT:
		case ENC_FCVTAU_64D_FLOAT2INT:
		case ENC_FCVTMS_32H_FLOAT2INT:
		case ENC_FCVTMS_64H_FLOAT2INT:
		case ENC_FCVTMS_32S_FLOAT2INT:
		case ENC_FCVTMS_64S_FLOAT2INT:
		case ENC_FCVTMS_32D_FLOAT2INT:
		case ENC_FCVTMS_64D_FLOAT2INT:
		case ENC_FCVTMU_32H_FLOAT2INT:
		case ENC_FCVTMU_64H_FLOAT2INT:
		case ENC_FCVTMU_32S_FLOAT2INT:
		case ENC_FCVTMU_64S_FLOAT2INT:
		case ENC_FCVTMU_32D_FLOAT2INT:
		case ENC_FCVTMU_64D_FLOAT2INT:
		case ENC_FCVTNS_32H_FLOAT2INT:
		case ENC_FCVTNS_64H_FLOAT2INT:
		case ENC_FCVTNS_32S_FLOAT2INT:
		case ENC_FCVTNS_64S_FLOAT2INT:
		case ENC_FCVTNS_32D_FLOAT2INT:
		case ENC_FCVTNS_64D_FLOAT2INT:
		case ENC_FCVTNU_32H_FLOAT2INT:
		case ENC_FCVTNU_64H_FLOAT2INT:
		case ENC_FCVTNU_32S_FLOAT2INT:
		case ENC_FCVTNU_64S_FLOAT2INT:
		case ENC_FCVTNU_32D_FLOAT2INT:
		case ENC_FCVTNU_64D_FLOAT2INT:
		case ENC_FCVTPS_32H_FLOAT2INT:
		case ENC_FCVTPS_64H_FLOAT2INT:
		case ENC_FCVTPS_32S_FLOAT2INT:
		case ENC_FCVTPS_64S_FLOAT2INT:
		case ENC_FCVTPS_32D_FLOAT2INT:
		case ENC_FCVTPS_64D_FLOAT2INT:
		case ENC_FCVTPU_32H_FLOAT2INT:
		case ENC_FCVTPU_64H_FLOAT2INT:
		case ENC_FCVTPU_32S_FLOAT2INT:
		case ENC_FCVTPU_64S_FLOAT2INT:
		case ENC_FCVTPU_32D_FLOAT2INT:
		case ENC_FCVTPU_64D_FLOAT2INT:
		case ENC_FCVTZS_32H_FLOAT2INT:
		case ENC_FCVTZS_64H_FLOAT2INT:
		case ENC_FCVTZS_32S_FLOAT2INT:
		case ENC_FCVTZS_64S_FLOAT2INT:
		case ENC_FCVTZS_32D_FLOAT2INT:
		case ENC_FCVTZS_64D_FLOAT2INT:
		case ENC_FCVTZU_32H_FLOAT2INT:
		case ENC_FCVTZU_64H_FLOAT2INT:
		case ENC_FCVTZU_32S_FLOAT2INT:
		case ENC_FCVTZU_64S_FLOAT2INT:
		case ENC_FCVTZU_32D_FLOAT2INT:
		case ENC_FCVTZU_64D_FLOAT2INT:
		case ENC_FJCVTZS_32D_FLOAT2INT:
		case ENC_FMOV_32H_FLOAT2INT:
		case ENC_FMOV_64H_FLOAT2INT:
		case ENC_FMOV_H32_FLOAT2INT:
		case ENC_FMOV_S32_FLOAT2INT:
		case ENC_FMOV_32S_FLOAT2INT:
		case ENC_FMOV_H64_FLOAT2INT:
		case ENC_FMOV_D64_FLOAT2INT:
		case ENC_FMOV_V64I_FLOAT2INT:
		case ENC_FMOV_64D_FLOAT2INT:
		case ENC_FMOV_64VX_FLOAT2INT:
		case ENC_SCVTF_H32_FLOAT2INT:
		case ENC_SCVTF_S32_FLOAT2INT:
		case ENC_SCVTF_D32_FLOAT2INT:
		case ENC_SCVTF_H64_FLOAT2INT:
		case ENC_SCVTF_S64_FLOAT2INT:
		case ENC_SCVTF_D64_FLOAT2INT:
		case ENC_UCVTF_H32_FLOAT2INT:
		case ENC_UCVTF_S32_FLOAT2INT:
		case ENC_UCVTF_D32_FLOAT2INT:
		case ENC_UCVTF_H64_FLOAT2INT:
		case ENC_UCVTF_S64_FLOAT2INT:
		case ENC_UCVTF_D64_FLOAT2INT:
			// sf=x|x|S=x|xxxxx|ftype=xx|x|rmode=xx|opcode=xxx|xxxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->sf = insword>>31;
			ctx->S = (insword>>29)&1;
			ctx->ftype = (insword>>22)&3;
			ctx->rmode = (insword>>19)&3;
			ctx->opcode = (insword>>16)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_CAS_C32_COMSWAP:
		case ENC_CASA_C32_COMSWAP:
		case ENC_CASAL_C32_COMSWAP:
		case ENC_CASL_C32_COMSWAP:
		case ENC_CAS_C64_COMSWAP:
		case ENC_CASA_C64_COMSWAP:
		case ENC_CASAL_C64_COMSWAP:
		case ENC_CASL_C64_COMSWAP:
		case ENC_CASAB_C32_COMSWAP:
		case ENC_CASALB_C32_COMSWAP:
		case ENC_CASB_C32_COMSWAP:
		case ENC_CASLB_C32_COMSWAP:
		case ENC_CASAH_C32_COMSWAP:
		case ENC_CASALH_C32_COMSWAP:
		case ENC_CASH_C32_COMSWAP:
		case ENC_CASLH_C32_COMSWAP:
			// size=xx|xxxxxxx|L=x|x|Rs=xxxxx|o0=x|Rt2=xxxxx|Rn=xxxxx|Rt=xxxxx
			ctx->size = insword>>30;
			ctx->L = (insword>>22)&1;
			ctx->Rs = (insword>>16)&0x1f;
			ctx->o0 = (insword>>15)&1;
			ctx->Rt2 = (insword>>10)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LDAR_LR32_LDSTORD:
		case ENC_LDAR_LR64_LDSTORD:
		case ENC_LDARB_LR32_LDSTORD:
		case ENC_LDARH_LR32_LDSTORD:
		case ENC_LDAXR_LR32_LDSTEXCLR:
		case ENC_LDAXR_LR64_LDSTEXCLR:
		case ENC_LDAXRB_LR32_LDSTEXCLR:
		case ENC_LDAXRH_LR32_LDSTEXCLR:
		case ENC_LDLAR_LR32_LDSTORD:
		case ENC_LDLAR_LR64_LDSTORD:
		case ENC_LDLARB_LR32_LDSTORD:
		case ENC_LDLARH_LR32_LDSTORD:
		case ENC_LDXR_LR32_LDSTEXCLR:
		case ENC_LDXR_LR64_LDSTEXCLR:
		case ENC_LDXRB_LR32_LDSTEXCLR:
		case ENC_LDXRH_LR32_LDSTEXCLR:
		case ENC_STLLR_SL32_LDSTORD:
		case ENC_STLLR_SL64_LDSTORD:
		case ENC_STLLRB_SL32_LDSTORD:
		case ENC_STLLRH_SL32_LDSTORD:
		case ENC_STLR_SL32_LDSTORD:
		case ENC_STLR_SL64_LDSTORD:
		case ENC_STLRB_SL32_LDSTORD:
		case ENC_STLRH_SL32_LDSTORD:
		case ENC_STLXR_SR32_LDSTEXCLR:
		case ENC_STLXR_SR64_LDSTEXCLR:
		case ENC_STLXRB_SR32_LDSTEXCLR:
		case ENC_STLXRH_SR32_LDSTEXCLR:
		case ENC_STXR_SR32_LDSTEXCLR:
		case ENC_STXR_SR64_LDSTEXCLR:
		case ENC_STXRB_SR32_LDSTEXCLR:
		case ENC_STXRH_SR32_LDSTEXCLR:
			// size=xx|xxxxxx|o2=x|L=x|o1=x|Rs=xxxxx|o0=x|Rt2=xxxxx|Rn=xxxxx|Rt=xxxxx
			ctx->size = insword>>30;
			ctx->o2 = (insword>>23)&1;
			ctx->L = (insword>>22)&1;
			ctx->o1 = (insword>>21)&1;
			ctx->Rs = (insword>>16)&0x1f;
			ctx->o0 = (insword>>15)&1;
			ctx->Rt2 = (insword>>10)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LDAPURB_32_LDAPSTL_UNSCALED:
		case ENC_LDAPURH_32_LDAPSTL_UNSCALED:
		case ENC_LDAPURSB_32_LDAPSTL_UNSCALED:
		case ENC_LDAPURSB_64_LDAPSTL_UNSCALED:
		case ENC_LDAPURSH_32_LDAPSTL_UNSCALED:
		case ENC_LDAPURSH_64_LDAPSTL_UNSCALED:
		case ENC_LDAPURSW_64_LDAPSTL_UNSCALED:
		case ENC_LDAPUR_32_LDAPSTL_UNSCALED:
		case ENC_LDAPUR_64_LDAPSTL_UNSCALED:
		case ENC_STLURB_32_LDAPSTL_UNSCALED:
		case ENC_STLURH_32_LDAPSTL_UNSCALED:
		case ENC_STLUR_32_LDAPSTL_UNSCALED:
		case ENC_STLUR_64_LDAPSTL_UNSCALED:
			// size=xx|xxxxxx|opc=xx|x|imm9=xxxxxxxxx|xx|Rn=xxxxx|Rt=xxxxx
			ctx->size = insword>>30;
			ctx->opc = (insword>>22)&3;
			ctx->imm9 = (insword>>12)&0x1ff;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LD64B_64L_MEMOP:
		case ENC_LDADD_32_MEMOP:
		case ENC_LDADDA_32_MEMOP:
		case ENC_LDADDAL_32_MEMOP:
		case ENC_LDADDL_32_MEMOP:
		case ENC_LDADD_64_MEMOP:
		case ENC_LDADDA_64_MEMOP:
		case ENC_LDADDAL_64_MEMOP:
		case ENC_LDADDL_64_MEMOP:
		case ENC_LDADDAB_32_MEMOP:
		case ENC_LDADDALB_32_MEMOP:
		case ENC_LDADDB_32_MEMOP:
		case ENC_LDADDLB_32_MEMOP:
		case ENC_LDADDAH_32_MEMOP:
		case ENC_LDADDALH_32_MEMOP:
		case ENC_LDADDH_32_MEMOP:
		case ENC_LDADDLH_32_MEMOP:
		case ENC_LDAPR_32L_MEMOP:
		case ENC_LDAPR_64L_MEMOP:
		case ENC_LDAPRB_32L_MEMOP:
		case ENC_LDAPRH_32L_MEMOP:
		case ENC_LDCLR_32_MEMOP:
		case ENC_LDCLRA_32_MEMOP:
		case ENC_LDCLRAL_32_MEMOP:
		case ENC_LDCLRL_32_MEMOP:
		case ENC_LDCLR_64_MEMOP:
		case ENC_LDCLRA_64_MEMOP:
		case ENC_LDCLRAL_64_MEMOP:
		case ENC_LDCLRL_64_MEMOP:
		case ENC_LDCLRAB_32_MEMOP:
		case ENC_LDCLRALB_32_MEMOP:
		case ENC_LDCLRB_32_MEMOP:
		case ENC_LDCLRLB_32_MEMOP:
		case ENC_LDCLRAH_32_MEMOP:
		case ENC_LDCLRALH_32_MEMOP:
		case ENC_LDCLRH_32_MEMOP:
		case ENC_LDCLRLH_32_MEMOP:
		case ENC_LDEOR_32_MEMOP:
		case ENC_LDEORA_32_MEMOP:
		case ENC_LDEORAL_32_MEMOP:
		case ENC_LDEORL_32_MEMOP:
		case ENC_LDEOR_64_MEMOP:
		case ENC_LDEORA_64_MEMOP:
		case ENC_LDEORAL_64_MEMOP:
		case ENC_LDEORL_64_MEMOP:
		case ENC_LDEORAB_32_MEMOP:
		case ENC_LDEORALB_32_MEMOP:
		case ENC_LDEORB_32_MEMOP:
		case ENC_LDEORLB_32_MEMOP:
		case ENC_LDEORAH_32_MEMOP:
		case ENC_LDEORALH_32_MEMOP:
		case ENC_LDEORH_32_MEMOP:
		case ENC_LDEORLH_32_MEMOP:
		case ENC_LDSET_32_MEMOP:
		case ENC_LDSETA_32_MEMOP:
		case ENC_LDSETAL_32_MEMOP:
		case ENC_LDSETL_32_MEMOP:
		case ENC_LDSET_64_MEMOP:
		case ENC_LDSETA_64_MEMOP:
		case ENC_LDSETAL_64_MEMOP:
		case ENC_LDSETL_64_MEMOP:
		case ENC_LDSETAB_32_MEMOP:
		case ENC_LDSETALB_32_MEMOP:
		case ENC_LDSETB_32_MEMOP:
		case ENC_LDSETLB_32_MEMOP:
		case ENC_LDSETAH_32_MEMOP:
		case ENC_LDSETALH_32_MEMOP:
		case ENC_LDSETH_32_MEMOP:
		case ENC_LDSETLH_32_MEMOP:
		case ENC_LDSMAX_32_MEMOP:
		case ENC_LDSMAXA_32_MEMOP:
		case ENC_LDSMAXAL_32_MEMOP:
		case ENC_LDSMAXL_32_MEMOP:
		case ENC_LDSMAX_64_MEMOP:
		case ENC_LDSMAXA_64_MEMOP:
		case ENC_LDSMAXAL_64_MEMOP:
		case ENC_LDSMAXL_64_MEMOP:
		case ENC_LDSMAXAB_32_MEMOP:
		case ENC_LDSMAXALB_32_MEMOP:
		case ENC_LDSMAXB_32_MEMOP:
		case ENC_LDSMAXLB_32_MEMOP:
		case ENC_LDSMAXAH_32_MEMOP:
		case ENC_LDSMAXALH_32_MEMOP:
		case ENC_LDSMAXH_32_MEMOP:
		case ENC_LDSMAXLH_32_MEMOP:
		case ENC_LDSMIN_32_MEMOP:
		case ENC_LDSMINA_32_MEMOP:
		case ENC_LDSMINAL_32_MEMOP:
		case ENC_LDSMINL_32_MEMOP:
		case ENC_LDSMIN_64_MEMOP:
		case ENC_LDSMINA_64_MEMOP:
		case ENC_LDSMINAL_64_MEMOP:
		case ENC_LDSMINL_64_MEMOP:
		case ENC_LDSMINAB_32_MEMOP:
		case ENC_LDSMINALB_32_MEMOP:
		case ENC_LDSMINB_32_MEMOP:
		case ENC_LDSMINLB_32_MEMOP:
		case ENC_LDSMINAH_32_MEMOP:
		case ENC_LDSMINALH_32_MEMOP:
		case ENC_LDSMINH_32_MEMOP:
		case ENC_LDSMINLH_32_MEMOP:
		case ENC_LDUMAX_32_MEMOP:
		case ENC_LDUMAXA_32_MEMOP:
		case ENC_LDUMAXAL_32_MEMOP:
		case ENC_LDUMAXL_32_MEMOP:
		case ENC_LDUMAX_64_MEMOP:
		case ENC_LDUMAXA_64_MEMOP:
		case ENC_LDUMAXAL_64_MEMOP:
		case ENC_LDUMAXL_64_MEMOP:
		case ENC_LDUMAXAB_32_MEMOP:
		case ENC_LDUMAXALB_32_MEMOP:
		case ENC_LDUMAXB_32_MEMOP:
		case ENC_LDUMAXLB_32_MEMOP:
		case ENC_LDUMAXAH_32_MEMOP:
		case ENC_LDUMAXALH_32_MEMOP:
		case ENC_LDUMAXH_32_MEMOP:
		case ENC_LDUMAXLH_32_MEMOP:
		case ENC_LDUMIN_32_MEMOP:
		case ENC_LDUMINA_32_MEMOP:
		case ENC_LDUMINAL_32_MEMOP:
		case ENC_LDUMINL_32_MEMOP:
		case ENC_LDUMIN_64_MEMOP:
		case ENC_LDUMINA_64_MEMOP:
		case ENC_LDUMINAL_64_MEMOP:
		case ENC_LDUMINL_64_MEMOP:
		case ENC_LDUMINAB_32_MEMOP:
		case ENC_LDUMINALB_32_MEMOP:
		case ENC_LDUMINB_32_MEMOP:
		case ENC_LDUMINLB_32_MEMOP:
		case ENC_LDUMINAH_32_MEMOP:
		case ENC_LDUMINALH_32_MEMOP:
		case ENC_LDUMINH_32_MEMOP:
		case ENC_LDUMINLH_32_MEMOP:
		case ENC_ST64B_64L_MEMOP:
		case ENC_ST64BV_64_MEMOP:
		case ENC_ST64BV0_64_MEMOP:
		case ENC_STADDB_LDADDB_32_MEMOP:
		case ENC_STADDLB_LDADDLB_32_MEMOP:
		case ENC_STADDH_LDADDH_32_MEMOP:
		case ENC_STADDLH_LDADDLH_32_MEMOP:
		case ENC_STADD_LDADD_32_MEMOP:
		case ENC_STADDL_LDADDL_32_MEMOP:
		case ENC_STADD_LDADD_64_MEMOP:
		case ENC_STADDL_LDADDL_64_MEMOP:
		case ENC_STCLRB_LDCLRB_32_MEMOP:
		case ENC_STCLRLB_LDCLRLB_32_MEMOP:
		case ENC_STCLRH_LDCLRH_32_MEMOP:
		case ENC_STCLRLH_LDCLRLH_32_MEMOP:
		case ENC_STCLR_LDCLR_32_MEMOP:
		case ENC_STCLRL_LDCLRL_32_MEMOP:
		case ENC_STCLR_LDCLR_64_MEMOP:
		case ENC_STCLRL_LDCLRL_64_MEMOP:
		case ENC_STEORB_LDEORB_32_MEMOP:
		case ENC_STEORLB_LDEORLB_32_MEMOP:
		case ENC_STEORH_LDEORH_32_MEMOP:
		case ENC_STEORLH_LDEORLH_32_MEMOP:
		case ENC_STEOR_LDEOR_32_MEMOP:
		case ENC_STEORL_LDEORL_32_MEMOP:
		case ENC_STEOR_LDEOR_64_MEMOP:
		case ENC_STEORL_LDEORL_64_MEMOP:
		case ENC_STSETB_LDSETB_32_MEMOP:
		case ENC_STSETLB_LDSETLB_32_MEMOP:
		case ENC_STSETH_LDSETH_32_MEMOP:
		case ENC_STSETLH_LDSETLH_32_MEMOP:
		case ENC_STSET_LDSET_32_MEMOP:
		case ENC_STSETL_LDSETL_32_MEMOP:
		case ENC_STSET_LDSET_64_MEMOP:
		case ENC_STSETL_LDSETL_64_MEMOP:
		case ENC_STSMAXB_LDSMAXB_32_MEMOP:
		case ENC_STSMAXLB_LDSMAXLB_32_MEMOP:
		case ENC_STSMAXH_LDSMAXH_32_MEMOP:
		case ENC_STSMAXLH_LDSMAXLH_32_MEMOP:
		case ENC_STSMAX_LDSMAX_32_MEMOP:
		case ENC_STSMAXL_LDSMAXL_32_MEMOP:
		case ENC_STSMAX_LDSMAX_64_MEMOP:
		case ENC_STSMAXL_LDSMAXL_64_MEMOP:
		case ENC_STSMINB_LDSMINB_32_MEMOP:
		case ENC_STSMINLB_LDSMINLB_32_MEMOP:
		case ENC_STSMINH_LDSMINH_32_MEMOP:
		case ENC_STSMINLH_LDSMINLH_32_MEMOP:
		case ENC_STSMIN_LDSMIN_32_MEMOP:
		case ENC_STSMINL_LDSMINL_32_MEMOP:
		case ENC_STSMIN_LDSMIN_64_MEMOP:
		case ENC_STSMINL_LDSMINL_64_MEMOP:
		case ENC_STUMAXB_LDUMAXB_32_MEMOP:
		case ENC_STUMAXLB_LDUMAXLB_32_MEMOP:
		case ENC_STUMAXH_LDUMAXH_32_MEMOP:
		case ENC_STUMAXLH_LDUMAXLH_32_MEMOP:
		case ENC_STUMAX_LDUMAX_32_MEMOP:
		case ENC_STUMAXL_LDUMAXL_32_MEMOP:
		case ENC_STUMAX_LDUMAX_64_MEMOP:
		case ENC_STUMAXL_LDUMAXL_64_MEMOP:
		case ENC_STUMINB_LDUMINB_32_MEMOP:
		case ENC_STUMINLB_LDUMINLB_32_MEMOP:
		case ENC_STUMINH_LDUMINH_32_MEMOP:
		case ENC_STUMINLH_LDUMINLH_32_MEMOP:
		case ENC_STUMIN_LDUMIN_32_MEMOP:
		case ENC_STUMINL_LDUMINL_32_MEMOP:
		case ENC_STUMIN_LDUMIN_64_MEMOP:
		case ENC_STUMINL_LDUMINL_64_MEMOP:
		case ENC_SWP_32_MEMOP:
		case ENC_SWPA_32_MEMOP:
		case ENC_SWPAL_32_MEMOP:
		case ENC_SWPL_32_MEMOP:
		case ENC_SWP_64_MEMOP:
		case ENC_SWPA_64_MEMOP:
		case ENC_SWPAL_64_MEMOP:
		case ENC_SWPL_64_MEMOP:
		case ENC_SWPAB_32_MEMOP:
		case ENC_SWPALB_32_MEMOP:
		case ENC_SWPB_32_MEMOP:
		case ENC_SWPLB_32_MEMOP:
		case ENC_SWPAH_32_MEMOP:
		case ENC_SWPALH_32_MEMOP:
		case ENC_SWPH_32_MEMOP:
		case ENC_SWPLH_32_MEMOP:
			// size=xx|xxx|V=x|xx|A=x|R=x|x|Rs=xxxxx|o3=x|opc=xxx|xx|Rn=xxxxx|Rt=xxxxx
			ctx->size = insword>>30;
			ctx->V = (insword>>26)&1;
			ctx->A = (insword>>23)&1;
			ctx->R = (insword>>22)&1;
			ctx->Rs = (insword>>16)&0x1f;
			ctx->o3 = (insword>>15)&1;
			ctx->opc = (insword>>12)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LDRAA_64_LDST_PAC:
		case ENC_LDRAA_64W_LDST_PAC:
		case ENC_LDRAB_64_LDST_PAC:
		case ENC_LDRAB_64W_LDST_PAC:
			// size=xx|xxx|V=x|xx|M=x|S=x|x|imm9=xxxxxxxxx|W=x|x|Rn=xxxxx|Rt=xxxxx
			ctx->size = insword>>30;
			ctx->V = (insword>>26)&1;
			ctx->M = (insword>>23)&1;
			ctx->S = (insword>>22)&1;
			ctx->imm9 = (insword>>12)&0x1ff;
			ctx->W = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LDRB_32_LDST_POS:
		case ENC_LDRH_32_LDST_POS:
		case ENC_LDRSB_32_LDST_POS:
		case ENC_LDRSB_64_LDST_POS:
		case ENC_LDRSH_32_LDST_POS:
		case ENC_LDRSH_64_LDST_POS:
		case ENC_LDRSW_64_LDST_POS:
		case ENC_LDR_B_LDST_POS:
		case ENC_LDR_H_LDST_POS:
		case ENC_LDR_S_LDST_POS:
		case ENC_LDR_D_LDST_POS:
		case ENC_LDR_Q_LDST_POS:
		case ENC_LDR_32_LDST_POS:
		case ENC_LDR_64_LDST_POS:
		case ENC_PRFM_P_LDST_POS:
		case ENC_STRB_32_LDST_POS:
		case ENC_STRH_32_LDST_POS:
		case ENC_STR_B_LDST_POS:
		case ENC_STR_H_LDST_POS:
		case ENC_STR_S_LDST_POS:
		case ENC_STR_D_LDST_POS:
		case ENC_STR_Q_LDST_POS:
		case ENC_STR_32_LDST_POS:
		case ENC_STR_64_LDST_POS:
			// size=xx|xxx|V=x|xx|opc=xx|imm12=xxxxxxxxxxxx|Rn=xxxxx|Rt=xxxxx
			ctx->size = insword>>30;
			ctx->V = (insword>>26)&1;
			ctx->opc = (insword>>22)&3;
			ctx->imm12 = (insword>>10)&0xfff;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LDRB_32B_LDST_REGOFF:
		case ENC_LDRB_32BL_LDST_REGOFF:
		case ENC_LDRH_32_LDST_REGOFF:
		case ENC_LDRSB_32B_LDST_REGOFF:
		case ENC_LDRSB_32BL_LDST_REGOFF:
		case ENC_LDRSB_64B_LDST_REGOFF:
		case ENC_LDRSB_64BL_LDST_REGOFF:
		case ENC_LDRSH_32_LDST_REGOFF:
		case ENC_LDRSH_64_LDST_REGOFF:
		case ENC_LDRSW_64_LDST_REGOFF:
		case ENC_LDR_B_LDST_REGOFF:
		case ENC_LDR_BL_LDST_REGOFF:
		case ENC_LDR_H_LDST_REGOFF:
		case ENC_LDR_S_LDST_REGOFF:
		case ENC_LDR_D_LDST_REGOFF:
		case ENC_LDR_Q_LDST_REGOFF:
		case ENC_LDR_32_LDST_REGOFF:
		case ENC_LDR_64_LDST_REGOFF:
		case ENC_PRFM_P_LDST_REGOFF:
		case ENC_STRB_32B_LDST_REGOFF:
		case ENC_STRB_32BL_LDST_REGOFF:
		case ENC_STRH_32_LDST_REGOFF:
		case ENC_STR_B_LDST_REGOFF:
		case ENC_STR_BL_LDST_REGOFF:
		case ENC_STR_H_LDST_REGOFF:
		case ENC_STR_S_LDST_REGOFF:
		case ENC_STR_D_LDST_REGOFF:
		case ENC_STR_Q_LDST_REGOFF:
		case ENC_STR_32_LDST_REGOFF:
		case ENC_STR_64_LDST_REGOFF:
			// size=xx|xxx|V=x|xx|opc=xx|x|Rm=xxxxx|option=xxx|S=x|xx|Rn=xxxxx|Rt=xxxxx
			ctx->size = insword>>30;
			ctx->V = (insword>>26)&1;
			ctx->opc = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->option = (insword>>13)&7;
			ctx->S = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LDRB_32_LDST_IMMPOST:
		case ENC_LDRB_32_LDST_IMMPRE:
		case ENC_LDRH_32_LDST_IMMPOST:
		case ENC_LDRH_32_LDST_IMMPRE:
		case ENC_LDRSB_32_LDST_IMMPOST:
		case ENC_LDRSB_64_LDST_IMMPOST:
		case ENC_LDRSB_32_LDST_IMMPRE:
		case ENC_LDRSB_64_LDST_IMMPRE:
		case ENC_LDRSH_32_LDST_IMMPOST:
		case ENC_LDRSH_64_LDST_IMMPOST:
		case ENC_LDRSH_32_LDST_IMMPRE:
		case ENC_LDRSH_64_LDST_IMMPRE:
		case ENC_LDRSW_64_LDST_IMMPOST:
		case ENC_LDRSW_64_LDST_IMMPRE:
		case ENC_LDR_B_LDST_IMMPOST:
		case ENC_LDR_H_LDST_IMMPOST:
		case ENC_LDR_S_LDST_IMMPOST:
		case ENC_LDR_D_LDST_IMMPOST:
		case ENC_LDR_Q_LDST_IMMPOST:
		case ENC_LDR_B_LDST_IMMPRE:
		case ENC_LDR_H_LDST_IMMPRE:
		case ENC_LDR_S_LDST_IMMPRE:
		case ENC_LDR_D_LDST_IMMPRE:
		case ENC_LDR_Q_LDST_IMMPRE:
		case ENC_LDR_32_LDST_IMMPOST:
		case ENC_LDR_64_LDST_IMMPOST:
		case ENC_LDR_32_LDST_IMMPRE:
		case ENC_LDR_64_LDST_IMMPRE:
		case ENC_LDTR_32_LDST_UNPRIV:
		case ENC_LDTR_64_LDST_UNPRIV:
		case ENC_LDTRB_32_LDST_UNPRIV:
		case ENC_LDTRH_32_LDST_UNPRIV:
		case ENC_LDTRSB_32_LDST_UNPRIV:
		case ENC_LDTRSB_64_LDST_UNPRIV:
		case ENC_LDTRSH_32_LDST_UNPRIV:
		case ENC_LDTRSH_64_LDST_UNPRIV:
		case ENC_LDTRSW_64_LDST_UNPRIV:
		case ENC_LDURB_32_LDST_UNSCALED:
		case ENC_LDURH_32_LDST_UNSCALED:
		case ENC_LDURSB_32_LDST_UNSCALED:
		case ENC_LDURSB_64_LDST_UNSCALED:
		case ENC_LDURSH_32_LDST_UNSCALED:
		case ENC_LDURSH_64_LDST_UNSCALED:
		case ENC_LDURSW_64_LDST_UNSCALED:
		case ENC_LDUR_B_LDST_UNSCALED:
		case ENC_LDUR_H_LDST_UNSCALED:
		case ENC_LDUR_S_LDST_UNSCALED:
		case ENC_LDUR_D_LDST_UNSCALED:
		case ENC_LDUR_Q_LDST_UNSCALED:
		case ENC_LDUR_32_LDST_UNSCALED:
		case ENC_LDUR_64_LDST_UNSCALED:
		case ENC_PRFUM_P_LDST_UNSCALED:
		case ENC_STRB_32_LDST_IMMPOST:
		case ENC_STRB_32_LDST_IMMPRE:
		case ENC_STRH_32_LDST_IMMPOST:
		case ENC_STRH_32_LDST_IMMPRE:
		case ENC_STR_B_LDST_IMMPOST:
		case ENC_STR_H_LDST_IMMPOST:
		case ENC_STR_S_LDST_IMMPOST:
		case ENC_STR_D_LDST_IMMPOST:
		case ENC_STR_Q_LDST_IMMPOST:
		case ENC_STR_B_LDST_IMMPRE:
		case ENC_STR_H_LDST_IMMPRE:
		case ENC_STR_S_LDST_IMMPRE:
		case ENC_STR_D_LDST_IMMPRE:
		case ENC_STR_Q_LDST_IMMPRE:
		case ENC_STR_32_LDST_IMMPOST:
		case ENC_STR_64_LDST_IMMPOST:
		case ENC_STR_32_LDST_IMMPRE:
		case ENC_STR_64_LDST_IMMPRE:
		case ENC_STTR_32_LDST_UNPRIV:
		case ENC_STTR_64_LDST_UNPRIV:
		case ENC_STTRB_32_LDST_UNPRIV:
		case ENC_STTRH_32_LDST_UNPRIV:
		case ENC_STURB_32_LDST_UNSCALED:
		case ENC_STURH_32_LDST_UNSCALED:
		case ENC_STUR_B_LDST_UNSCALED:
		case ENC_STUR_H_LDST_UNSCALED:
		case ENC_STUR_S_LDST_UNSCALED:
		case ENC_STUR_D_LDST_UNSCALED:
		case ENC_STUR_Q_LDST_UNSCALED:
		case ENC_STUR_32_LDST_UNSCALED:
		case ENC_STUR_64_LDST_UNSCALED:
			// size=xx|xxx|V=x|xx|opc=xx|x|imm9=xxxxxxxxx|xx|Rn=xxxxx|Rt=xxxxx
			ctx->size = insword>>30;
			ctx->V = (insword>>26)&1;
			ctx->opc = (insword>>22)&3;
			ctx->imm9 = (insword>>12)&0x1ff;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_ZERO_ZA_I_:
			// xxxxxxxxxxxxxxxxxxxxxx|xx|imm8=xxxxxxxx
			ctx->imm8 = insword&0xff;
			break;
		case ENC_WFET_ONLY_SYSTEMINSTRSWITHREG:
		case ENC_WFIT_ONLY_SYSTEMINSTRSWITHREG:
			// xxxxxxxxxxxxxxxxxxxx|CRm=xxxx|op2=xxx|Rd=xxxxx
			ctx->CRm = (insword>>8)&15;
			ctx->op2 = (insword>>5)&7;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_DSB_BON_BARRIERS:
			// xxxxxxxxxxxxxxxxxxxx|imm2=xx|xx|op2<2>=x|op2<1:0>=xx|Rt=xxxxx
			ctx->imm2 = (insword>>10)&3;
			ctx->op2 = (insword>>7)&1;
			ctx->op2 = (insword>>5)&3;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_SHA512SU0_VV2_CRYPTOSHA512_2:
		case ENC_SM4E_VV4_CRYPTOSHA512_2:
			// xxxxxxxxxxxxxxxxxxxx|opcode=xx|Rn=xxxxx|Rd=xxxxx
			ctx->opcode = (insword>>10)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_UDF_ONLY_PERM_UNDEF:
			// xxxxxxxxxxxxxxxx|imm16=xxxxxxxxxxxxxxxx
			ctx->imm16 = insword&0xffff;
			break;
		case ENC_PUNPKHI_P_P_:
		case ENC_PUNPKLO_P_P_:
			// xxxxxxxxxxxxxxx|H=x|xxxxxx|x|Pn=xxxx|x|Pd=xxxx
			ctx->H = (insword>>16)&1;
			ctx->Pn = (insword>>5)&15;
			ctx->Pd = insword&15;
			break;
		case ENC_MOV_DUPM_Z_I_:
		case ENC_DUPM_Z_I_:
			// xxxxxxxxxxxxxx|imm13=xxxxxxxxxxxxx|Zd=xxxxx
			ctx->imm13 = (insword>>5)&0x1fff;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_LD1Q_ZA_P_RRR_:
		case ENC_ST1Q_ZA_P_RRR_:
			// xxxxxxxxxxx|Rm=xxxxx|V=x|Rs=xx|Pg=xxx|Rn=xxxxx|x|ZAt=xxxx
			ctx->Rm = (insword>>16)&0x1f;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->ZAt = insword&15;
			break;
		case ENC_XAR_VVV2_CRYPTO3_IMM6:
			// xxxxxxxxxxx|Rm=xxxxx|imm6=xxxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->Rm = (insword>>16)&0x1f;
			ctx->imm6 = (insword>>10)&0x3f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SM3TT1A_VVV4_CRYPTO3_IMM2:
		case ENC_SM3TT1B_VVV4_CRYPTO3_IMM2:
		case ENC_SM3TT2A_VVV4_CRYPTO3_IMM2:
		case ENC_SM3TT2B_VVV_CRYPTO3_IMM2:
			// xxxxxxxxxxx|Rm=xxxxx|xx|imm2=xx|opcode=xx|Rn=xxxxx|Rd=xxxxx
			ctx->Rm = (insword>>16)&0x1f;
			ctx->imm2 = (insword>>12)&3;
			ctx->opcode = (insword>>10)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_RAX1_VVV2_CRYPTOSHA512_3:
		case ENC_SHA512H2_QQV_CRYPTOSHA512_3:
		case ENC_SHA512H_QQV_CRYPTOSHA512_3:
		case ENC_SHA512SU1_VVV2_CRYPTOSHA512_3:
		case ENC_SM3PARTW1_VVV4_CRYPTOSHA512_3:
		case ENC_SM3PARTW2_VVV4_CRYPTOSHA512_3:
		case ENC_SM4EKEY_VVV4_CRYPTOSHA512_3:
			// xxxxxxxxxxx|Rm=xxxxx|x|O=x|xx|opcode=xx|Rn=xxxxx|Rd=xxxxx
			ctx->Rm = (insword>>16)&0x1f;
			ctx->O = (insword>>14)&1;
			ctx->opcode = (insword>>10)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_PRFB_I_P_BZ_D_64_SCALED:
		case ENC_PRFD_I_P_BZ_D_64_SCALED:
		case ENC_PRFH_I_P_BZ_D_64_SCALED:
		case ENC_PRFW_I_P_BZ_D_64_SCALED:
			// xxxxxxxxxxx|Zm=xxxxx|x|msz=xx|Pg=xxx|Rn=xxxxx|x|prfop=xxxx
			ctx->Zm = (insword>>16)&0x1f;
			ctx->msz = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->prfop = insword&15;
			break;
		case ENC_EXT_Z_ZI_DES:
			// xxxxxxxxxxx|imm8h=xxxxx|xxx|imm8l=xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->imm8h = (insword>>16)&0x1f;
			ctx->imm8l = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_EXT_Z_ZI_CON:
			// xxxxxxxxxxx|imm8h=xxxxx|xxx|imm8l=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->imm8h = (insword>>16)&0x1f;
			ctx->imm8l = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_AT_SYS_CR_SYSTEMINSTRS:
		case ENC_AUTIA1716_HI_HINTS:
		case ENC_AUTIASP_HI_HINTS:
		case ENC_AUTIAZ_HI_HINTS:
		case ENC_AUTIB1716_HI_HINTS:
		case ENC_AUTIBSP_HI_HINTS:
		case ENC_AUTIBZ_HI_HINTS:
		case ENC_AXFLAG_M_PSTATE:
		case ENC_BTI_HB_HINTS:
		case ENC_CFP_SYS_CR_SYSTEMINSTRS:
		case ENC_CLREX_BN_BARRIERS:
		case ENC_CPP_SYS_CR_SYSTEMINSTRS:
		case ENC_CSDB_HI_HINTS:
		case ENC_DC_SYS_CR_SYSTEMINSTRS:
		case ENC_DGH_HI_HINTS:
		case ENC_DVP_SYS_CR_SYSTEMINSTRS:
		case ENC_ESB_HI_HINTS:
		case ENC_HINT_HM_HINTS:
		case ENC_IC_SYS_CR_SYSTEMINSTRS:
		case ENC_MSR_SI_PSTATE:
		case ENC_NOP_HI_HINTS:
		case ENC_PACIA1716_HI_HINTS:
		case ENC_PACIASP_HI_HINTS:
		case ENC_PACIAZ_HI_HINTS:
		case ENC_PACIB1716_HI_HINTS:
		case ENC_PACIBSP_HI_HINTS:
		case ENC_PACIBZ_HI_HINTS:
		case ENC_PSB_HC_HINTS:
		case ENC_SEV_HI_HINTS:
		case ENC_SEVL_HI_HINTS:
		case ENC_SMSTART_MSR_SI_PSTATE:
		case ENC_SMSTOP_MSR_SI_PSTATE:
		case ENC_SYS_CR_SYSTEMINSTRS:
		case ENC_SYSL_RC_SYSTEMINSTRS:
		case ENC_TCOMMIT_ONLY_BARRIERS:
		case ENC_TLBI_SYS_CR_SYSTEMINSTRS:
		case ENC_TSB_HC_HINTS:
		case ENC_TSTART_BR_SYSTEMRESULT:
		case ENC_TTEST_BR_SYSTEMRESULT:
		case ENC_WFE_HI_HINTS:
		case ENC_WFI_HI_HINTS:
		case ENC_XAFLAG_M_PSTATE:
		case ENC_XPACLRI_HI_HINTS:
		case ENC_YIELD_HI_HINTS:
			// xxxxxxxxxx|L=x|op0=xx|op1=xxx|CRn=xxxx|CRm=xxxx|op2=xxx|Rt=xxxxx
			ctx->L = (insword>>21)&1;
			ctx->op0 = (insword>>19)&3;
			ctx->op1 = (insword>>16)&7;
			ctx->CRn = (insword>>12)&15;
			ctx->CRm = (insword>>8)&15;
			ctx->op2 = (insword>>5)&7;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_DMB_BO_BARRIERS:
		case ENC_DSB_BO_BARRIERS:
		case ENC_ISB_BI_BARRIERS:
		case ENC_PSSBB_DSB_BO_BARRIERS:
		case ENC_SB_ONLY_BARRIERS:
		case ENC_SSBB_DSB_BO_BARRIERS:
			// xxxxxxxxxx|L=x|op0=xx|op1=xxx|CRn=xxxx|CRm=xxxx|op2[2]=x|opc=xx|Rt=xxxxx
			ctx->L = (insword>>21)&1;
			ctx->op0 = (insword>>19)&3;
			ctx->op1 = (insword>>16)&7;
			ctx->CRn = (insword>>12)&15;
			ctx->CRm = (insword>>8)&15;
			ctx->op2 = (insword>>7)&1;
			ctx->opc = (insword>>5)&3;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_MRS_RS_SYSTEMMOVE:
		case ENC_MSR_SR_SYSTEMMOVE:
			// xxxxxxxxxx|L=x|op0[1]=x|o0=x|op1=xxx|CRn=xxxx|CRm=xxxx|op2=xxx|Rt=xxxxx
			ctx->L = (insword>>21)&1;
			ctx->op0 = (insword>>20)&1;
			ctx->o0 = (insword>>19)&1;
			ctx->op1 = (insword>>16)&7;
			ctx->CRn = (insword>>12)&15;
			ctx->CRm = (insword>>8)&15;
			ctx->op2 = (insword>>5)&7;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_CFINV_M_PSTATE:
			// xxxxxxxxxx|L=x|op0[1]=x|op0[0]=x|op1=xxx|CRn=xxxx|CRm=xxxx|op2=xxx|Rt=xxxxx
			ctx->L = (insword>>21)&1;
			ctx->op0 = (insword>>20)&1;
			ctx->op0 = (insword>>19)&1;
			ctx->op1 = (insword>>16)&7;
			ctx->CRn = (insword>>12)&15;
			ctx->CRm = (insword>>8)&15;
			ctx->op2 = (insword>>5)&7;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_PRFB_I_P_BI_S:
		case ENC_PRFD_I_P_BI_S:
		case ENC_PRFH_I_P_BI_S:
		case ENC_PRFW_I_P_BI_S:
			// xxxxxxxxxx|imm6=xxxxxx|x|msz=xx|Pg=xxx|Rn=xxxxx|x|prfop=xxxx
			ctx->imm6 = (insword>>16)&0x3f;
			ctx->msz = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->prfop = insword&15;
			break;
		case ENC_LDR_Z_BI_:
		case ENC_STR_Z_BI_:
			// xxxxxxxxxx|imm9h=xxxxxx|xxx|imm9l=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->imm9h = (insword>>16)&0x3f;
			ctx->imm9l = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LDR_P_BI_:
		case ENC_STR_P_BI_:
			// xxxxxxxxxx|imm9h=xxxxxx|xxx|imm9l=xxx|Rn=xxxxx|x|Pt=xxxx
			ctx->imm9h = (insword>>16)&0x3f;
			ctx->imm9l = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Pt = insword&15;
			break;
		case ENC_LDR_ZA_RI_:
		case ENC_STR_ZA_RI_:
			// xxxxxxxxxx|op=x|xxxxxx|Rv=xx|xxx|Rn=xxxxx|x|imm4=xxxx
			ctx->op = (insword>>21)&1;
			ctx->Rv = (insword>>13)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->imm4 = insword&15;
			break;
		case ENC_BCAX_VVV16_CRYPTO4:
		case ENC_EOR3_VVV16_CRYPTO4:
		case ENC_SM3SS1_VVV4_CRYPTO4:
			// xxxxxxxxx|Op0=xx|Rm=xxxxx|x|Ra=xxxxx|Rn=xxxxx|Rd=xxxxx
			ctx->Op0 = (insword>>21)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Ra = (insword>>10)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_BRKN_P_P_PP_:
		case ENC_BRKNS_P_P_PP_:
			// xxxxxxxxx|S=x|xxxxxxxx|Pg=xxxx|x|Pn=xxxx|x|Pdm=xxxx
			ctx->S = (insword>>22)&1;
			ctx->Pg = (insword>>10)&15;
			ctx->Pn = (insword>>5)&15;
			ctx->Pdm = insword&15;
			break;
		case ENC_BFMLALB_Z_ZZZ_:
		case ENC_BFMLALT_Z_ZZZ_:
		case ENC_FMLALB_Z_ZZZ_:
		case ENC_FMLALT_Z_ZZZ_:
		case ENC_FMLSLB_Z_ZZZ_:
		case ENC_FMLSLT_Z_ZZZ_:
			// xxxxxxxxx|o2=x|x|Zm=xxxxx|xx|op=x|xx|T=x|Zn=xxxxx|Zda=xxxxx
			ctx->o2 = (insword>>22)&1;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->op = (insword>>13)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_BFMLALB_Z_ZZZI_:
		case ENC_BFMLALT_Z_ZZZI_:
		case ENC_FMLALB_Z_ZZZI_S:
		case ENC_FMLALT_Z_ZZZI_S:
		case ENC_FMLSLB_Z_ZZZI_S:
		case ENC_FMLSLT_Z_ZZZI_S:
			// xxxxxxxxx|o2=x|x|i3h=xx|Zm=xxx|xx|op=x|x|i3l=x|T=x|Zn=xxxxx|Zda=xxxxx
			ctx->o2 = (insword>>22)&1;
			ctx->i3h = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->op = (insword>>13)&1;
			ctx->i3l = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_ADDPL_R_RI_:
		case ENC_ADDVL_R_RI_:
			// xxxxxxxxx|op=x|x|Rn=xxxxx|xxxxx|imm6=xxxxxx|Rd=xxxxx
			ctx->op = (insword>>22)&1;
			ctx->Rn = (insword>>16)&0x1f;
			ctx->imm6 = (insword>>5)&0x3f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_BFDOT_Z_ZZZ_:
			// xxxxxxxxx|op=x|x|Zm=xxxxx|xxxxxx|Zn=xxxxx|Zda=xxxxx
			ctx->op = (insword>>22)&1;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_TRN1_Z_ZZ_Q:
		case ENC_TRN2_Z_ZZ_Q:
		case ENC_UZP1_Z_ZZ_Q:
		case ENC_UZP2_Z_ZZ_Q:
		case ENC_ZIP2_Z_ZZ_Q:
		case ENC_ZIP1_Z_ZZ_Q:
			// xxxxxxxxx|op=x|x|Zm=xxxxx|xxx|xx|H=x|Zn=xxxxx|Zd=xxxxx
			ctx->op = (insword>>22)&1;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->H = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_BFDOT_Z_ZZZI_:
			// xxxxxxxxx|op=x|x|i2=xx|Zm=xxx|xxxxxx|Zn=xxxxx|Zda=xxxxx
			ctx->op = (insword>>22)&1;
			ctx->i2 = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_RDVL_R_I_:
			// xxxxxxxxx|op=x|x|opc2<4:1>=xxxx|opc2<0>=x|xxxxx|imm6=xxxxxx|Rd=xxxxx
			ctx->op = (insword>>22)&1;
			ctx->opc2 = (insword>>17)&15;
			ctx->opc2 = (insword>>16)&1;
			ctx->imm6 = (insword>>5)&0x3f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SSHLLB_Z_ZI_:
		case ENC_SSHLLT_Z_ZI_:
		case ENC_USHLLB_Z_ZI_:
		case ENC_USHLLT_Z_ZI_:
			// xxxxxxxxx|tszh=x|x|tszl=xx|imm3=xxx|xxxx|U=x|T=x|Zn=xxxxx|Zd=xxxxx
			ctx->tszh = (insword>>22)&1;
			ctx->tszl = (insword>>19)&3;
			ctx->imm3 = (insword>>16)&7;
			ctx->U = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_RSHRNB_Z_ZI_:
		case ENC_RSHRNT_Z_ZI_:
		case ENC_SHRNB_Z_ZI_:
		case ENC_SHRNT_Z_ZI_:
		case ENC_SQRSHRNB_Z_ZI_:
		case ENC_SQRSHRNT_Z_ZI_:
		case ENC_SQRSHRUNB_Z_ZI_:
		case ENC_SQRSHRUNT_Z_ZI_:
		case ENC_SQSHRNB_Z_ZI_:
		case ENC_SQSHRNT_Z_ZI_:
		case ENC_SQSHRUNB_Z_ZI_:
		case ENC_SQSHRUNT_Z_ZI_:
		case ENC_UQRSHRNB_Z_ZI_:
		case ENC_UQRSHRNT_Z_ZI_:
		case ENC_UQSHRNB_Z_ZI_:
		case ENC_UQSHRNT_Z_ZI_:
			// xxxxxxxxx|tszh=x|x|tszl=xx|imm3=xxx|xx|op=x|U=x|R=x|T=x|Zn=xxxxx|Zd=xxxxx
			ctx->tszh = (insword>>22)&1;
			ctx->tszl = (insword>>19)&3;
			ctx->imm3 = (insword>>16)&7;
			ctx->op = (insword>>13)&1;
			ctx->U = (insword>>12)&1;
			ctx->R = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SQXTUNB_Z_ZZ_:
		case ENC_SQXTUNT_Z_ZZ_:
			// xxxxxxxxx|tszh=x|x|tszl=xx|xxxxxx|opc=xx|T=x|Zn=xxxxx|Zd=xxxxx
			ctx->tszh = (insword>>22)&1;
			ctx->tszl = (insword>>19)&3;
			ctx->opc = (insword>>11)&3;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SQXTNB_Z_ZZ_:
		case ENC_SQXTNT_Z_ZZ_:
		case ENC_UQXTNB_Z_ZZ_:
		case ENC_UQXTNT_Z_ZZ_:
			// xxxxxxxxx|tszh=x|x|tszl=xx|xxxxxx|x|U=x|T=x|Zn=xxxxx|Zd=xxxxx
			ctx->tszh = (insword>>22)&1;
			ctx->tszl = (insword>>19)&3;
			ctx->U = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_LD1H_Z_P_BZ_S_X32_SCALED:
		case ENC_LD1SH_Z_P_BZ_S_X32_SCALED:
		case ENC_LD1W_Z_P_BZ_S_X32_SCALED:
		case ENC_LDFF1H_Z_P_BZ_S_X32_SCALED:
		case ENC_LDFF1SH_Z_P_BZ_S_X32_SCALED:
		case ENC_LDFF1W_Z_P_BZ_S_X32_SCALED:
			// xxxxxxxxx|xs=x|x|Zm=xxxxx|x|U=x|ff=x|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->xs = (insword>>22)&1;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->U = (insword>>14)&1;
			ctx->ff = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_PRFB_I_P_BZ_S_X32_SCALED:
		case ENC_PRFB_I_P_BZ_D_X32_SCALED:
		case ENC_PRFD_I_P_BZ_S_X32_SCALED:
		case ENC_PRFD_I_P_BZ_D_X32_SCALED:
		case ENC_PRFH_I_P_BZ_S_X32_SCALED:
		case ENC_PRFH_I_P_BZ_D_X32_SCALED:
		case ENC_PRFW_I_P_BZ_S_X32_SCALED:
		case ENC_PRFW_I_P_BZ_D_X32_SCALED:
			// xxxxxxxxx|xs=x|x|Zm=xxxxx|x|msz=xx|Pg=xxx|Rn=xxxxx|x|prfop=xxxx
			ctx->xs = (insword>>22)&1;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->msz = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->prfop = insword&15;
			break;
		case ENC_BRKA_P_P_P_:
		case ENC_BRKAS_P_P_P_Z:
		case ENC_BRKB_P_P_P_:
		case ENC_BRKBS_P_P_P_Z:
			// xxxxxxxx|B=x|S=x|xxxxxxxx|Pg=xxxx|x|Pn=xxxx|M=x|Pd=xxxx
			ctx->B = (insword>>23)&1;
			ctx->S = (insword>>22)&1;
			ctx->Pg = (insword>>10)&15;
			ctx->Pn = (insword>>5)&15;
			ctx->M = (insword>>4)&1;
			ctx->Pd = insword&15;
			break;
		case ENC_DUP_P_P_PI_:
			// xxxxxxxx|i1=x|tszh=x|x|tszl=xxx|Rm=xx|xx|Pg=xxxx|S=x|Pn=xxxx|x|Pd=xxxx
			ctx->i1 = (insword>>23)&1;
			ctx->tszh = (insword>>22)&1;
			ctx->tszl = (insword>>18)&7;
			ctx->Rm = (insword>>16)&3;
			ctx->Pg = (insword>>10)&15;
			ctx->S = (insword>>9)&1;
			ctx->Pn = (insword>>5)&15;
			ctx->Pd = insword&15;
			break;
		case ENC_MOV_DUP_Z_ZI_:
		case ENC_MOV_DUP_Z_ZI_2:
		case ENC_DUP_Z_ZI_:
			// xxxxxxxx|imm2=xx|x|tsz=xxxxx|xxxxxx|Zn=xxxxx|Zd=xxxxx
			ctx->imm2 = (insword>>22)&3;
			ctx->tsz = (insword>>16)&0x1f;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_LD1D_ZA_P_RRR_:
		case ENC_ST1D_ZA_P_RRR_:
			// xxxxxxxx|msz=xx|x|Rm=xxxxx|V=x|Rs=xx|Pg=xxx|Rn=xxxxx|x|ZAt=xxx|i1=x
			ctx->msz = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->ZAt = (insword>>1)&7;
			ctx->i1 = insword&1;
			break;
		case ENC_LD1W_ZA_P_RRR_:
		case ENC_ST1W_ZA_P_RRR_:
			// xxxxxxxx|msz=xx|x|Rm=xxxxx|V=x|Rs=xx|Pg=xxx|Rn=xxxxx|x|ZAt=xx|imm2=xx
			ctx->msz = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->ZAt = (insword>>2)&3;
			ctx->imm2 = insword&3;
			break;
		case ENC_LD1H_ZA_P_RRR_:
		case ENC_ST1H_ZA_P_RRR_:
			// xxxxxxxx|msz=xx|x|Rm=xxxxx|V=x|Rs=xx|Pg=xxx|Rn=xxxxx|x|ZAt=x|imm3=xxx
			ctx->msz = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->ZAt = (insword>>3)&1;
			ctx->imm3 = insword&7;
			break;
		case ENC_LD1B_ZA_P_RRR_:
		case ENC_ST1B_ZA_P_RRR_:
			// xxxxxxxx|msz=xx|x|Rm=xxxxx|V=x|Rs=xx|Pg=xxx|Rn=xxxxx|x|imm4=xxxx
			ctx->msz = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->imm4 = insword&15;
			break;
		case ENC_PFALSE_P_:
		case ENC_RDFFR_P_F_:
			// xxxxxxxx|op=x|S=x|xxxxxxxxxxxx|xxxxxx|Pd=xxxx
			ctx->op = (insword>>23)&1;
			ctx->S = (insword>>22)&1;
			ctx->Pd = insword&15;
			break;
		case ENC_RDFFR_P_P_F_:
		case ENC_RDFFRS_P_P_F_:
			// xxxxxxxx|op=x|S=x|xxxxxxxxxxxx|x|Pg=xxxx|x|Pd=xxxx
			ctx->op = (insword>>23)&1;
			ctx->S = (insword>>22)&1;
			ctx->Pg = (insword>>5)&15;
			ctx->Pd = insword&15;
			break;
		case ENC_PFIRST_P_P_P_:
			// xxxxxxxx|op=x|S=x|xxxxxxxxxxxx|x|Pg=xxxx|x|Pdn=xxxx
			ctx->op = (insword>>23)&1;
			ctx->S = (insword>>22)&1;
			ctx->Pg = (insword>>5)&15;
			ctx->Pdn = insword&15;
			break;
		case ENC_MOVS_ANDS_P_P_PP_Z:
		case ENC_MOVS_ORRS_P_P_PP_Z:
		case ENC_MOV_AND_P_P_PP_Z:
		case ENC_MOV_ORR_P_P_PP_Z:
		case ENC_MOV_SEL_P_P_PP_:
		case ENC_NOTS_EORS_P_P_PP_Z:
		case ENC_NOT_EOR_P_P_PP_Z:
		case ENC_AND_P_P_PP_Z:
		case ENC_ANDS_P_P_PP_Z:
		case ENC_BIC_P_P_PP_Z:
		case ENC_BICS_P_P_PP_Z:
		case ENC_EOR_P_P_PP_Z:
		case ENC_EORS_P_P_PP_Z:
		case ENC_NAND_P_P_PP_Z:
		case ENC_NANDS_P_P_PP_Z:
		case ENC_NOR_P_P_PP_Z:
		case ENC_NORS_P_P_PP_Z:
		case ENC_ORN_P_P_PP_Z:
		case ENC_ORNS_P_P_PP_Z:
		case ENC_ORR_P_P_PP_Z:
		case ENC_ORRS_P_P_PP_Z:
		case ENC_SEL_P_P_PP_:
			// xxxxxxxx|op=x|S=x|xx|Pm=xxxx|xx|Pg=xxxx|o2=x|Pn=xxxx|o3=x|Pd=xxxx
			ctx->op = (insword>>23)&1;
			ctx->S = (insword>>22)&1;
			ctx->Pm = (insword>>16)&15;
			ctx->Pg = (insword>>10)&15;
			ctx->o2 = (insword>>9)&1;
			ctx->Pn = (insword>>5)&15;
			ctx->o3 = (insword>>4)&1;
			ctx->Pd = insword&15;
			break;
		case ENC_BRKPA_P_P_PP_:
		case ENC_BRKPAS_P_P_PP_:
		case ENC_BRKPB_P_P_PP_:
		case ENC_BRKPBS_P_P_PP_:
			// xxxxxxxx|op=x|S=x|xx|Pm=xxxx|xx|Pg=xxxx|x|Pn=xxxx|B=x|Pd=xxxx
			ctx->op = (insword>>23)&1;
			ctx->S = (insword>>22)&1;
			ctx->Pm = (insword>>16)&15;
			ctx->Pg = (insword>>10)&15;
			ctx->Pn = (insword>>5)&15;
			ctx->B = (insword>>4)&1;
			ctx->Pd = insword&15;
			break;
		case ENC_BRK_EX_EXCEPTION:
		case ENC_DCPS1_DC_EXCEPTION:
		case ENC_DCPS2_DC_EXCEPTION:
		case ENC_DCPS3_DC_EXCEPTION:
		case ENC_HLT_EX_EXCEPTION:
		case ENC_HVC_EX_EXCEPTION:
		case ENC_SMC_EX_EXCEPTION:
		case ENC_SVC_EX_EXCEPTION:
		case ENC_TCANCEL_EX_EXCEPTION:
			// xxxxxxxx|opc=xxx|imm16=xxxxxxxxxxxxxxxx|op2=xxx|LL=xx
			ctx->opc = (insword>>21)&7;
			ctx->imm16 = (insword>>5)&0xffff;
			ctx->op2 = (insword>>2)&7;
			ctx->LL = insword&3;
			break;
		case ENC_BIC_AND_Z_ZI_:
		case ENC_EON_EOR_Z_ZI_:
		case ENC_ORN_ORR_Z_ZI_:
		case ENC_AND_Z_ZI_:
		case ENC_EOR_Z_ZI_:
		case ENC_ORR_Z_ZI_:
			// xxxxxxxx|opc=xx|xxxx|imm13=xxxxxxxxxxxxx|Zdn=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->imm13 = (insword>>5)&0x1fff;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_BFCVT_Z_P_Z_S2BF:
		case ENC_BFCVTNT_Z_P_Z_S2BF:
		case ENC_FCVT_Z_P_Z_H2S:
		case ENC_FCVT_Z_P_Z_H2D:
		case ENC_FCVT_Z_P_Z_S2H:
		case ENC_FCVT_Z_P_Z_S2D:
		case ENC_FCVT_Z_P_Z_D2H:
		case ENC_FCVT_Z_P_Z_D2S:
		case ENC_FCVTLT_Z_P_Z_H2S:
		case ENC_FCVTLT_Z_P_Z_S2D:
		case ENC_FCVTNT_Z_P_Z_S2H:
		case ENC_FCVTNT_Z_P_Z_D2S:
		case ENC_FCVTX_Z_P_Z_D2S:
		case ENC_FCVTXNT_Z_P_Z_D2S:
			// xxxxxxxx|opc=xx|xxxx|opc2=xx|xxx|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->opc2 = (insword>>16)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_FCVTZS_Z_P_Z_FP162H:
		case ENC_FCVTZS_Z_P_Z_FP162W:
		case ENC_FCVTZS_Z_P_Z_FP162X:
		case ENC_FCVTZS_Z_P_Z_S2W:
		case ENC_FCVTZS_Z_P_Z_S2X:
		case ENC_FCVTZS_Z_P_Z_D2W:
		case ENC_FCVTZS_Z_P_Z_D2X:
		case ENC_FCVTZU_Z_P_Z_FP162H:
		case ENC_FCVTZU_Z_P_Z_FP162W:
		case ENC_FCVTZU_Z_P_Z_FP162X:
		case ENC_FCVTZU_Z_P_Z_S2W:
		case ENC_FCVTZU_Z_P_Z_S2X:
		case ENC_FCVTZU_Z_P_Z_D2W:
		case ENC_FCVTZU_Z_P_Z_D2X:
		case ENC_SCVTF_Z_P_Z_H2FP16:
		case ENC_SCVTF_Z_P_Z_W2FP16:
		case ENC_SCVTF_Z_P_Z_W2S:
		case ENC_SCVTF_Z_P_Z_W2D:
		case ENC_SCVTF_Z_P_Z_X2FP16:
		case ENC_SCVTF_Z_P_Z_X2S:
		case ENC_SCVTF_Z_P_Z_X2D:
		case ENC_UCVTF_Z_P_Z_H2FP16:
		case ENC_UCVTF_Z_P_Z_W2FP16:
		case ENC_UCVTF_Z_P_Z_W2S:
		case ENC_UCVTF_Z_P_Z_W2D:
		case ENC_UCVTF_Z_P_Z_X2FP16:
		case ENC_UCVTF_Z_P_Z_X2S:
		case ENC_UCVTF_Z_P_Z_X2D:
			// xxxxxxxx|opc=xx|xxx|opc2=xx|int_U=x|xxx|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->opc2 = (insword>>17)&3;
			ctx->int_U = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_FLOGB_Z_P_Z_:
			// xxxxxxxx|opc=xx|xxx|size=xx|U=x|xxx|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->size = (insword>>17)&3;
			ctx->U = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_MOV_ORR_Z_ZZ_:
		case ENC_AND_Z_ZZ_:
		case ENC_BIC_Z_ZZ_:
		case ENC_EOR_Z_ZZ_:
		case ENC_ORR_Z_ZZ_:
			// xxxxxxxx|opc=xx|x|Zm=xxxxx|xxxxxx|Zn=xxxxx|Zd=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_BFMMLA_Z_ZZZ_:
		case ENC_FMMLA_Z_ZZZ_S:
		case ENC_FMMLA_Z_ZZZ_D:
			// xxxxxxxx|opc=xx|x|Zm=xxxxx|xxxxxx|Zn=xxxxx|Zda=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_BCAX_Z_ZZZ_:
		case ENC_BSL1N_Z_ZZZ_:
		case ENC_BSL2N_Z_ZZZ_:
		case ENC_BSL_Z_ZZZ_:
		case ENC_EOR3_Z_ZZZ_:
		case ENC_NBSL_Z_ZZZ_:
			// xxxxxxxx|opc=xx|x|Zm=xxxxx|xxxxx|o2=x|Zk=xxxxx|Zdn=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->o2 = (insword>>10)&1;
			ctx->Zk = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_ADR_Z_AZ_D_S32_SCALED:
		case ENC_ADR_Z_AZ_D_U32_SCALED:
			// xxxxxxxx|opc=xx|x|Zm=xxxxx|xxxx|msz=xx|Zn=xxxxx|Zd=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->msz = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_LDG_64LOFFSET_LDSTTAGS:
		case ENC_LDGM_64BULK_LDSTTAGS:
		case ENC_ST2G_64SPOST_LDSTTAGS:
		case ENC_ST2G_64SPRE_LDSTTAGS:
		case ENC_ST2G_64SOFFSET_LDSTTAGS:
		case ENC_STG_64SPOST_LDSTTAGS:
		case ENC_STG_64SPRE_LDSTTAGS:
		case ENC_STG_64SOFFSET_LDSTTAGS:
		case ENC_STGM_64BULK_LDSTTAGS:
		case ENC_STZ2G_64SPOST_LDSTTAGS:
		case ENC_STZ2G_64SPRE_LDSTTAGS:
		case ENC_STZ2G_64SOFFSET_LDSTTAGS:
		case ENC_STZG_64SPOST_LDSTTAGS:
		case ENC_STZG_64SPRE_LDSTTAGS:
		case ENC_STZG_64SOFFSET_LDSTTAGS:
		case ENC_STZGM_64BULK_LDSTTAGS:
			// xxxxxxxx|opc=xx|x|imm9=xxxxxxxxx|op2=xx|Xn=xxxxx|Xt=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->imm9 = (insword>>12)&0x1ff;
			ctx->op2 = (insword>>10)&3;
			ctx->Xn = (insword>>5)&0x1f;
			ctx->Xt = insword&0x1f;
			break;
		case ENC_MOVPRFX_Z_Z_:
			// xxxxxxxx|opc=xx|x|opc2<4:1>=xxxx|opc2<0>=x|xxxxxx|Zn=xxxxx|Zd=xxxxx
			ctx->opc = (insword>>22)&3;
			ctx->opc2 = (insword>>17)&15;
			ctx->opc2 = (insword>>16)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_INSR_Z_R_:
			// xxxxxxxx|size=xx|xxxxxxxxxxxx|Rm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_MOV_DUP_Z_R_:
		case ENC_DUP_Z_R_:
			// xxxxxxxx|size=xx|xxxxxxxxxxxx|Rn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_INSR_Z_V_:
			// xxxxxxxx|size=xx|xxxxxxxxxxxx|Vm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Vm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_REV_Z_Z_:
			// xxxxxxxx|size=xx|xxxxxxxxxxxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_PNEXT_P_P_P_:
			// xxxxxxxx|size=xx|xxxxxxxxxxxx|x|Pg=xxxx|x|Pdn=xxxx
			ctx->size = (insword>>22)&3;
			ctx->Pg = (insword>>5)&15;
			ctx->Pdn = insword&15;
			break;
		case ENC_REV_P_P_:
			// xxxxxxxx|size=xx|xxxxxxxxxxxx|x|Pn=xxxx|x|Pd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->Pn = (insword>>5)&15;
			ctx->Pd = insword&15;
			break;
		case ENC_AESIMC_Z_Z_:
		case ENC_AESMC_Z_Z_:
			// xxxxxxxx|size=xx|xxxxxxxxxxx|op=x|xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->op = (insword>>10)&1;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_MOV_CPY_Z_P_R_:
		case ENC_CPY_Z_P_R_:
			// xxxxxxxx|size=xx|xxxxxxxxx|Pg=xxx|Rn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_MOV_CPY_Z_P_V_:
		case ENC_CPY_Z_P_V_:
			// xxxxxxxx|size=xx|xxxxxxxxx|Pg=xxx|Vn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Vn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SPLICE_Z_P_ZZ_DES:
			// xxxxxxxx|size=xx|xxxxxxxxx|Pg=xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_COMPACT_Z_P_Z_:
		case ENC_REVD_Z_P_Z_:
		case ENC_SPLICE_Z_P_ZZ_CON:
			// xxxxxxxx|size=xx|xxxxxxxxx|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_CLASTA_R_P_Z_:
		case ENC_CLASTB_R_P_Z_:
			// xxxxxxxx|size=xx|xxxxx|B=x|xxx|Pg=xxx|Zm=xxxxx|Rdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->B = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Rdn = insword&0x1f;
			break;
		case ENC_CLASTA_V_P_Z_:
		case ENC_CLASTB_V_P_Z_:
			// xxxxxxxx|size=xx|xxxxx|B=x|xxx|Pg=xxx|Zm=xxxxx|Vdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->B = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Vdn = insword&0x1f;
			break;
		case ENC_CLASTA_Z_P_ZZ_:
		case ENC_CLASTB_Z_P_ZZ_:
			// xxxxxxxx|size=xx|xxxxx|B=x|xxx|Pg=xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->B = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_LASTA_R_P_Z_:
		case ENC_LASTB_R_P_Z_:
			// xxxxxxxx|size=xx|xxxxx|B=x|xxx|Pg=xxx|Zn=xxxxx|Rd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->B = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_LASTA_V_P_Z_:
		case ENC_LASTB_V_P_Z_:
			// xxxxxxxx|size=xx|xxxxx|B=x|xxx|Pg=xxx|Zn=xxxxx|Vd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->B = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Vd = insword&0x1f;
			break;
		case ENC_MOV_MOVA_ZA_P_RZ_Q:
		case ENC_MOVA_ZA_P_RZ_Q:
			// xxxxxxxx|size=xx|xxxxx|Q=x|V=x|Rs=xx|Pg=xxx|Zn=xxxxx|x|ZAd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->Q = (insword>>16)&1;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->ZAd = insword&15;
			break;
		case ENC_MOV_MOVA_ZA_P_RZ_D:
		case ENC_MOVA_ZA_P_RZ_D:
			// xxxxxxxx|size=xx|xxxxx|Q=x|V=x|Rs=xx|Pg=xxx|Zn=xxxxx|x|ZAd=xxx|i1=x
			ctx->size = (insword>>22)&3;
			ctx->Q = (insword>>16)&1;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->ZAd = (insword>>1)&7;
			ctx->i1 = insword&1;
			break;
		case ENC_MOV_MOVA_ZA_P_RZ_W:
		case ENC_MOVA_ZA_P_RZ_W:
			// xxxxxxxx|size=xx|xxxxx|Q=x|V=x|Rs=xx|Pg=xxx|Zn=xxxxx|x|ZAd=xx|imm2=xx
			ctx->size = (insword>>22)&3;
			ctx->Q = (insword>>16)&1;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->ZAd = (insword>>2)&3;
			ctx->imm2 = insword&3;
			break;
		case ENC_MOV_MOVA_ZA_P_RZ_H:
		case ENC_MOVA_ZA_P_RZ_H:
			// xxxxxxxx|size=xx|xxxxx|Q=x|V=x|Rs=xx|Pg=xxx|Zn=xxxxx|x|ZAd=x|imm3=xxx
			ctx->size = (insword>>22)&3;
			ctx->Q = (insword>>16)&1;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->ZAd = (insword>>3)&1;
			ctx->imm3 = insword&7;
			break;
		case ENC_MOV_MOVA_ZA_P_RZ_B:
		case ENC_MOVA_ZA_P_RZ_B:
			// xxxxxxxx|size=xx|xxxxx|Q=x|V=x|Rs=xx|Pg=xxx|Zn=xxxxx|x|imm4=xxxx
			ctx->size = (insword>>22)&3;
			ctx->Q = (insword>>16)&1;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->imm4 = insword&15;
			break;
		case ENC_MOV_MOVA_Z_P_RZA_Q:
		case ENC_MOVA_Z_P_RZA_Q:
			// xxxxxxxx|size=xx|xxxxx|Q=x|V=x|Rs=xx|Pg=xxx|x|ZAn=xxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Q = (insword>>16)&1;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->ZAn = (insword>>5)&15;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_MOV_MOVA_Z_P_RZA_D:
		case ENC_MOVA_Z_P_RZA_D:
			// xxxxxxxx|size=xx|xxxxx|Q=x|V=x|Rs=xx|Pg=xxx|x|ZAn=xxx|i1=x|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Q = (insword>>16)&1;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->ZAn = (insword>>6)&7;
			ctx->i1 = (insword>>5)&1;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_MOV_MOVA_Z_P_RZA_W:
		case ENC_MOVA_Z_P_RZA_W:
			// xxxxxxxx|size=xx|xxxxx|Q=x|V=x|Rs=xx|Pg=xxx|x|ZAn=xx|imm2=xx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Q = (insword>>16)&1;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->ZAn = (insword>>7)&3;
			ctx->imm2 = (insword>>5)&3;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_MOV_MOVA_Z_P_RZA_H:
		case ENC_MOVA_Z_P_RZA_H:
			// xxxxxxxx|size=xx|xxxxx|Q=x|V=x|Rs=xx|Pg=xxx|x|ZAn=x|imm3=xxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Q = (insword>>16)&1;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->ZAn = (insword>>8)&1;
			ctx->imm3 = (insword>>5)&7;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_MOV_MOVA_Z_P_RZA_B:
		case ENC_MOVA_Z_P_RZA_B:
			// xxxxxxxx|size=xx|xxxxx|Q=x|V=x|Rs=xx|Pg=xxx|x|imm4=xxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Q = (insword>>16)&1;
			ctx->V = (insword>>15)&1;
			ctx->Rs = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->imm4 = (insword>>5)&15;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_PTRUE_P_S_:
		case ENC_PTRUES_P_S_:
			// xxxxxxxx|size=xx|xxxxx|S=x|xxxxxx|pattern=xxxxx|x|Pd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->S = (insword>>16)&1;
			ctx->pattern = (insword>>5)&0x1f;
			ctx->Pd = insword&15;
			break;
		case ENC_SADALP_Z_P_Z_:
		case ENC_UADALP_Z_P_Z_:
			// xxxxxxxx|size=xx|xxxxx|U=x|xxx|Pg=xxx|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->U = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_AESD_Z_ZZ_:
		case ENC_AESE_Z_ZZ_:
		case ENC_SM4E_Z_ZZ_:
			// xxxxxxxx|size=xx|xxxxx|op=x|xxxxx|o2=x|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->op = (insword>>16)&1;
			ctx->o2 = (insword>>10)&1;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_CADD_Z_ZZ_:
		case ENC_SQCADD_Z_ZZ_:
			// xxxxxxxx|size=xx|xxxxx|op=x|xxxxx|rot=x|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->op = (insword>>16)&1;
			ctx->rot = (insword>>10)&1;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_SHA1H_SS_CRYPTOSHA2:
		case ENC_SHA1SU1_VV_CRYPTOSHA2:
		case ENC_SHA256SU0_VV_CRYPTOSHA2:
			// xxxxxxxx|size=xx|xxxxx|opcode=xxxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opcode = (insword>>12)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_AESD_B_CRYPTOAES:
		case ENC_AESE_B_CRYPTOAES:
		case ENC_AESIMC_B_CRYPTOAES:
		case ENC_AESMC_B_CRYPTOAES:
			// xxxxxxxx|size=xx|xxxxx|opcode[4:1]=xxxx|D=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opcode = (insword>>13)&15;
			ctx->D = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCADD_Z_P_ZZ_:
			// xxxxxxxx|size=xx|xxxxx|rot=x|xxx|Pg=xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->rot = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_SQDECP_Z_P_Z_:
		case ENC_SQINCP_Z_P_Z_:
		case ENC_UQDECP_Z_P_Z_:
		case ENC_UQINCP_Z_P_Z_:
			// xxxxxxxx|size=xx|xxxx|D=x|U=x|xxxxx|opc=xx|Pm=xxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->D = (insword>>17)&1;
			ctx->U = (insword>>16)&1;
			ctx->opc = (insword>>9)&3;
			ctx->Pm = (insword>>5)&15;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_SQDECP_R_P_R_SX:
		case ENC_SQDECP_R_P_R_X:
		case ENC_SQINCP_R_P_R_SX:
		case ENC_SQINCP_R_P_R_X:
		case ENC_UQDECP_R_P_R_UW:
		case ENC_UQDECP_R_P_R_X:
		case ENC_UQINCP_R_P_R_UW:
		case ENC_UQINCP_R_P_R_X:
			// xxxxxxxx|size=xx|xxxx|D=x|U=x|xxxxx|sf=x|op=x|Pm=xxxx|Rdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->D = (insword>>17)&1;
			ctx->U = (insword>>16)&1;
			ctx->sf = (insword>>10)&1;
			ctx->op = (insword>>9)&1;
			ctx->Pm = (insword>>5)&15;
			ctx->Rdn = insword&0x1f;
			break;
		case ENC_MUL_Z_P_ZZ_:
		case ENC_SMULH_Z_P_ZZ_:
		case ENC_UMULH_Z_P_ZZ_:
			// xxxxxxxx|size=xx|xxxx|H=x|U=x|xxx|Pg=xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->H = (insword>>17)&1;
			ctx->U = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_SDIV_Z_P_ZZ_:
		case ENC_SDIVR_Z_P_ZZ_:
		case ENC_UDIV_Z_P_ZZ_:
		case ENC_UDIVR_Z_P_ZZ_:
			// xxxxxxxx|size=xx|xxxx|R=x|U=x|xxx|Pg=xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->R = (insword>>17)&1;
			ctx->U = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_SUNPKHI_Z_Z_:
		case ENC_SUNPKLO_Z_Z_:
		case ENC_UUNPKHI_Z_Z_:
		case ENC_UUNPKLO_Z_Z_:
			// xxxxxxxx|size=xx|xxxx|U=x|H=x|xxxxxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->U = (insword>>17)&1;
			ctx->H = (insword>>16)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_FCMEQ_P_P_Z0_:
		case ENC_FCMGT_P_P_Z0_:
		case ENC_FCMGE_P_P_Z0_:
		case ENC_FCMLT_P_P_Z0_:
		case ENC_FCMLE_P_P_Z0_:
		case ENC_FCMNE_P_P_Z0_:
			// xxxxxxxx|size=xx|xxxx|eq=x|lt=x|xxx|Pg=xxx|Zn=xxxxx|ne=x|Pd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->eq = (insword>>17)&1;
			ctx->lt = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->ne = (insword>>4)&1;
			ctx->Pd = insword&15;
			break;
		case ENC_DECP_R_P_R_:
		case ENC_INCP_R_P_R_:
			// xxxxxxxx|size=xx|xxxx|op=x|D=x|xxxxx|opc2=xx|Pm=xxxx|Rdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->op = (insword>>17)&1;
			ctx->D = (insword>>16)&1;
			ctx->opc2 = (insword>>9)&3;
			ctx->Pm = (insword>>5)&15;
			ctx->Rdn = insword&0x1f;
			break;
		case ENC_DECP_Z_P_Z_:
		case ENC_INCP_Z_P_Z_:
			// xxxxxxxx|size=xx|xxxx|op=x|D=x|xxxxx|opc2=xx|Pm=xxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->op = (insword>>17)&1;
			ctx->D = (insword>>16)&1;
			ctx->opc2 = (insword>>9)&3;
			ctx->Pm = (insword>>5)&15;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_SADDV_R_P_Z_:
		case ENC_SMAXV_R_P_Z_:
		case ENC_SMINV_R_P_Z_:
		case ENC_UADDV_R_P_Z_:
		case ENC_UMAXV_R_P_Z_:
		case ENC_UMINV_R_P_Z_:
			// xxxxxxxx|size=xx|xxxx|op=x|U=x|xxx|Pg=xxx|Zn=xxxxx|Vd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->op = (insword>>17)&1;
			ctx->U = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Vd = insword&0x1f;
			break;
		case ENC_FADDA_V_P_Z_:
			// xxxxxxxx|size=xx|xxxx|opc=xx|xxx|Pg=xxx|Zm=xxxxx|Vdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>16)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Vdn = insword&0x1f;
			break;
		case ENC_ANDV_R_P_Z_:
		case ENC_EORV_R_P_Z_:
		case ENC_ORV_R_P_Z_:
			// xxxxxxxx|size=xx|xxxx|opc=xx|xxx|Pg=xxx|Zn=xxxxx|Vd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>16)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Vd = insword&0x1f;
			break;
		case ENC_FRECPX_Z_P_Z_:
		case ENC_FSQRT_Z_P_Z_:
		case ENC_RBIT_Z_P_Z_:
		case ENC_REVB_Z_Z_:
		case ENC_REVH_Z_Z_:
		case ENC_REVW_Z_Z_:
			// xxxxxxxx|size=xx|xxxx|opc=xx|xxx|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>16)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_ASR_Z_P_ZW_:
		case ENC_ASR_Z_P_ZZ_:
		case ENC_ASRR_Z_P_ZZ_:
		case ENC_LSL_Z_P_ZW_:
		case ENC_LSL_Z_P_ZZ_:
		case ENC_LSLR_Z_P_ZZ_:
		case ENC_LSR_Z_P_ZW_:
		case ENC_LSR_Z_P_ZZ_:
		case ENC_LSRR_Z_P_ZZ_:
			// xxxxxxxx|size=xx|xxx|R=x|L=x|U=x|xxx|Pg=xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->R = (insword>>18)&1;
			ctx->L = (insword>>17)&1;
			ctx->U = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_SHADD_Z_P_ZZ_:
		case ENC_SHSUB_Z_P_ZZ_:
		case ENC_SHSUBR_Z_P_ZZ_:
		case ENC_SRHADD_Z_P_ZZ_:
		case ENC_UHADD_Z_P_ZZ_:
		case ENC_UHSUB_Z_P_ZZ_:
		case ENC_UHSUBR_Z_P_ZZ_:
		case ENC_URHADD_Z_P_ZZ_:
			// xxxxxxxx|size=xx|xxx|R=x|S=x|U=x|xxx|Pg=xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->R = (insword>>18)&1;
			ctx->S = (insword>>17)&1;
			ctx->U = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_FTMAD_Z_ZZI_:
			// xxxxxxxx|size=xx|xxx|imm3=xxx|xxxxxx|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->imm3 = (insword>>16)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_SQADD_Z_P_ZZ_:
		case ENC_SQSUB_Z_P_ZZ_:
		case ENC_SQSUBR_Z_P_ZZ_:
		case ENC_SUQADD_Z_P_ZZ_:
		case ENC_UQADD_Z_P_ZZ_:
		case ENC_UQSUB_Z_P_ZZ_:
		case ENC_UQSUBR_Z_P_ZZ_:
		case ENC_USQADD_Z_P_ZZ_:
			// xxxxxxxx|size=xx|xxx|op=x|S=x|U=x|xxx|Pg=xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->op = (insword>>18)&1;
			ctx->S = (insword>>17)&1;
			ctx->U = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_FRECPE_Z_Z_:
		case ENC_FRSQRTE_Z_Z_:
			// xxxxxxxx|size=xx|xxx|opc<2:1>=xx|opc<0>=x|xxxxxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>17)&3;
			ctx->opc = (insword>>16)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_ADD_Z_P_ZZ_:
		case ENC_AND_Z_P_ZZ_:
		case ENC_BIC_Z_P_ZZ_:
		case ENC_EOR_Z_P_ZZ_:
		case ENC_FADDP_Z_P_ZZ_:
		case ENC_FMAXNMP_Z_P_ZZ_:
		case ENC_FMAXP_Z_P_ZZ_:
		case ENC_FMINNMP_Z_P_ZZ_:
		case ENC_FMINP_Z_P_ZZ_:
		case ENC_ORR_Z_P_ZZ_:
		case ENC_SUB_Z_P_ZZ_:
		case ENC_SUBR_Z_P_ZZ_:
			// xxxxxxxx|size=xx|xxx|opc<2:1>=xx|opc<0>=x|xxx|Pg=xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>17)&3;
			ctx->opc = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_FADDV_V_P_Z_:
		case ENC_FMAXNMV_V_P_Z_:
		case ENC_FMAXV_V_P_Z_:
		case ENC_FMINNMV_V_P_Z_:
		case ENC_FMINV_V_P_Z_:
			// xxxxxxxx|size=xx|xxx|opc<2:1>=xx|opc<0>=x|xxx|Pg=xxx|Zn=xxxxx|Vd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>17)&3;
			ctx->opc = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Vd = insword&0x1f;
			break;
		case ENC_ABS_Z_P_Z_:
		case ENC_CLS_Z_P_Z_:
		case ENC_CLZ_Z_P_Z_:
		case ENC_CNOT_Z_P_Z_:
		case ENC_CNT_Z_P_Z_:
		case ENC_FABS_Z_P_Z_:
		case ENC_FNEG_Z_P_Z_:
		case ENC_FRINTI_Z_P_Z_:
		case ENC_FRINTX_Z_P_Z_:
		case ENC_FRINTA_Z_P_Z_:
		case ENC_FRINTN_Z_P_Z_:
		case ENC_FRINTZ_Z_P_Z_:
		case ENC_FRINTM_Z_P_Z_:
		case ENC_FRINTP_Z_P_Z_:
		case ENC_NEG_Z_P_Z_:
		case ENC_NOT_Z_P_Z_:
			// xxxxxxxx|size=xx|xxx|opc<2:1>=xx|opc<0>=x|xxx|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>17)&3;
			ctx->opc = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_FADD_Z_P_ZS_:
		case ENC_FMAX_Z_P_ZS_:
		case ENC_FMAXNM_Z_P_ZS_:
		case ENC_FMIN_Z_P_ZS_:
		case ENC_FMINNM_Z_P_ZS_:
		case ENC_FMUL_Z_P_ZS_:
		case ENC_FSUB_Z_P_ZS_:
		case ENC_FSUBR_Z_P_ZS_:
			// xxxxxxxx|size=xx|xxx|opc<2:1>=xx|opc<0>=x|xxx|Pg=xxx|xxxx|i1=x|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>17)&3;
			ctx->opc = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->i1 = (insword>>5)&1;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_CNTP_R_P_P_:
			// xxxxxxxx|size=xx|xxx|opc<2:1>=xx|opc<0>=x|xx|Pg=xxxx|x|Pn=xxxx|Rd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>17)&3;
			ctx->opc = (insword>>16)&1;
			ctx->Pg = (insword>>10)&15;
			ctx->Pn = (insword>>5)&15;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_MUL_Z_ZI_:
			// xxxxxxxx|size=xx|xxx|opc<2:1>=xx|opc<0>=x|xx|o2=x|imm8=xxxxxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>17)&3;
			ctx->opc = (insword>>16)&1;
			ctx->o2 = (insword>>13)&1;
			ctx->imm8 = (insword>>5)&0xff;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_ADD_Z_ZI_:
		case ENC_SUB_Z_ZI_:
		case ENC_SUBR_Z_ZI_:
			// xxxxxxxx|size=xx|xxx|opc<2:1>=xx|opc<0>=x|xx|sh=x|imm8=xxxxxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>17)&3;
			ctx->opc = (insword>>16)&1;
			ctx->sh = (insword>>13)&1;
			ctx->imm8 = (insword>>5)&0xff;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_MOVPRFX_Z_P_Z_:
			// xxxxxxxx|size=xx|xxx|opc=xx|M=x|xxx|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>17)&3;
			ctx->M = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_ADDP_Z_P_ZZ_:
		case ENC_SABD_Z_P_ZZ_:
		case ENC_SMAX_Z_P_ZZ_:
		case ENC_SMAXP_Z_P_ZZ_:
		case ENC_SMIN_Z_P_ZZ_:
		case ENC_SMINP_Z_P_ZZ_:
		case ENC_UABD_Z_P_ZZ_:
		case ENC_UMAX_Z_P_ZZ_:
		case ENC_UMAXP_Z_P_ZZ_:
		case ENC_UMIN_Z_P_ZZ_:
		case ENC_UMINP_Z_P_ZZ_:
			// xxxxxxxx|size=xx|xxx|opc=xx|U=x|xxx|Pg=xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>17)&3;
			ctx->U = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_FMOV_FDUP_Z_I_:
		case ENC_FDUP_Z_I_:
			// xxxxxxxx|size=xx|xxx|opc=xx|xxx|o2=x|imm8=xxxxxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>17)&3;
			ctx->o2 = (insword>>13)&1;
			ctx->imm8 = (insword>>5)&0xff;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_FMOV_DUP_Z_I_:
		case ENC_MOV_DUP_Z_I_:
		case ENC_DUP_Z_I_:
			// xxxxxxxx|size=xx|xxx|opc=xx|xxx|sh=x|imm8=xxxxxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>17)&3;
			ctx->sh = (insword>>13)&1;
			ctx->imm8 = (insword>>5)&0xff;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SXTB_Z_P_Z_:
		case ENC_SXTH_Z_P_Z_:
		case ENC_SXTW_Z_P_Z_:
		case ENC_UXTB_Z_P_Z_:
		case ENC_UXTH_Z_P_Z_:
		case ENC_UXTW_Z_P_Z_:
			// xxxxxxxx|size=xx|xxx|xx|U=x|xxx|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->U = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SMAX_Z_ZI_:
		case ENC_SMIN_Z_ZI_:
		case ENC_UMAX_Z_ZI_:
		case ENC_UMIN_Z_ZI_:
			// xxxxxxxx|size=xx|xxx|xx|U=x|xx|o2=x|imm8=xxxxxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->U = (insword>>16)&1;
			ctx->o2 = (insword>>13)&1;
			ctx->imm8 = (insword>>5)&0xff;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_SQADD_Z_ZI_:
		case ENC_SQSUB_Z_ZI_:
		case ENC_UQADD_Z_ZI_:
		case ENC_UQSUB_Z_ZI_:
			// xxxxxxxx|size=xx|xxx|xx|U=x|xx|sh=x|imm8=xxxxxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->U = (insword>>16)&1;
			ctx->sh = (insword>>13)&1;
			ctx->imm8 = (insword>>5)&0xff;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_FMOV_FCPY_Z_P_I_:
		case ENC_FCPY_Z_P_I_:
			// xxxxxxxx|size=xx|xx|Pg=xxxx|xxx|imm8=xxxxxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Pg = (insword>>16)&15;
			ctx->imm8 = (insword>>5)&0xff;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_FMOV_CPY_Z_P_I_:
		case ENC_MOV_CPY_Z_O_I_:
		case ENC_MOV_CPY_Z_P_I_:
		case ENC_CPY_Z_O_I_:
		case ENC_CPY_Z_P_I_:
			// xxxxxxxx|size=xx|xx|Pg=xxxx|x|M=x|sh=x|imm8=xxxxxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Pg = (insword>>16)&15;
			ctx->M = (insword>>14)&1;
			ctx->sh = (insword>>13)&1;
			ctx->imm8 = (insword>>5)&0xff;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_TRN1_P_PP_:
		case ENC_TRN2_P_PP_:
		case ENC_UZP1_P_PP_:
		case ENC_UZP2_P_PP_:
		case ENC_ZIP2_P_PP_:
		case ENC_ZIP1_P_PP_:
			// xxxxxxxx|size=xx|xx|Pm=xxxx|xxx|opc=xx|H=x|x|Pn=xxxx|x|Pd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->Pm = (insword>>16)&15;
			ctx->opc = (insword>>11)&3;
			ctx->H = (insword>>10)&1;
			ctx->Pn = (insword>>5)&15;
			ctx->Pd = insword&15;
			break;
		case ENC_SQRSHL_Z_P_ZZ_:
		case ENC_SQRSHLR_Z_P_ZZ_:
		case ENC_SQSHL_Z_P_ZZ_:
		case ENC_SQSHLR_Z_P_ZZ_:
		case ENC_SRSHL_Z_P_ZZ_:
		case ENC_SRSHLR_Z_P_ZZ_:
		case ENC_UQRSHL_Z_P_ZZ_:
		case ENC_UQRSHLR_Z_P_ZZ_:
		case ENC_UQSHL_Z_P_ZZ_:
		case ENC_UQSHLR_Z_P_ZZ_:
		case ENC_URSHL_Z_P_ZZ_:
		case ENC_URSHLR_Z_P_ZZ_:
			// xxxxxxxx|size=xx|xx|Q=x|R=x|N=x|U=x|xxx|Pg=xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Q = (insword>>19)&1;
			ctx->R = (insword>>18)&1;
			ctx->N = (insword>>17)&1;
			ctx->U = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_SQABS_Z_P_Z_:
		case ENC_SQNEG_Z_P_Z_:
		case ENC_URECPE_Z_P_Z_:
		case ENC_URSQRTE_Z_P_Z_:
			// xxxxxxxx|size=xx|xx|Q=x|x|opc=xx|xxx|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Q = (insword>>19)&1;
			ctx->opc = (insword>>16)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_DECB_R_RS_:
		case ENC_DECD_R_RS_:
		case ENC_DECH_R_RS_:
		case ENC_DECW_R_RS_:
		case ENC_INCB_R_RS_:
		case ENC_INCD_R_RS_:
		case ENC_INCH_R_RS_:
		case ENC_INCW_R_RS_:
			// xxxxxxxx|size=xx|xx|imm4=xxxx|xxxxx|D=x|pattern=xxxxx|Rdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->imm4 = (insword>>16)&15;
			ctx->D = (insword>>10)&1;
			ctx->pattern = (insword>>5)&0x1f;
			ctx->Rdn = insword&0x1f;
			break;
		case ENC_DECD_Z_ZS_:
		case ENC_DECH_Z_ZS_:
		case ENC_DECW_Z_ZS_:
		case ENC_INCD_Z_ZS_:
		case ENC_INCH_Z_ZS_:
		case ENC_INCW_Z_ZS_:
			// xxxxxxxx|size=xx|xx|imm4=xxxx|xxxxx|D=x|pattern=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->imm4 = (insword>>16)&15;
			ctx->D = (insword>>10)&1;
			ctx->pattern = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_CNTB_R_S_:
		case ENC_CNTD_R_S_:
		case ENC_CNTH_R_S_:
		case ENC_CNTW_R_S_:
			// xxxxxxxx|size=xx|xx|imm4=xxxx|xxxxx|op=x|pattern=xxxxx|Rd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->imm4 = (insword>>16)&15;
			ctx->op = (insword>>10)&1;
			ctx->pattern = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SQDECD_Z_ZS_:
		case ENC_SQDECH_Z_ZS_:
		case ENC_SQDECW_Z_ZS_:
		case ENC_SQINCD_Z_ZS_:
		case ENC_SQINCH_Z_ZS_:
		case ENC_SQINCW_Z_ZS_:
		case ENC_UQDECD_Z_ZS_:
		case ENC_UQDECH_Z_ZS_:
		case ENC_UQDECW_Z_ZS_:
		case ENC_UQINCD_Z_ZS_:
		case ENC_UQINCH_Z_ZS_:
		case ENC_UQINCW_Z_ZS_:
			// xxxxxxxx|size=xx|xx|imm4=xxxx|xxxx|D=x|U=x|pattern=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->imm4 = (insword>>16)&15;
			ctx->D = (insword>>11)&1;
			ctx->U = (insword>>10)&1;
			ctx->pattern = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_FABD_Z_P_ZZ_:
		case ENC_FADD_Z_P_ZZ_:
		case ENC_FDIV_Z_P_ZZ_:
		case ENC_FDIVR_Z_P_ZZ_:
		case ENC_FMAX_Z_P_ZZ_:
		case ENC_FMAXNM_Z_P_ZZ_:
		case ENC_FMIN_Z_P_ZZ_:
		case ENC_FMINNM_Z_P_ZZ_:
		case ENC_FMUL_Z_P_ZZ_:
		case ENC_FMULX_Z_P_ZZ_:
		case ENC_FSCALE_Z_P_ZZ_:
		case ENC_FSUB_Z_P_ZZ_:
		case ENC_FSUBR_Z_P_ZZ_:
			// xxxxxxxx|size=xx|xx|opc<3:1>=xxx|opc<0>=x|xxx|Pg=xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>17)&7;
			ctx->opc = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_INDEX_Z_RR_:
			// xxxxxxxx|size=xx|x|Rm=xxxxx|xxxxxx|Rn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_WHILERW_P_RR_:
		case ENC_WHILEWR_P_RR_:
			// xxxxxxxx|size=xx|x|Rm=xxxxx|xxxxxx|Rn=xxxxx|rw=x|Pd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->rw = (insword>>4)&1;
			ctx->Pd = insword&15;
			break;
		case ENC_INDEX_Z_IR_:
			// xxxxxxxx|size=xx|x|Rm=xxxxx|xxxxxx|imm5=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->imm5 = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_WHILEGE_P_P_RR_:
		case ENC_WHILEGT_P_P_RR_:
		case ENC_WHILEHI_P_P_RR_:
		case ENC_WHILEHS_P_P_RR_:
		case ENC_WHILELE_P_P_RR_:
		case ENC_WHILELO_P_P_RR_:
		case ENC_WHILELS_P_P_RR_:
		case ENC_WHILELT_P_P_RR_:
			// xxxxxxxx|size=xx|x|Rm=xxxxx|xxx|sf=x|U=x|lt=x|Rn=xxxxx|eq=x|Pd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->sf = (insword>>12)&1;
			ctx->U = (insword>>11)&1;
			ctx->lt = (insword>>10)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->eq = (insword>>4)&1;
			ctx->Pd = insword&15;
			break;
		case ENC_SHA1C_QSV_CRYPTOSHA3:
		case ENC_SHA1M_QSV_CRYPTOSHA3:
		case ENC_SHA1P_QSV_CRYPTOSHA3:
		case ENC_SHA1SU0_VVV_CRYPTOSHA3:
		case ENC_SHA256SU1_VVV_CRYPTOSHA3:
			// xxxxxxxx|size=xx|x|Rm=xxxxx|x|opcode=xxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>12)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SHA256H2_QQV_CRYPTOSHA3:
		case ENC_SHA256H_QQV_CRYPTOSHA3:
			// xxxxxxxx|size=xx|x|Rm=xxxxx|x|opcode[2:1]=xx|P=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>13)&3;
			ctx->P = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMAD_Z_P_ZZZ_:
		case ENC_FMSB_Z_P_ZZZ_:
		case ENC_FNMAD_Z_P_ZZZ_:
		case ENC_FNMSB_Z_P_ZZZ_:
			// xxxxxxxx|size=xx|x|Za=xxxxx|x|N=x|op=x|Pg=xxx|Zm=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Za = (insword>>16)&0x1f;
			ctx->N = (insword>>14)&1;
			ctx->op = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_CMPGT_P_P_ZW_:
		case ENC_CMPGE_P_P_ZW_:
		case ENC_CMPHI_P_P_ZW_:
		case ENC_CMPHS_P_P_ZW_:
		case ENC_CMPLT_P_P_ZW_:
		case ENC_CMPLE_P_P_ZW_:
		case ENC_CMPLO_P_P_ZW_:
		case ENC_CMPLS_P_P_ZW_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|U=x|x|lt=x|Pg=xxx|Zn=xxxxx|ne=x|Pd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->U = (insword>>15)&1;
			ctx->lt = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->ne = (insword>>4)&1;
			ctx->Pd = insword&15;
			break;
		case ENC_FCMLE_FCMGE_P_P_ZZ_:
		case ENC_FCMLT_FCMGT_P_P_ZZ_:
		case ENC_FCMEQ_P_P_ZZ_:
		case ENC_FCMGT_P_P_ZZ_:
		case ENC_FCMGE_P_P_ZZ_:
		case ENC_FCMNE_P_P_ZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|op=x|x|cmph=x|Pg=xxx|Zn=xxxxx|cmpl=x|Pd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->op = (insword>>15)&1;
			ctx->cmph = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->cmpl = (insword>>4)&1;
			ctx->Pd = insword&15;
			break;
		case ENC_CMPLE_CMPGE_P_P_ZZ_:
		case ENC_CMPLO_CMPHI_P_P_ZZ_:
		case ENC_CMPLS_CMPHS_P_P_ZZ_:
		case ENC_CMPLT_CMPGT_P_P_ZZ_:
		case ENC_CMPEQ_P_P_ZW_:
		case ENC_CMPNE_P_P_ZW_:
		case ENC_CMPEQ_P_P_ZZ_:
		case ENC_CMPGT_P_P_ZZ_:
		case ENC_CMPGE_P_P_ZZ_:
		case ENC_CMPHI_P_P_ZZ_:
		case ENC_CMPHS_P_P_ZZ_:
		case ENC_CMPNE_P_P_ZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|op=x|x|o2=x|Pg=xxx|Zn=xxxxx|ne=x|Pd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->op = (insword>>15)&1;
			ctx->o2 = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->ne = (insword>>4)&1;
			ctx->Pd = insword&15;
			break;
		case ENC_FACLE_FACGE_P_P_ZZ_:
		case ENC_FACLT_FACGT_P_P_ZZ_:
		case ENC_FACGT_P_P_ZZ_:
		case ENC_FACGE_P_P_ZZ_:
		case ENC_FCMUO_P_P_ZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|op=x|x|o2=x|Pg=xxx|Zn=xxxxx|o3=x|Pd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->op = (insword>>15)&1;
			ctx->o2 = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->o3 = (insword>>4)&1;
			ctx->Pd = insword&15;
			break;
		case ENC_HISTSEG_Z_ZZ_:
		case ENC_TBL_Z_ZZ_1:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|xxxxxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_USDOT_Z_ZZZ_S:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|xxxxxx|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_SQDMULH_Z_ZZ_:
		case ENC_SQRDMULH_Z_ZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|xxxxx|R=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->R = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SQDMLALBT_Z_ZZZ_:
		case ENC_SQDMLSLBT_Z_ZZZ_:
		case ENC_SQRDMLAH_Z_ZZZ_:
		case ENC_SQRDMLSH_Z_ZZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|xxxxx|S=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->S = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_SCLAMP_Z_ZZ_:
		case ENC_UCLAMP_Z_ZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|xxxxx|U=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->U = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SABA_Z_ZZZ_:
		case ENC_SDOT_Z_ZZZ_:
		case ENC_UABA_Z_ZZZ_:
		case ENC_UDOT_Z_ZZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|xxxxx|U=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->U = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_FTSSEL_Z_ZZ_:
		case ENC_RAX1_Z_ZZ_:
		case ENC_SM4EKEY_Z_ZZ_:
		case ENC_TBL_Z_ZZ_2:
		case ENC_TBX_Z_ZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|xxxxx|op=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->op = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_EORBT_Z_ZZ_:
		case ENC_EORTB_Z_ZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|xxxxx|tb=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->tb = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SQDMLALB_Z_ZZZ_:
		case ENC_SQDMLALT_Z_ZZZ_:
		case ENC_SQDMLSLB_Z_ZZZ_:
		case ENC_SQDMLSLT_Z_ZZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|xxxx|S=x|T=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->S = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_SADDLBT_Z_ZZ_:
		case ENC_SSUBLBT_Z_ZZ_:
		case ENC_SSUBLTB_Z_ZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|xxxx|S=x|tb=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->S = (insword>>11)&1;
			ctx->tb = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SABALB_Z_ZZZ_:
		case ENC_SABALT_Z_ZZZ_:
		case ENC_UABALB_Z_ZZZ_:
		case ENC_UABALT_Z_ZZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|xxxx|U=x|T=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->U = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_BDEP_Z_ZZ_:
		case ENC_BEXT_Z_ZZ_:
		case ENC_BGRP_Z_ZZ_:
		case ENC_LSL_Z_ZW_:
		case ENC_MUL_Z_ZZ_:
		case ENC_PMUL_Z_ZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|xxxx|opc=xx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->opc = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_CDOT_Z_ZZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|xxxx|rot=xx|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->rot = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_ASR_Z_ZW_:
		case ENC_LSR_Z_ZW_:
		case ENC_SMULH_Z_ZZ_:
		case ENC_UMULH_Z_ZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|xxxx|x|U=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->U = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_HISTCNT_Z_P_ZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|xxx|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_MATCH_P_P_ZZ_:
		case ENC_NMATCH_P_P_ZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|xxx|Pg=xxx|Zn=xxxxx|op=x|Pd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->op = (insword>>4)&1;
			ctx->Pd = insword&15;
			break;
		case ENC_ADDHNB_Z_ZZ_:
		case ENC_ADDHNT_Z_ZZ_:
		case ENC_RADDHNB_Z_ZZ_:
		case ENC_RADDHNT_Z_ZZ_:
		case ENC_RSUBHNB_Z_ZZ_:
		case ENC_RSUBHNT_Z_ZZ_:
		case ENC_SUBHNB_Z_ZZ_:
		case ENC_SUBHNT_Z_ZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|xxx|S=x|R=x|T=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->S = (insword>>12)&1;
			ctx->R = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SADDWB_Z_ZZ_:
		case ENC_SADDWT_Z_ZZ_:
		case ENC_SSUBWB_Z_ZZ_:
		case ENC_SSUBWT_Z_ZZ_:
		case ENC_UADDWB_Z_ZZ_:
		case ENC_UADDWT_Z_ZZ_:
		case ENC_USUBWB_Z_ZZ_:
		case ENC_USUBWT_Z_ZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|xxx|S=x|U=x|T=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->S = (insword>>12)&1;
			ctx->U = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SMLALB_Z_ZZZ_:
		case ENC_SMLALT_Z_ZZZ_:
		case ENC_SMLSLB_Z_ZZZ_:
		case ENC_SMLSLT_Z_ZZZ_:
		case ENC_UMLALB_Z_ZZZ_:
		case ENC_UMLALT_Z_ZZZ_:
		case ENC_UMLSLB_Z_ZZZ_:
		case ENC_UMLSLT_Z_ZZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|xxx|S=x|U=x|T=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->S = (insword>>12)&1;
			ctx->U = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_PMULLB_Z_ZZ_:
		case ENC_PMULLT_Z_ZZ_:
		case ENC_SMULLB_Z_ZZ_:
		case ENC_SMULLT_Z_ZZ_:
		case ENC_SQDMULLB_Z_ZZ_:
		case ENC_SQDMULLT_Z_ZZ_:
		case ENC_UMULLB_Z_ZZ_:
		case ENC_UMULLT_Z_ZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|xxx|op=x|U=x|T=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->op = (insword>>12)&1;
			ctx->U = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_CMLA_Z_ZZZ_:
		case ENC_SQRDCMLAH_Z_ZZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|xxx|op=x|rot=xx|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->op = (insword>>12)&1;
			ctx->rot = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_ADD_Z_ZZ_:
		case ENC_FADD_Z_ZZ_:
		case ENC_FMUL_Z_ZZ_:
		case ENC_FRECPS_Z_ZZ_:
		case ENC_FRSQRTS_Z_ZZ_:
		case ENC_FSUB_Z_ZZ_:
		case ENC_FTSMUL_Z_ZZ_:
		case ENC_SUB_Z_ZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|xxx|opc<2:1>=xx|opc<0>=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->opc = (insword>>11)&3;
			ctx->opc = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_TRN1_Z_ZZ_:
		case ENC_TRN2_Z_ZZ_:
		case ENC_UZP1_Z_ZZ_:
		case ENC_UZP2_Z_ZZ_:
		case ENC_ZIP2_Z_ZZ_:
		case ENC_ZIP1_Z_ZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|xxx|xx|H=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->H = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SQADD_Z_ZZ_:
		case ENC_SQSUB_Z_ZZ_:
		case ENC_UQADD_Z_ZZ_:
		case ENC_UQSUB_Z_ZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|xxx|xx|U=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->U = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_MOV_SEL_Z_P_ZZ_:
		case ENC_SEL_Z_P_ZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|xx|Pg=xxxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&15;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_MAD_Z_P_ZZZ_:
		case ENC_MSB_Z_P_ZZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|xx|op=x|Pg=xxx|Za=xxxxx|Zdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->op = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Za = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_MLA_Z_P_ZZZ_:
		case ENC_MLS_Z_P_ZZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|xx|op=x|Pg=xxx|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->op = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_SABDLB_Z_ZZ_:
		case ENC_SABDLT_Z_ZZ_:
		case ENC_SADDLB_Z_ZZ_:
		case ENC_SADDLT_Z_ZZ_:
		case ENC_SSUBLB_Z_ZZ_:
		case ENC_SSUBLT_Z_ZZ_:
		case ENC_UABDLB_Z_ZZ_:
		case ENC_UABDLT_Z_ZZ_:
		case ENC_UADDLB_Z_ZZ_:
		case ENC_UADDLT_Z_ZZ_:
		case ENC_USUBLB_Z_ZZ_:
		case ENC_USUBLT_Z_ZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|xx|op=x|S=x|U=x|T=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->op = (insword>>13)&1;
			ctx->S = (insword>>12)&1;
			ctx->U = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_FMLA_Z_P_ZZZ_:
		case ENC_FMLS_Z_P_ZZZ_:
		case ENC_FNMLA_Z_P_ZZZ_:
		case ENC_FNMLS_Z_P_ZZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|x|N=x|op=x|Pg=xxx|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->N = (insword>>14)&1;
			ctx->op = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_FCMLA_Z_P_ZZZ_:
			// xxxxxxxx|size=xx|x|Zm=xxxxx|x|rot=xx|Pg=xxx|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->rot = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_FMUL_Z_ZZI_D:
		case ENC_MUL_Z_ZZI_D:
			// xxxxxxxx|size=xx|x|i1=x|Zm=xxxx|xxxxxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i1 = (insword>>20)&1;
			ctx->Zm = (insword>>16)&15;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SQDMULH_Z_ZZI_D:
		case ENC_SQRDMULH_Z_ZZI_D:
			// xxxxxxxx|size=xx|x|i1=x|Zm=xxxx|xxxxx|R=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i1 = (insword>>20)&1;
			ctx->Zm = (insword>>16)&15;
			ctx->R = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_MLA_Z_ZZZI_D:
		case ENC_MLS_Z_ZZZI_D:
		case ENC_SQRDMLAH_Z_ZZZI_D:
		case ENC_SQRDMLSH_Z_ZZZI_D:
			// xxxxxxxx|size=xx|x|i1=x|Zm=xxxx|xxxxx|S=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i1 = (insword>>20)&1;
			ctx->Zm = (insword>>16)&15;
			ctx->S = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_SDOT_Z_ZZZI_D:
		case ENC_UDOT_Z_ZZZI_D:
			// xxxxxxxx|size=xx|x|i1=x|Zm=xxxx|xxxxx|U=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i1 = (insword>>20)&1;
			ctx->Zm = (insword>>16)&15;
			ctx->U = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_FMLA_Z_ZZZI_D:
		case ENC_FMLS_Z_ZZZI_D:
			// xxxxxxxx|size=xx|x|i1=x|Zm=xxxx|xxxxx|op=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i1 = (insword>>20)&1;
			ctx->Zm = (insword>>16)&15;
			ctx->op = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_CDOT_Z_ZZZI_D:
		case ENC_CMLA_Z_ZZZI_S:
		case ENC_FCMLA_Z_ZZZI_S:
		case ENC_SQRDCMLAH_Z_ZZZI_S:
			// xxxxxxxx|size=xx|x|i1=x|Zm=xxxx|xxxx|rot=xx|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i1 = (insword>>20)&1;
			ctx->Zm = (insword>>16)&15;
			ctx->rot = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_FMUL_Z_ZZI_S:
		case ENC_MUL_Z_ZZI_S:
			// xxxxxxxx|size=xx|x|i2=xx|Zm=xxx|xxxxxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i2 = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SQDMULH_Z_ZZI_S:
		case ENC_SQRDMULH_Z_ZZI_S:
			// xxxxxxxx|size=xx|x|i2=xx|Zm=xxx|xxxxx|R=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i2 = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->R = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_MLA_Z_ZZZI_S:
		case ENC_MLS_Z_ZZZI_S:
		case ENC_SQRDMLAH_Z_ZZZI_S:
		case ENC_SQRDMLSH_Z_ZZZI_S:
			// xxxxxxxx|size=xx|x|i2=xx|Zm=xxx|xxxxx|S=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i2 = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->S = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_SDOT_Z_ZZZI_S:
		case ENC_SUDOT_Z_ZZZI_S:
		case ENC_UDOT_Z_ZZZI_S:
		case ENC_USDOT_Z_ZZZI_S:
			// xxxxxxxx|size=xx|x|i2=xx|Zm=xxx|xxxxx|U=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i2 = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->U = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_FMLA_Z_ZZZI_S:
		case ENC_FMLS_Z_ZZZI_S:
			// xxxxxxxx|size=xx|x|i2=xx|Zm=xxx|xxxxx|op=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i2 = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->op = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_CDOT_Z_ZZZI_S:
		case ENC_CMLA_Z_ZZZI_H:
		case ENC_FCMLA_Z_ZZZI_H:
		case ENC_SQRDCMLAH_Z_ZZZI_H:
			// xxxxxxxx|size=xx|x|i2=xx|Zm=xxx|xxxx|rot=xx|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i2 = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->rot = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_SQDMULLB_Z_ZZI_D:
		case ENC_SQDMULLT_Z_ZZI_D:
			// xxxxxxxx|size=xx|x|i2h=x|Zm=xxxx|xxxx|i2l=x|T=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i2h = (insword>>20)&1;
			ctx->Zm = (insword>>16)&15;
			ctx->i2l = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SQDMLALB_Z_ZZZI_D:
		case ENC_SQDMLALT_Z_ZZZI_D:
		case ENC_SQDMLSLB_Z_ZZZI_D:
		case ENC_SQDMLSLT_Z_ZZZI_D:
			// xxxxxxxx|size=xx|x|i2h=x|Zm=xxxx|xxx|S=x|i2l=x|T=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i2h = (insword>>20)&1;
			ctx->Zm = (insword>>16)&15;
			ctx->S = (insword>>12)&1;
			ctx->i2l = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_SMULLB_Z_ZZI_D:
		case ENC_SMULLT_Z_ZZI_D:
		case ENC_UMULLB_Z_ZZI_D:
		case ENC_UMULLT_Z_ZZI_D:
			// xxxxxxxx|size=xx|x|i2h=x|Zm=xxxx|xxx|U=x|i2l=x|T=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i2h = (insword>>20)&1;
			ctx->Zm = (insword>>16)&15;
			ctx->U = (insword>>12)&1;
			ctx->i2l = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SMLALB_Z_ZZZI_D:
		case ENC_SMLALT_Z_ZZZI_D:
		case ENC_SMLSLB_Z_ZZZI_D:
		case ENC_SMLSLT_Z_ZZZI_D:
		case ENC_UMLALB_Z_ZZZI_D:
		case ENC_UMLALT_Z_ZZZI_D:
		case ENC_UMLSLB_Z_ZZZI_D:
		case ENC_UMLSLT_Z_ZZZI_D:
			// xxxxxxxx|size=xx|x|i2h=x|Zm=xxxx|xx|S=x|U=x|i2l=x|T=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i2h = (insword>>20)&1;
			ctx->Zm = (insword>>16)&15;
			ctx->S = (insword>>13)&1;
			ctx->U = (insword>>12)&1;
			ctx->i2l = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_SQDMULLB_Z_ZZI_S:
		case ENC_SQDMULLT_Z_ZZI_S:
			// xxxxxxxx|size=xx|x|i3h=xx|Zm=xxx|xxxx|i3l=x|T=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i3h = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->i3l = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SQDMLALB_Z_ZZZI_S:
		case ENC_SQDMLALT_Z_ZZZI_S:
		case ENC_SQDMLSLB_Z_ZZZI_S:
		case ENC_SQDMLSLT_Z_ZZZI_S:
			// xxxxxxxx|size=xx|x|i3h=xx|Zm=xxx|xxx|S=x|i3l=x|T=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i3h = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->S = (insword>>12)&1;
			ctx->i3l = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_SMULLB_Z_ZZI_S:
		case ENC_SMULLT_Z_ZZI_S:
		case ENC_UMULLB_Z_ZZI_S:
		case ENC_UMULLT_Z_ZZI_S:
			// xxxxxxxx|size=xx|x|i3h=xx|Zm=xxx|xxx|U=x|i3l=x|T=x|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i3h = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->U = (insword>>12)&1;
			ctx->i3l = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SMLALB_Z_ZZZI_S:
		case ENC_SMLALT_Z_ZZZI_S:
		case ENC_SMLSLB_Z_ZZZI_S:
		case ENC_SMLSLT_Z_ZZZI_S:
		case ENC_UMLALB_Z_ZZZI_S:
		case ENC_UMLALT_Z_ZZZI_S:
		case ENC_UMLSLB_Z_ZZZI_S:
		case ENC_UMLSLT_Z_ZZZI_S:
			// xxxxxxxx|size=xx|x|i3h=xx|Zm=xxx|xx|S=x|U=x|i3l=x|T=x|Zn=xxxxx|Zda=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->i3h = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->S = (insword>>13)&1;
			ctx->U = (insword>>12)&1;
			ctx->i3l = (insword>>11)&1;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_CMPGT_P_P_ZI_:
		case ENC_CMPGE_P_P_ZI_:
		case ENC_CMPLT_P_P_ZI_:
		case ENC_CMPLE_P_P_ZI_:
			// xxxxxxxx|size=xx|x|imm5=xxxxx|op=x|x|lt=x|Pg=xxx|Zn=xxxxx|ne=x|Pd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->imm5 = (insword>>16)&0x1f;
			ctx->op = (insword>>15)&1;
			ctx->lt = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->ne = (insword>>4)&1;
			ctx->Pd = insword&15;
			break;
		case ENC_CMPEQ_P_P_ZI_:
		case ENC_CMPNE_P_P_ZI_:
			// xxxxxxxx|size=xx|x|imm5=xxxxx|op=x|x|o2=x|Pg=xxx|Zn=xxxxx|ne=x|Pd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->imm5 = (insword>>16)&0x1f;
			ctx->op = (insword>>15)&1;
			ctx->o2 = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->ne = (insword>>4)&1;
			ctx->Pd = insword&15;
			break;
		case ENC_INDEX_Z_RI_:
			// xxxxxxxx|size=xx|x|imm5=xxxxx|xxxxxx|Rn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->imm5 = (insword>>16)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_INDEX_Z_II_:
			// xxxxxxxx|size=xx|x|imm5b=xxxxx|xxxxxx|imm5=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->imm5b = (insword>>16)&0x1f;
			ctx->imm5 = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_CMPHI_P_P_ZI_:
		case ENC_CMPHS_P_P_ZI_:
		case ENC_CMPLO_P_P_ZI_:
		case ENC_CMPLS_P_P_ZI_:
			// xxxxxxxx|size=xx|x|imm7=xxxxxxx|lt=x|Pg=xxx|Zn=xxxxx|ne=x|Pd=xxxx
			ctx->size = (insword>>22)&3;
			ctx->imm7 = (insword>>14)&0x7f;
			ctx->lt = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->ne = (insword>>4)&1;
			ctx->Pd = insword&15;
			break;
		case ENC_FEXPA_Z_Z_:
			// xxxxxxxx|size=xx|x|opc<4:1>=xxxx|opc<0>=x|xxxxxx|Zn=xxxxx|Zd=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->opc = (insword>>17)&15;
			ctx->opc = (insword>>16)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SQDECB_R_RS_SX:
		case ENC_SQDECB_R_RS_X:
		case ENC_SQDECD_R_RS_SX:
		case ENC_SQDECD_R_RS_X:
		case ENC_SQDECH_R_RS_SX:
		case ENC_SQDECH_R_RS_X:
		case ENC_SQDECW_R_RS_SX:
		case ENC_SQDECW_R_RS_X:
		case ENC_SQINCB_R_RS_SX:
		case ENC_SQINCB_R_RS_X:
		case ENC_SQINCD_R_RS_SX:
		case ENC_SQINCD_R_RS_X:
		case ENC_SQINCH_R_RS_SX:
		case ENC_SQINCH_R_RS_X:
		case ENC_SQINCW_R_RS_SX:
		case ENC_SQINCW_R_RS_X:
		case ENC_UQDECB_R_RS_UW:
		case ENC_UQDECB_R_RS_X:
		case ENC_UQDECD_R_RS_UW:
		case ENC_UQDECD_R_RS_X:
		case ENC_UQDECH_R_RS_UW:
		case ENC_UQDECH_R_RS_X:
		case ENC_UQDECW_R_RS_UW:
		case ENC_UQDECW_R_RS_X:
		case ENC_UQINCB_R_RS_UW:
		case ENC_UQINCB_R_RS_X:
		case ENC_UQINCD_R_RS_UW:
		case ENC_UQINCD_R_RS_X:
		case ENC_UQINCH_R_RS_UW:
		case ENC_UQINCH_R_RS_X:
		case ENC_UQINCW_R_RS_UW:
		case ENC_UQINCW_R_RS_X:
			// xxxxxxxx|size=xx|x|sf=x|imm4=xxxx|xxxx|D=x|U=x|pattern=xxxxx|Rdn=xxxxx
			ctx->size = (insword>>22)&3;
			ctx->sf = (insword>>20)&1;
			ctx->imm4 = (insword>>16)&15;
			ctx->D = (insword>>11)&1;
			ctx->U = (insword>>10)&1;
			ctx->pattern = (insword>>5)&0x1f;
			ctx->Rdn = insword&0x1f;
			break;
		case ENC_ASR_Z_P_ZI_:
		case ENC_ASRD_Z_P_ZI_:
		case ENC_LSL_Z_P_ZI_:
		case ENC_LSR_Z_P_ZI_:
		case ENC_SQSHL_Z_P_ZI_:
		case ENC_SQSHLU_Z_P_ZI_:
		case ENC_SRSHR_Z_P_ZI_:
		case ENC_UQSHL_Z_P_ZI_:
		case ENC_URSHR_Z_P_ZI_:
			// xxxxxxxx|tszh=xx|xx|opc=xx|L=x|U=x|xxx|Pg=xxx|tszl=xx|imm3=xxx|Zdn=xxxxx
			ctx->tszh = (insword>>22)&3;
			ctx->opc = (insword>>18)&3;
			ctx->L = (insword>>17)&1;
			ctx->U = (insword>>16)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->tszl = (insword>>8)&3;
			ctx->imm3 = (insword>>5)&7;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_XAR_Z_ZZI_:
			// xxxxxxxx|tszh=xx|x|tszl=xx|imm3=xxx|xxxxxx|Zm=xxxxx|Zdn=xxxxx
			ctx->tszh = (insword>>22)&3;
			ctx->tszl = (insword>>19)&3;
			ctx->imm3 = (insword>>16)&7;
			ctx->Zm = (insword>>5)&0x1f;
			ctx->Zdn = insword&0x1f;
			break;
		case ENC_SLI_Z_ZZI_:
		case ENC_SRI_Z_ZZI_:
			// xxxxxxxx|tszh=xx|x|tszl=xx|imm3=xxx|xxxxx|op=x|Zn=xxxxx|Zd=xxxxx
			ctx->tszh = (insword>>22)&3;
			ctx->tszl = (insword>>19)&3;
			ctx->imm3 = (insword>>16)&7;
			ctx->op = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SRSRA_Z_ZI_:
		case ENC_SSRA_Z_ZI_:
		case ENC_URSRA_Z_ZI_:
		case ENC_USRA_Z_ZI_:
			// xxxxxxxx|tszh=xx|x|tszl=xx|imm3=xxx|xxxx|R=x|U=x|Zn=xxxxx|Zda=xxxxx
			ctx->tszh = (insword>>22)&3;
			ctx->tszl = (insword>>19)&3;
			ctx->imm3 = (insword>>16)&7;
			ctx->R = (insword>>11)&1;
			ctx->U = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_LSL_Z_ZI_:
			// xxxxxxxx|tszh=xx|x|tszl=xx|imm3=xxx|xxxx|opc=xx|Zn=xxxxx|Zd=xxxxx
			ctx->tszh = (insword>>22)&3;
			ctx->tszl = (insword>>19)&3;
			ctx->imm3 = (insword>>16)&7;
			ctx->opc = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_ASR_Z_ZI_:
		case ENC_LSR_Z_ZI_:
			// xxxxxxxx|tszh=xx|x|tszl=xx|imm3=xxx|xxxx|x|U=x|Zn=xxxxx|Zd=xxxxx
			ctx->tszh = (insword>>22)&3;
			ctx->tszl = (insword>>19)&3;
			ctx->imm3 = (insword>>16)&7;
			ctx->U = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SMMLA_Z_ZZZ_:
		case ENC_UMMLA_Z_ZZZ_:
		case ENC_USMMLA_Z_ZZZ_:
			// xxxxxxxx|uns=xx|x|Zm=xxxxx|xxxxxx|Zn=xxxxx|Zda=xxxxx
			ctx->uns = (insword>>22)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_FMUL_Z_ZZI_H:
		case ENC_MUL_Z_ZZI_H:
			// xxxxxxxx|x|i3h=x|x|i3l=xx|Zm=xxx|xxxxxx|Zn=xxxxx|Zd=xxxxx
			ctx->i3h = (insword>>22)&1;
			ctx->i3l = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_SQDMULH_Z_ZZI_H:
		case ENC_SQRDMULH_Z_ZZI_H:
			// xxxxxxxx|x|i3h=x|x|i3l=xx|Zm=xxx|xxxxx|R=x|Zn=xxxxx|Zd=xxxxx
			ctx->i3h = (insword>>22)&1;
			ctx->i3l = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->R = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_MLA_Z_ZZZI_H:
		case ENC_MLS_Z_ZZZI_H:
		case ENC_SQRDMLAH_Z_ZZZI_H:
		case ENC_SQRDMLSH_Z_ZZZI_H:
			// xxxxxxxx|x|i3h=x|x|i3l=xx|Zm=xxx|xxxxx|S=x|Zn=xxxxx|Zda=xxxxx
			ctx->i3h = (insword>>22)&1;
			ctx->i3l = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->S = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_FMLA_Z_ZZZI_H:
		case ENC_FMLS_Z_ZZZI_H:
			// xxxxxxxx|x|i3h=x|x|i3l=xx|Zm=xxx|xxxxx|op=x|Zn=xxxxx|Zda=xxxxx
			ctx->i3h = (insword>>22)&1;
			ctx->i3l = (insword>>19)&3;
			ctx->Zm = (insword>>16)&7;
			ctx->op = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_ADCLB_Z_ZZZ_:
		case ENC_ADCLT_Z_ZZZ_:
		case ENC_SBCLB_Z_ZZZ_:
		case ENC_SBCLT_Z_ZZZ_:
			// xxxxxxxx|x|sz=x|x|Zm=xxxxx|xxxxx|T=x|Zn=xxxxx|Zda=xxxxx
			ctx->sz = (insword>>22)&1;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->T = (insword>>10)&1;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zda = insword&0x1f;
			break;
		case ENC_ADR_Z_AZ_SD_SAME_SCALED:
			// xxxxxxxx|x|sz=x|x|Zm=xxxxx|xxxx|msz=xx|Zn=xxxxx|Zd=xxxxx
			ctx->sz = (insword>>22)&1;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->msz = (insword>>10)&3;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zd = insword&0x1f;
			break;
		case ENC_BLR_64_BRANCH_REG:
		case ENC_BLRAAZ_64_BRANCH_REG:
		case ENC_BLRAA_64P_BRANCH_REG:
		case ENC_BLRABZ_64_BRANCH_REG:
		case ENC_BLRAB_64P_BRANCH_REG:
		case ENC_BR_64_BRANCH_REG:
		case ENC_BRAAZ_64_BRANCH_REG:
		case ENC_BRAA_64P_BRANCH_REG:
		case ENC_BRABZ_64_BRANCH_REG:
		case ENC_BRAB_64P_BRANCH_REG:
		case ENC_RET_64R_BRANCH_REG:
		case ENC_RETAA_64E_BRANCH_REG:
		case ENC_RETAB_64E_BRANCH_REG:
			// xxxxxxx|Z=x|opc[2:1]=x|op=xx|op2=xxxxx|op3[5:2]=xxxx|A=x|M=x|Rn=xxxxx|Rm=xxxxx
			ctx->Z = (insword>>24)&1;
			ctx->opc = (insword>>23)&1;
			ctx->op = (insword>>21)&3;
			ctx->op2 = (insword>>16)&0x1f;
			ctx->op3 = (insword>>12)&15;
			ctx->A = (insword>>11)&1;
			ctx->M = (insword>>10)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rm = insword&0x1f;
			break;
		case ENC_LD1B_Z_P_BR_U8:
		case ENC_LD1B_Z_P_BR_U16:
		case ENC_LD1B_Z_P_BR_U32:
		case ENC_LD1B_Z_P_BR_U64:
		case ENC_LD1D_Z_P_BR_U64:
		case ENC_LD1H_Z_P_BR_U16:
		case ENC_LD1H_Z_P_BR_U32:
		case ENC_LD1H_Z_P_BR_U64:
		case ENC_LD1SB_Z_P_BR_S16:
		case ENC_LD1SB_Z_P_BR_S32:
		case ENC_LD1SB_Z_P_BR_S64:
		case ENC_LD1SH_Z_P_BR_S32:
		case ENC_LD1SH_Z_P_BR_S64:
		case ENC_LD1SW_Z_P_BR_S64:
		case ENC_LD1W_Z_P_BR_U32:
		case ENC_LD1W_Z_P_BR_U64:
		case ENC_LDFF1B_Z_P_BR_U8:
		case ENC_LDFF1B_Z_P_BR_U16:
		case ENC_LDFF1B_Z_P_BR_U32:
		case ENC_LDFF1B_Z_P_BR_U64:
		case ENC_LDFF1D_Z_P_BR_U64:
		case ENC_LDFF1H_Z_P_BR_U16:
		case ENC_LDFF1H_Z_P_BR_U32:
		case ENC_LDFF1H_Z_P_BR_U64:
		case ENC_LDFF1SB_Z_P_BR_S16:
		case ENC_LDFF1SB_Z_P_BR_S32:
		case ENC_LDFF1SB_Z_P_BR_S64:
		case ENC_LDFF1SH_Z_P_BR_S32:
		case ENC_LDFF1SH_Z_P_BR_S64:
		case ENC_LDFF1SW_Z_P_BR_S64:
		case ENC_LDFF1W_Z_P_BR_U32:
		case ENC_LDFF1W_Z_P_BR_U64:
			// xxxxxxx|dtype<3:1>=xxx|dtype<0>=x|Rm=xxxxx|xxx|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->dtype = (insword>>22)&7;
			ctx->dtype = (insword>>21)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LD1B_Z_P_BI_U8:
		case ENC_LD1B_Z_P_BI_U16:
		case ENC_LD1B_Z_P_BI_U32:
		case ENC_LD1B_Z_P_BI_U64:
		case ENC_LD1D_Z_P_BI_U64:
		case ENC_LD1H_Z_P_BI_U16:
		case ENC_LD1H_Z_P_BI_U32:
		case ENC_LD1H_Z_P_BI_U64:
		case ENC_LD1SB_Z_P_BI_S16:
		case ENC_LD1SB_Z_P_BI_S32:
		case ENC_LD1SB_Z_P_BI_S64:
		case ENC_LD1SH_Z_P_BI_S32:
		case ENC_LD1SH_Z_P_BI_S64:
		case ENC_LD1SW_Z_P_BI_S64:
		case ENC_LD1W_Z_P_BI_U32:
		case ENC_LD1W_Z_P_BI_U64:
		case ENC_LDNF1B_Z_P_BI_U8:
		case ENC_LDNF1B_Z_P_BI_U16:
		case ENC_LDNF1B_Z_P_BI_U32:
		case ENC_LDNF1B_Z_P_BI_U64:
		case ENC_LDNF1D_Z_P_BI_U64:
		case ENC_LDNF1H_Z_P_BI_U16:
		case ENC_LDNF1H_Z_P_BI_U32:
		case ENC_LDNF1H_Z_P_BI_U64:
		case ENC_LDNF1SB_Z_P_BI_S16:
		case ENC_LDNF1SB_Z_P_BI_S32:
		case ENC_LDNF1SB_Z_P_BI_S64:
		case ENC_LDNF1SH_Z_P_BI_S32:
		case ENC_LDNF1SH_Z_P_BI_S64:
		case ENC_LDNF1SW_Z_P_BI_S64:
		case ENC_LDNF1W_Z_P_BI_U32:
		case ENC_LDNF1W_Z_P_BI_U64:
			// xxxxxxx|dtype<3:1>=xxx|dtype<0>=x|x|imm4=xxxx|xxx|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->dtype = (insword>>22)&7;
			ctx->dtype = (insword>>21)&1;
			ctx->imm4 = (insword>>16)&15;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LD1RB_Z_P_BI_U8:
		case ENC_LD1RB_Z_P_BI_U16:
		case ENC_LD1RB_Z_P_BI_U32:
		case ENC_LD1RB_Z_P_BI_U64:
		case ENC_LD1RD_Z_P_BI_U64:
		case ENC_LD1RH_Z_P_BI_U16:
		case ENC_LD1RH_Z_P_BI_U32:
		case ENC_LD1RH_Z_P_BI_U64:
		case ENC_LD1RSB_Z_P_BI_S16:
		case ENC_LD1RSB_Z_P_BI_S32:
		case ENC_LD1RSB_Z_P_BI_S64:
		case ENC_LD1RSH_Z_P_BI_S32:
		case ENC_LD1RSH_Z_P_BI_S64:
		case ENC_LD1RSW_Z_P_BI_S64:
		case ENC_LD1RW_Z_P_BI_U32:
		case ENC_LD1RW_Z_P_BI_U64:
			// xxxxxxx|dtypeh=xx|x|imm6=xxxxxx|x|dtypel=xx|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->dtypeh = (insword>>23)&3;
			ctx->imm6 = (insword>>16)&0x3f;
			ctx->dtypel = (insword>>13)&3;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LD2B_Z_P_BR_CONTIGUOUS:
		case ENC_LD2D_Z_P_BR_CONTIGUOUS:
		case ENC_LD2H_Z_P_BR_CONTIGUOUS:
		case ENC_LD2W_Z_P_BR_CONTIGUOUS:
		case ENC_LD3B_Z_P_BR_CONTIGUOUS:
		case ENC_LD3D_Z_P_BR_CONTIGUOUS:
		case ENC_LD3H_Z_P_BR_CONTIGUOUS:
		case ENC_LD3W_Z_P_BR_CONTIGUOUS:
		case ENC_LD4B_Z_P_BR_CONTIGUOUS:
		case ENC_LD4D_Z_P_BR_CONTIGUOUS:
		case ENC_LD4H_Z_P_BR_CONTIGUOUS:
		case ENC_LD4W_Z_P_BR_CONTIGUOUS:
		case ENC_ST2B_Z_P_BR_CONTIGUOUS:
		case ENC_ST2D_Z_P_BR_CONTIGUOUS:
		case ENC_ST2H_Z_P_BR_CONTIGUOUS:
		case ENC_ST2W_Z_P_BR_CONTIGUOUS:
		case ENC_ST3B_Z_P_BR_CONTIGUOUS:
		case ENC_ST3D_Z_P_BR_CONTIGUOUS:
		case ENC_ST3H_Z_P_BR_CONTIGUOUS:
		case ENC_ST3W_Z_P_BR_CONTIGUOUS:
		case ENC_ST4B_Z_P_BR_CONTIGUOUS:
		case ENC_ST4D_Z_P_BR_CONTIGUOUS:
		case ENC_ST4H_Z_P_BR_CONTIGUOUS:
		case ENC_ST4W_Z_P_BR_CONTIGUOUS:
			// xxxxxxx|msz=xx|opc=xx|Rm=xxxxx|xxx|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->opc = (insword>>21)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LD2B_Z_P_BI_CONTIGUOUS:
		case ENC_LD2D_Z_P_BI_CONTIGUOUS:
		case ENC_LD2H_Z_P_BI_CONTIGUOUS:
		case ENC_LD2W_Z_P_BI_CONTIGUOUS:
		case ENC_LD3B_Z_P_BI_CONTIGUOUS:
		case ENC_LD3D_Z_P_BI_CONTIGUOUS:
		case ENC_LD3H_Z_P_BI_CONTIGUOUS:
		case ENC_LD3W_Z_P_BI_CONTIGUOUS:
		case ENC_LD4B_Z_P_BI_CONTIGUOUS:
		case ENC_LD4D_Z_P_BI_CONTIGUOUS:
		case ENC_LD4H_Z_P_BI_CONTIGUOUS:
		case ENC_LD4W_Z_P_BI_CONTIGUOUS:
		case ENC_ST2B_Z_P_BI_CONTIGUOUS:
		case ENC_ST2D_Z_P_BI_CONTIGUOUS:
		case ENC_ST2H_Z_P_BI_CONTIGUOUS:
		case ENC_ST2W_Z_P_BI_CONTIGUOUS:
		case ENC_ST3B_Z_P_BI_CONTIGUOUS:
		case ENC_ST3D_Z_P_BI_CONTIGUOUS:
		case ENC_ST3H_Z_P_BI_CONTIGUOUS:
		case ENC_ST3W_Z_P_BI_CONTIGUOUS:
		case ENC_ST4B_Z_P_BI_CONTIGUOUS:
		case ENC_ST4D_Z_P_BI_CONTIGUOUS:
		case ENC_ST4H_Z_P_BI_CONTIGUOUS:
		case ENC_ST4W_Z_P_BI_CONTIGUOUS:
			// xxxxxxx|msz=xx|opc=xx|x|imm4=xxxx|xxx|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->opc = (insword>>21)&3;
			ctx->imm4 = (insword>>16)&15;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_ST1B_Z_P_BI_:
		case ENC_ST1D_Z_P_BI_:
		case ENC_ST1H_Z_P_BI_:
		case ENC_ST1W_Z_P_BI_:
			// xxxxxxx|msz=xx|size=xx|x|imm4=xxxx|xxx|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->size = (insword>>21)&3;
			ctx->imm4 = (insword>>16)&15;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LD1ROB_Z_P_BR_CONTIGUOUS:
		case ENC_LD1ROD_Z_P_BR_CONTIGUOUS:
		case ENC_LD1ROH_Z_P_BR_CONTIGUOUS:
		case ENC_LD1ROW_Z_P_BR_CONTIGUOUS:
		case ENC_LD1RQB_Z_P_BR_CONTIGUOUS:
		case ENC_LD1RQD_Z_P_BR_CONTIGUOUS:
		case ENC_LD1RQH_Z_P_BR_CONTIGUOUS:
		case ENC_LD1RQW_Z_P_BR_CONTIGUOUS:
			// xxxxxxx|msz=xx|ssz=xx|Rm=xxxxx|xxx|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->ssz = (insword>>21)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LD1ROB_Z_P_BI_U8:
		case ENC_LD1ROD_Z_P_BI_U64:
		case ENC_LD1ROH_Z_P_BI_U16:
		case ENC_LD1ROW_Z_P_BI_U32:
		case ENC_LD1RQB_Z_P_BI_U8:
		case ENC_LD1RQD_Z_P_BI_U64:
		case ENC_LD1RQH_Z_P_BI_U16:
		case ENC_LD1RQW_Z_P_BI_U32:
			// xxxxxxx|msz=xx|ssz=xx|x|imm4=xxxx|xxx|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->ssz = (insword>>21)&3;
			ctx->imm4 = (insword>>16)&15;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LD1B_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LD1D_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LD1H_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LD1SB_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LD1SH_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LD1SW_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LD1W_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LDFF1B_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LDFF1D_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LDFF1H_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LDFF1SB_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LDFF1SH_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LDFF1SW_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LDFF1W_Z_P_BZ_D_X32_UNSCALED:
			// xxxxxxx|msz=xx|xs=x|x|Zm=xxxxx|x|U=x|ff=x|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->xs = (insword>>22)&1;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->U = (insword>>14)&1;
			ctx->ff = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LDNT1B_Z_P_BI_CONTIGUOUS:
		case ENC_LDNT1D_Z_P_BI_CONTIGUOUS:
		case ENC_LDNT1H_Z_P_BI_CONTIGUOUS:
		case ENC_LDNT1W_Z_P_BI_CONTIGUOUS:
		case ENC_STNT1B_Z_P_BI_CONTIGUOUS:
		case ENC_STNT1D_Z_P_BI_CONTIGUOUS:
		case ENC_STNT1H_Z_P_BI_CONTIGUOUS:
		case ENC_STNT1W_Z_P_BI_CONTIGUOUS:
			// xxxxxxx|msz=xx|xxx|imm4=xxxx|xxx|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->imm4 = (insword>>16)&15;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LDNT1B_Z_P_BR_CONTIGUOUS:
		case ENC_LDNT1D_Z_P_BR_CONTIGUOUS:
		case ENC_LDNT1H_Z_P_BR_CONTIGUOUS:
		case ENC_LDNT1W_Z_P_BR_CONTIGUOUS:
		case ENC_STNT1B_Z_P_BR_CONTIGUOUS:
		case ENC_STNT1D_Z_P_BR_CONTIGUOUS:
		case ENC_STNT1H_Z_P_BR_CONTIGUOUS:
		case ENC_STNT1W_Z_P_BR_CONTIGUOUS:
			// xxxxxxx|msz=xx|xx|Rm=xxxxx|xxx|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_PRFB_I_P_BR_S:
		case ENC_PRFD_I_P_BR_S:
		case ENC_PRFH_I_P_BR_S:
		case ENC_PRFW_I_P_BR_S:
			// xxxxxxx|msz=xx|xx|Rm=xxxxx|xxx|Pg=xxx|Rn=xxxxx|x|prfop=xxxx
			ctx->msz = (insword>>23)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->prfop = insword&15;
			break;
		case ENC_STNT1B_Z_P_AR_S_X32_UNSCALED:
		case ENC_STNT1B_Z_P_AR_D_64_UNSCALED:
		case ENC_STNT1D_Z_P_AR_D_64_UNSCALED:
		case ENC_STNT1H_Z_P_AR_S_X32_UNSCALED:
		case ENC_STNT1H_Z_P_AR_D_64_UNSCALED:
		case ENC_STNT1W_Z_P_AR_S_X32_UNSCALED:
		case ENC_STNT1W_Z_P_AR_D_64_UNSCALED:
			// xxxxxxx|msz=xx|xx|Rm=xxxxx|xxx|Pg=xxx|Zn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LDNT1B_Z_P_AR_S_X32_UNSCALED:
		case ENC_LDNT1H_Z_P_AR_S_X32_UNSCALED:
		case ENC_LDNT1SB_Z_P_AR_S_X32_UNSCALED:
		case ENC_LDNT1SH_Z_P_AR_S_X32_UNSCALED:
		case ENC_LDNT1W_Z_P_AR_S_X32_UNSCALED:
			// xxxxxxx|msz=xx|xx|Rm=xxxxx|xx|U=x|Pg=xxx|Zn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->U = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LDNT1B_Z_P_AR_D_64_UNSCALED:
		case ENC_LDNT1D_Z_P_AR_D_64_UNSCALED:
		case ENC_LDNT1H_Z_P_AR_D_64_UNSCALED:
		case ENC_LDNT1SB_Z_P_AR_D_64_UNSCALED:
		case ENC_LDNT1SH_Z_P_AR_D_64_UNSCALED:
		case ENC_LDNT1SW_Z_P_AR_D_64_UNSCALED:
		case ENC_LDNT1W_Z_P_AR_D_64_UNSCALED:
			// xxxxxxx|msz=xx|xx|Rm=xxxxx|x|U=x|x|Pg=xxx|Zn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->U = (insword>>14)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_ST1B_Z_P_BZ_D_64_UNSCALED:
		case ENC_ST1D_Z_P_BZ_D_64_SCALED:
		case ENC_ST1D_Z_P_BZ_D_64_UNSCALED:
		case ENC_ST1H_Z_P_BZ_D_64_SCALED:
		case ENC_ST1H_Z_P_BZ_D_64_UNSCALED:
		case ENC_ST1W_Z_P_BZ_D_64_SCALED:
		case ENC_ST1W_Z_P_BZ_D_64_UNSCALED:
			// xxxxxxx|msz=xx|xx|Zm=xxxxx|xxx|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LD1B_Z_P_BZ_D_64_UNSCALED:
		case ENC_LD1D_Z_P_BZ_D_64_UNSCALED:
		case ENC_LD1H_Z_P_BZ_D_64_UNSCALED:
		case ENC_LD1SB_Z_P_BZ_D_64_UNSCALED:
		case ENC_LD1SH_Z_P_BZ_D_64_UNSCALED:
		case ENC_LD1SW_Z_P_BZ_D_64_UNSCALED:
		case ENC_LD1W_Z_P_BZ_D_64_UNSCALED:
		case ENC_LDFF1B_Z_P_BZ_D_64_UNSCALED:
		case ENC_LDFF1D_Z_P_BZ_D_64_UNSCALED:
		case ENC_LDFF1H_Z_P_BZ_D_64_UNSCALED:
		case ENC_LDFF1SB_Z_P_BZ_D_64_UNSCALED:
		case ENC_LDFF1SH_Z_P_BZ_D_64_UNSCALED:
		case ENC_LDFF1SW_Z_P_BZ_D_64_UNSCALED:
		case ENC_LDFF1W_Z_P_BZ_D_64_UNSCALED:
			// xxxxxxx|msz=xx|xx|Zm=xxxxx|x|U=x|ff=x|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->U = (insword>>14)&1;
			ctx->ff = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_ST1B_Z_P_BZ_D_X32_UNSCALED:
		case ENC_ST1B_Z_P_BZ_S_X32_UNSCALED:
		case ENC_ST1D_Z_P_BZ_D_X32_SCALED:
		case ENC_ST1D_Z_P_BZ_D_X32_UNSCALED:
		case ENC_ST1H_Z_P_BZ_S_X32_SCALED:
		case ENC_ST1H_Z_P_BZ_D_X32_SCALED:
		case ENC_ST1H_Z_P_BZ_D_X32_UNSCALED:
		case ENC_ST1H_Z_P_BZ_S_X32_UNSCALED:
		case ENC_ST1W_Z_P_BZ_S_X32_SCALED:
		case ENC_ST1W_Z_P_BZ_D_X32_SCALED:
		case ENC_ST1W_Z_P_BZ_D_X32_UNSCALED:
		case ENC_ST1W_Z_P_BZ_S_X32_UNSCALED:
			// xxxxxxx|msz=xx|xx|Zm=xxxxx|x|xs=x|x|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->xs = (insword>>14)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_ST1B_Z_P_AI_S:
		case ENC_ST1B_Z_P_AI_D:
		case ENC_ST1D_Z_P_AI_D:
		case ENC_ST1H_Z_P_AI_S:
		case ENC_ST1H_Z_P_AI_D:
		case ENC_ST1W_Z_P_AI_S:
		case ENC_ST1W_Z_P_AI_D:
			// xxxxxxx|msz=xx|xx|imm5=xxxxx|xxx|Pg=xxx|Zn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->imm5 = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_PRFB_I_P_AI_S:
		case ENC_PRFB_I_P_AI_D:
		case ENC_PRFD_I_P_AI_S:
		case ENC_PRFD_I_P_AI_D:
		case ENC_PRFH_I_P_AI_S:
		case ENC_PRFH_I_P_AI_D:
		case ENC_PRFW_I_P_AI_S:
		case ENC_PRFW_I_P_AI_D:
			// xxxxxxx|msz=xx|xx|imm5=xxxxx|xxx|Pg=xxx|Zn=xxxxx|x|prfop=xxxx
			ctx->msz = (insword>>23)&3;
			ctx->imm5 = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->prfop = insword&15;
			break;
		case ENC_LD1B_Z_P_AI_S:
		case ENC_LD1B_Z_P_AI_D:
		case ENC_LD1D_Z_P_AI_D:
		case ENC_LD1H_Z_P_AI_S:
		case ENC_LD1H_Z_P_AI_D:
		case ENC_LD1SB_Z_P_AI_S:
		case ENC_LD1SB_Z_P_AI_D:
		case ENC_LD1SH_Z_P_AI_S:
		case ENC_LD1SH_Z_P_AI_D:
		case ENC_LD1SW_Z_P_AI_D:
		case ENC_LD1W_Z_P_AI_S:
		case ENC_LD1W_Z_P_AI_D:
		case ENC_LDFF1B_Z_P_AI_S:
		case ENC_LDFF1B_Z_P_AI_D:
		case ENC_LDFF1D_Z_P_AI_D:
		case ENC_LDFF1H_Z_P_AI_S:
		case ENC_LDFF1H_Z_P_AI_D:
		case ENC_LDFF1SB_Z_P_AI_S:
		case ENC_LDFF1SB_Z_P_AI_D:
		case ENC_LDFF1SH_Z_P_AI_S:
		case ENC_LDFF1SH_Z_P_AI_D:
		case ENC_LDFF1SW_Z_P_AI_D:
		case ENC_LDFF1W_Z_P_AI_S:
		case ENC_LDFF1W_Z_P_AI_D:
			// xxxxxxx|msz=xx|xx|imm5=xxxxx|x|U=x|ff=x|Pg=xxx|Zn=xxxxx|Zt=xxxxx
			ctx->msz = (insword>>23)&3;
			ctx->imm5 = (insword>>16)&0x1f;
			ctx->U = (insword>>14)&1;
			ctx->ff = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_B_ONLY_CONDBRANCH:
			// xxxxxxx|o1=x|imm19=xxxxxxxxxxxxxxxxxxx|o0=x|cond=xxxx
			ctx->o1 = (insword>>24)&1;
			ctx->imm19 = (insword>>5)&0x7ffff;
			ctx->o0 = (insword>>4)&1;
			ctx->cond = insword&15;
			break;
		case ENC_ST1D_Z_P_BR_:
			// xxxxxxx|opc<2:1>=xx|opc<0>=x|o2=x|Rm=xxxxx|xxx|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->opc = (insword>>23)&3;
			ctx->opc = (insword>>22)&1;
			ctx->o2 = (insword>>21)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_DRPS_64E_BRANCH_REG:
			// xxxxxxx|opc=xxxx|op2=xxxxx|op3=xxxxxx|Rt=xxxxx|op4=xxxxx
			ctx->opc = (insword>>21)&15;
			ctx->op2 = (insword>>16)&0x1f;
			ctx->op3 = (insword>>10)&0x3f;
			ctx->Rt = (insword>>5)&0x1f;
			ctx->op4 = insword&0x1f;
			break;
		case ENC_LD1B_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LD1D_Z_P_BZ_D_X32_SCALED:
		case ENC_LD1H_Z_P_BZ_D_X32_SCALED:
		case ENC_LD1H_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LD1SB_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LD1SH_Z_P_BZ_D_X32_SCALED:
		case ENC_LD1SH_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LD1SW_Z_P_BZ_D_X32_SCALED:
		case ENC_LD1W_Z_P_BZ_D_X32_SCALED:
		case ENC_LD1W_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LDFF1B_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LDFF1D_Z_P_BZ_D_X32_SCALED:
		case ENC_LDFF1H_Z_P_BZ_D_X32_SCALED:
		case ENC_LDFF1H_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LDFF1SB_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LDFF1SH_Z_P_BZ_D_X32_SCALED:
		case ENC_LDFF1SH_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LDFF1SW_Z_P_BZ_D_X32_SCALED:
		case ENC_LDFF1W_Z_P_BZ_D_X32_SCALED:
		case ENC_LDFF1W_Z_P_BZ_S_X32_UNSCALED:
			// xxxxxxx|opc=xx|xs=x|x|Zm=xxxxx|x|U=x|ff=x|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->opc = (insword>>23)&3;
			ctx->xs = (insword>>22)&1;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->U = (insword>>14)&1;
			ctx->ff = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_LD1D_Z_P_BZ_D_64_SCALED:
		case ENC_LD1H_Z_P_BZ_D_64_SCALED:
		case ENC_LD1SH_Z_P_BZ_D_64_SCALED:
		case ENC_LD1SW_Z_P_BZ_D_64_SCALED:
		case ENC_LD1W_Z_P_BZ_D_64_SCALED:
		case ENC_LDFF1D_Z_P_BZ_D_64_SCALED:
		case ENC_LDFF1H_Z_P_BZ_D_64_SCALED:
		case ENC_LDFF1SH_Z_P_BZ_D_64_SCALED:
		case ENC_LDFF1SW_Z_P_BZ_D_64_SCALED:
		case ENC_LDFF1W_Z_P_BZ_D_64_SCALED:
			// xxxxxxx|opc=xx|xx|Zm=xxxxx|x|U=x|ff=x|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->opc = (insword>>23)&3;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->U = (insword>>14)&1;
			ctx->ff = (insword>>13)&1;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_ERET_64E_BRANCH_REG:
		case ENC_ERETAA_64E_BRANCH_REG:
		case ENC_ERETAB_64E_BRANCH_REG:
			// xxxxxxx|opc[3]=x|opc[2:0]=xxx|op2=xxxxx|op3[5:2]=xxxx|A=x|M=x|Rn=xxxxx|op4=xxxxx
			ctx->opc = (insword>>24)&1;
			ctx->opc = (insword>>21)&7;
			ctx->op2 = (insword>>16)&0x1f;
			ctx->op3 = (insword>>12)&15;
			ctx->A = (insword>>11)&1;
			ctx->M = (insword>>10)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->op4 = insword&0x1f;
			break;
		case ENC_ST1B_Z_P_BR_:
		case ENC_ST1H_Z_P_BR_:
		case ENC_ST1W_Z_P_BR_:
			// xxxxxxx|xx|size=xx|Rm=xxxxx|xxx|Pg=xxx|Rn=xxxxx|Zt=xxxxx
			ctx->size = (insword>>21)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Pg = (insword>>10)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Zt = insword&0x1f;
			break;
		case ENC_FCVTZS_ASISDSHF_C:
		case ENC_FCVTZU_ASISDSHF_C:
		case ENC_SCVTF_ASISDSHF_C:
		case ENC_SHL_ASISDSHF_R:
		case ENC_SLI_ASISDSHF_R:
		case ENC_SRI_ASISDSHF_R:
		case ENC_UCVTF_ASISDSHF_C:
			// xx|U=x|xxxxxx|immh=xxxx|immb=xxx|opcode=xxxxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->immh = (insword>>19)&15;
			ctx->immb = (insword>>16)&7;
			ctx->opcode = (insword>>11)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SQRSHRN_ASISDSHF_N:
		case ENC_SQRSHRUN_ASISDSHF_N:
		case ENC_SQSHRN_ASISDSHF_N:
		case ENC_SQSHRUN_ASISDSHF_N:
		case ENC_UQRSHRN_ASISDSHF_N:
		case ENC_UQSHRN_ASISDSHF_N:
			// xx|U=x|xxxxxx|immh=xxxx|immb=xxx|opcode[4:1]=xxxx|op=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->immh = (insword>>19)&15;
			ctx->immb = (insword>>16)&7;
			ctx->opcode = (insword>>12)&15;
			ctx->op = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SQSHLU_ASISDSHF_R:
		case ENC_SQSHL_ASISDSHF_R:
		case ENC_UQSHL_ASISDSHF_R:
			// xx|U=x|xxxxxx|immh=xxxx|immb=xxx|opcode[4:2]=xxx|op=x|opcode[0]=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->immh = (insword>>19)&15;
			ctx->immb = (insword>>16)&7;
			ctx->opcode = (insword>>13)&7;
			ctx->op = (insword>>12)&1;
			ctx->opcode = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SRSHR_ASISDSHF_R:
		case ENC_SRSRA_ASISDSHF_R:
		case ENC_SSHR_ASISDSHF_R:
		case ENC_SSRA_ASISDSHF_R:
		case ENC_URSHR_ASISDSHF_R:
		case ENC_URSRA_ASISDSHF_R:
		case ENC_USHR_ASISDSHF_R:
		case ENC_USRA_ASISDSHF_R:
			// xx|U=x|xxxxxx|immh=xxxx|immb=xxx|opcode[4:3]=xx|o1=x|o0=x|opcode[0]=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->immh = (insword>>19)&15;
			ctx->immb = (insword>>16)&7;
			ctx->opcode = (insword>>14)&3;
			ctx->o1 = (insword>>13)&1;
			ctx->o0 = (insword>>12)&1;
			ctx->opcode = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FACGE_ASISDSAME_ONLY:
		case ENC_FACGT_ASISDSAME_ONLY:
		case ENC_FCMEQ_ASISDSAME_ONLY:
		case ENC_FCMGE_ASISDSAME_ONLY:
		case ENC_FCMGT_ASISDSAME_ONLY:
			// xx|U=x|xxxxx|E=x|sz=x|x|Rm=xxxxx|opcode[4:1]=xxxx|ac=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->E = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>12)&15;
			ctx->ac = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FACGE_ASISDSAMEFP16_ONLY:
		case ENC_FACGT_ASISDSAMEFP16_ONLY:
		case ENC_FCMEQ_ASISDSAMEFP16_ONLY:
		case ENC_FCMGE_ASISDSAMEFP16_ONLY:
		case ENC_FCMGT_ASISDSAMEFP16_ONLY:
			// xx|U=x|xxxxx|E=x|xx|Rm=xxxxx|xx|opcode[2:1]=xx|ac=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->E = (insword>>23)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>12)&3;
			ctx->ac = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCMLT_ASISDMISCFP16_FZ:
		case ENC_FRECPX_ASISDMISCFP16_R:
		case ENC_FRSQRTE_ASISDMISCFP16_R:
		case ENC_SCVTF_ASISDMISCFP16_R:
		case ENC_UCVTF_ASISDMISCFP16_R:
			// xx|U=x|xxxxx|a=x|xxxxxx|opcode=xxxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->a = (insword>>23)&1;
			ctx->opcode = (insword>>12)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCMEQ_ASISDMISCFP16_FZ:
		case ENC_FCMGE_ASISDMISCFP16_FZ:
		case ENC_FCMGT_ASISDMISCFP16_FZ:
		case ENC_FCMLE_ASISDMISCFP16_FZ:
			// xx|U=x|xxxxx|a=x|xxxxxx|opcode[4:1]=xxxx|op=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->a = (insword>>23)&1;
			ctx->opcode = (insword>>13)&15;
			ctx->op = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FABD_ASISDSAMEFP16_ONLY:
		case ENC_FMULX_ASISDSAMEFP16_ONLY:
		case ENC_FRECPS_ASISDSAMEFP16_ONLY:
		case ENC_FRSQRTS_ASISDSAMEFP16_ONLY:
			// xx|U=x|xxxxx|a=x|xx|Rm=xxxxx|xx|opcode=xxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->a = (insword>>23)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>11)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMAXNMP_ASISDPAIR_ONLY_H:
		case ENC_FMAXNMP_ASISDPAIR_ONLY_SD:
		case ENC_FMAXP_ASISDPAIR_ONLY_H:
		case ENC_FMAXP_ASISDPAIR_ONLY_SD:
		case ENC_FMINNMP_ASISDPAIR_ONLY_H:
		case ENC_FMINNMP_ASISDPAIR_ONLY_SD:
		case ENC_FMINP_ASISDPAIR_ONLY_H:
		case ENC_FMINP_ASISDPAIR_ONLY_SD:
			// xx|U=x|xxxxx|o1=x|sz=x|xxxxx|opcode=xxxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->o1 = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->opcode = (insword>>12)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCVTMS_ASISDMISC_R:
		case ENC_FCVTMU_ASISDMISC_R:
		case ENC_FCVTNS_ASISDMISC_R:
		case ENC_FCVTNU_ASISDMISC_R:
		case ENC_FCVTPS_ASISDMISC_R:
		case ENC_FCVTPU_ASISDMISC_R:
		case ENC_FCVTZS_ASISDMISC_R:
		case ENC_FCVTZU_ASISDMISC_R:
			// xx|U=x|xxxxx|o2=x|sz=x|xxxxx|opcode[4:1]=xxxx|o1=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->o2 = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->opcode = (insword>>13)&15;
			ctx->o1 = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCVTMS_ASISDMISCFP16_R:
		case ENC_FCVTMU_ASISDMISCFP16_R:
		case ENC_FCVTNS_ASISDMISCFP16_R:
		case ENC_FCVTNU_ASISDMISCFP16_R:
		case ENC_FCVTPS_ASISDMISCFP16_R:
		case ENC_FCVTPU_ASISDMISCFP16_R:
		case ENC_FCVTZS_ASISDMISCFP16_R:
		case ENC_FCVTZU_ASISDMISCFP16_R:
			// xx|U=x|xxxxx|o2=x|xxxxxx|opcode[4:1]=xxxx|o1=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->o2 = (insword>>23)&1;
			ctx->opcode = (insword>>13)&15;
			ctx->o1 = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMULX_ASISDELEM_RH_H:
		case ENC_FMUL_ASISDELEM_RH_H:
		case ENC_SQDMULL_ASISDELEM_L:
			// xx|U=x|xxxxx|size=xx|L=x|M=x|Rm=xxxx|opcode=xxxx|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->opcode = (insword>>12)&15;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SQDMULH_ASISDELEM_R:
		case ENC_SQRDMULH_ASISDELEM_R:
			// xx|U=x|xxxxx|size=xx|L=x|M=x|Rm=xxxx|opcode[3:1]=xxx|op=x|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->opcode = (insword>>13)&7;
			ctx->op = (insword>>12)&1;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SQRDMLAH_ASISDELEM_R:
		case ENC_SQRDMLSH_ASISDELEM_R:
			// xx|U=x|xxxxx|size=xx|L=x|M=x|Rm=xxxx|opcode[3:2]=xx|S=x|opcode[0]=x|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->opcode = (insword>>14)&3;
			ctx->S = (insword>>13)&1;
			ctx->opcode = (insword>>12)&1;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMLA_ASISDELEM_RH_H:
		case ENC_FMLS_ASISDELEM_RH_H:
		case ENC_SQDMLAL_ASISDELEM_L:
		case ENC_SQDMLSL_ASISDELEM_L:
			// xx|U=x|xxxxx|size=xx|L=x|M=x|Rm=xxxx|opcode[3]=x|o2=x|opcode[1:0]=xx|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->opcode = (insword>>15)&1;
			ctx->o2 = (insword>>14)&1;
			ctx->opcode = (insword>>12)&3;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_ABS_ASISDMISC_R:
		case ENC_ADDP_ASISDPAIR_ONLY:
		case ENC_CMLT_ASISDMISC_Z:
		case ENC_NEG_ASISDMISC_R:
		case ENC_SQABS_ASISDMISC_R:
		case ENC_SQNEG_ASISDMISC_R:
		case ENC_SQXTN_ASISDMISC_N:
		case ENC_SQXTUN_ASISDMISC_N:
		case ENC_SUQADD_ASISDMISC_R:
		case ENC_UQXTN_ASISDMISC_N:
		case ENC_USQADD_ASISDMISC_R:
			// xx|U=x|xxxxx|size=xx|xxxxx|opcode=xxxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->opcode = (insword>>12)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_CMEQ_ASISDMISC_Z:
		case ENC_CMGE_ASISDMISC_Z:
		case ENC_CMGT_ASISDMISC_Z:
		case ENC_CMLE_ASISDMISC_Z:
			// xx|U=x|xxxxx|size=xx|xxxxx|opcode[4:1]=xxxx|op=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->opcode = (insword>>13)&15;
			ctx->op = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_ADD_ASISDSAME_ONLY:
		case ENC_CMEQ_ASISDSAME_ONLY:
		case ENC_CMTST_ASISDSAME_ONLY:
		case ENC_SQADD_ASISDSAME_ONLY:
		case ENC_SQDMULH_ASISDSAME_ONLY:
		case ENC_SQRDMULH_ASISDSAME_ONLY:
		case ENC_SQSUB_ASISDSAME_ONLY:
		case ENC_SUB_ASISDSAME_ONLY:
		case ENC_UQADD_ASISDSAME_ONLY:
		case ENC_UQSUB_ASISDSAME_ONLY:
			// xx|U=x|xxxxx|size=xx|x|Rm=xxxxx|opcode=xxxxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>11)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SQDMULL_ASISDDIFF_ONLY:
			// xx|U=x|xxxxx|size=xx|x|Rm=xxxxx|opcode=xxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>12)&15;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SQDMLAL_ASISDDIFF_ONLY:
		case ENC_SQDMLSL_ASISDDIFF_ONLY:
			// xx|U=x|xxxxx|size=xx|x|Rm=xxxxx|opcode[3:2]=xx|o1=x|opcode[0]=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>14)&3;
			ctx->o1 = (insword>>13)&1;
			ctx->opcode = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_CMGE_ASISDSAME_ONLY:
		case ENC_CMGT_ASISDSAME_ONLY:
		case ENC_CMHI_ASISDSAME_ONLY:
		case ENC_CMHS_ASISDSAME_ONLY:
			// xx|U=x|xxxxx|size=xx|x|Rm=xxxxx|opcode[4:1]=xxxx|eq=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>12)&15;
			ctx->eq = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SQRSHL_ASISDSAME_ONLY:
		case ENC_SQSHL_ASISDSAME_ONLY:
		case ENC_SRSHL_ASISDSAME_ONLY:
		case ENC_SSHL_ASISDSAME_ONLY:
		case ENC_UQRSHL_ASISDSAME_ONLY:
		case ENC_UQSHL_ASISDSAME_ONLY:
		case ENC_URSHL_ASISDSAME_ONLY:
		case ENC_USHL_ASISDSAME_ONLY:
			// xx|U=x|xxxxx|size=xx|x|Rm=xxxxx|opcode[4:2]=xxx|R=x|S=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>13)&7;
			ctx->R = (insword>>12)&1;
			ctx->S = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SQRDMLAH_ASISDSAME2_ONLY:
		case ENC_SQRDMLSH_ASISDSAME2_ONLY:
			// xx|U=x|xxxxx|size=xx|x|Rm=xxxxx|x|opcode[3:1]=xxx|S=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>12)&7;
			ctx->S = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMULX_ASISDELEM_R_SD:
		case ENC_FMUL_ASISDELEM_R_SD:
			// xx|U=x|xxxxx|size[1]=x|sz=x|L=x|M=x|Rm=xxxx|opcode=xxxx|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->opcode = (insword>>12)&15;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMLA_ASISDELEM_R_SD:
		case ENC_FMLS_ASISDELEM_R_SD:
			// xx|U=x|xxxxx|size[1]=x|sz=x|L=x|M=x|Rm=xxxx|opcode[3]=x|o2=x|opcode[1:0]=xx|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->opcode = (insword>>15)&1;
			ctx->o2 = (insword>>14)&1;
			ctx->opcode = (insword>>12)&3;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FADDP_ASISDPAIR_ONLY_H:
		case ENC_FADDP_ASISDPAIR_ONLY_SD:
		case ENC_FCMLT_ASISDMISC_FZ:
		case ENC_FCVTAS_ASISDMISC_R:
		case ENC_FCVTAU_ASISDMISC_R:
		case ENC_FCVTXN_ASISDMISC_N:
		case ENC_FRECPE_ASISDMISC_R:
		case ENC_FRECPX_ASISDMISC_R:
		case ENC_FRSQRTE_ASISDMISC_R:
		case ENC_SCVTF_ASISDMISC_R:
		case ENC_UCVTF_ASISDMISC_R:
			// xx|U=x|xxxxx|size[1]=x|sz=x|xxxxx|opcode=xxxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->opcode = (insword>>12)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCMEQ_ASISDMISC_FZ:
		case ENC_FCMGE_ASISDMISC_FZ:
		case ENC_FCMGT_ASISDMISC_FZ:
		case ENC_FCMLE_ASISDMISC_FZ:
			// xx|U=x|xxxxx|size[1]=x|sz=x|xxxxx|opcode[4:1]=xxxx|op=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->opcode = (insword>>13)&15;
			ctx->op = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FABD_ASISDSAME_ONLY:
		case ENC_FMULX_ASISDSAME_ONLY:
		case ENC_FRECPS_ASISDSAME_ONLY:
		case ENC_FRSQRTS_ASISDSAME_ONLY:
			// xx|U=x|xxxxx|size[1]=x|sz=x|x|Rm=xxxxx|opcode=xxxxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>11)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCVTAS_ASISDMISCFP16_R:
		case ENC_FCVTAU_ASISDMISCFP16_R:
		case ENC_FRECPE_ASISDMISCFP16_R:
			// xx|U=x|xxxxx|size[1]=x|xxxxxx|opcode=xxxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>23)&1;
			ctx->opcode = (insword>>12)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_DUP_ASISDONE_ONLY:
		case ENC_MOV_DUP_ASISDONE_ONLY:
			// xx|op=x|xxxxxxxx|imm5=xxxxx|x|imm4=xxxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->op = (insword>>29)&1;
			ctx->imm5 = (insword>>16)&0x1f;
			ctx->imm4 = (insword>>11)&15;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMOPA_ZA_PP_ZZ_64:
		case ENC_FMOPS_ZA_PP_ZZ_64:
			// xx|xxxxxxxxx|Zm=xxxxx|Pm=xxx|Pn=xxx|Zn=xxxxx|S=x|x|ZAda=xxx
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Pm = (insword>>13)&7;
			ctx->Pn = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->S = (insword>>4)&1;
			ctx->ZAda = insword&7;
			break;
		case ENC_BFMOPA_ZA32_PP_ZZ_:
		case ENC_BFMOPS_ZA32_PP_ZZ_:
		case ENC_FMOPA_ZA32_PP_ZZ_16:
		case ENC_FMOPA_ZA_PP_ZZ_32:
		case ENC_FMOPS_ZA32_PP_ZZ_16:
		case ENC_FMOPS_ZA_PP_ZZ_32:
			// xx|xxxxxxxxx|Zm=xxxxx|Pm=xxx|Pn=xxx|Zn=xxxxx|S=x|x|x|ZAda=xx
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Pm = (insword>>13)&7;
			ctx->Pn = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->S = (insword>>4)&1;
			ctx->ZAda = insword&3;
			break;
		case ENC_ADDHA_ZA_PP_Z_64:
		case ENC_ADDVA_ZA_PP_Z_64:
			// xx|xxxxxxx|op=x|xxxxx|V=x|Pm=xxx|Pn=xxx|Zn=xxxxx|x|x|ZAda=xxx
			ctx->op = (insword>>22)&1;
			ctx->V = (insword>>16)&1;
			ctx->Pm = (insword>>13)&7;
			ctx->Pn = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->ZAda = insword&7;
			break;
		case ENC_ADDHA_ZA_PP_Z_32:
		case ENC_ADDVA_ZA_PP_Z_32:
			// xx|xxxxxxx|op=x|xx|xxx|V=x|Pm=xxx|Pn=xxx|Zn=xxxxx|x|x|x|ZAda=xx
			ctx->op = (insword>>22)&1;
			ctx->V = (insword>>16)&1;
			ctx->Pm = (insword>>13)&7;
			ctx->Pn = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->ZAda = insword&3;
			break;
		case ENC_PTEST_P_P_:
			// xx|xxxxxx|op=x|S=x|xx|xxxxxx|Pg=xxxx|x|Pn=xxxx|x|opc2=xxxx
			ctx->op = (insword>>23)&1;
			ctx->S = (insword>>22)&1;
			ctx->Pg = (insword>>10)&15;
			ctx->Pn = (insword>>5)&15;
			ctx->opc2 = insword&15;
			break;
		case ENC_CTERMEQ_RR_:
		case ENC_CTERMNE_RR_:
			// xx|xxxxxx|op=x|sz=x|x|Rm=xxxxx|xxxxxx|Rn=xxxxx|ne=x|x|x|xx
			ctx->op = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->ne = (insword>>4)&1;
			break;
		case ENC_SETFFR_F_:
			// xx|xxxxxx|opc=xx|xx|xxxxxxxxxx|xxxxxx|x|x|xx
			ctx->opc = (insword>>22)&3;
			break;
		case ENC_WRFFR_F_P_:
			// xx|xxxxxx|opc=xx|xx|xxxxxxxxxx|x|Pn=xxxx|x|x|x|xx
			ctx->opc = (insword>>22)&3;
			ctx->Pn = (insword>>5)&15;
			break;
		case ENC_SMOPA_ZA_PP_ZZ_64:
		case ENC_SMOPS_ZA_PP_ZZ_64:
		case ENC_SUMOPA_ZA_PP_ZZ_64:
		case ENC_SUMOPS_ZA_PP_ZZ_64:
		case ENC_UMOPA_ZA_PP_ZZ_64:
		case ENC_UMOPS_ZA_PP_ZZ_64:
		case ENC_USMOPA_ZA_PP_ZZ_64:
		case ENC_USMOPS_ZA_PP_ZZ_64:
			// xx|xxxxx|u0=x|xx|u1=x|Zm=xxxxx|Pm=xxx|Pn=xxx|Zn=xxxxx|S=x|x|ZAda=xxx
			ctx->u0 = (insword>>24)&1;
			ctx->u1 = (insword>>21)&1;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Pm = (insword>>13)&7;
			ctx->Pn = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->S = (insword>>4)&1;
			ctx->ZAda = insword&7;
			break;
		case ENC_SMOPA_ZA_PP_ZZ_32:
		case ENC_SMOPS_ZA_PP_ZZ_32:
		case ENC_SUMOPA_ZA_PP_ZZ_32:
		case ENC_SUMOPS_ZA_PP_ZZ_32:
		case ENC_UMOPA_ZA_PP_ZZ_32:
		case ENC_UMOPS_ZA_PP_ZZ_32:
		case ENC_USMOPA_ZA_PP_ZZ_32:
		case ENC_USMOPS_ZA_PP_ZZ_32:
			// xx|xxxxx|u0=x|xx|u1=x|Zm=xxxxx|Pm=xxx|Pn=xxx|Zn=xxxxx|S=x|x|x|ZAda=xx
			ctx->u0 = (insword>>24)&1;
			ctx->u1 = (insword>>21)&1;
			ctx->Zm = (insword>>16)&0x1f;
			ctx->Pm = (insword>>13)&7;
			ctx->Pn = (insword>>10)&7;
			ctx->Zn = (insword>>5)&0x1f;
			ctx->S = (insword>>4)&1;
			ctx->ZAda = insword&3;
			break;
		case ENC_FCVTZS_ASIMDSHF_C:
		case ENC_FCVTZU_ASIMDSHF_C:
		case ENC_SCVTF_ASIMDSHF_C:
		case ENC_SHL_ASIMDSHF_R:
		case ENC_SLI_ASIMDSHF_R:
		case ENC_SRI_ASIMDSHF_R:
		case ENC_SSHLL_ASIMDSHF_L:
		case ENC_SXTL_SSHLL_ASIMDSHF_L:
		case ENC_UCVTF_ASIMDSHF_C:
		case ENC_USHLL_ASIMDSHF_L:
		case ENC_UXTL_USHLL_ASIMDSHF_L:
			// x|Q=x|U=x|xxxxxx|immh=xxxx|immb=xxx|opcode=xxxxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->immh = (insword>>19)&15;
			ctx->immb = (insword>>16)&7;
			ctx->opcode = (insword>>11)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_RSHRN_ASIMDSHF_N:
		case ENC_SHRN_ASIMDSHF_N:
		case ENC_SQRSHRN_ASIMDSHF_N:
		case ENC_SQRSHRUN_ASIMDSHF_N:
		case ENC_SQSHRN_ASIMDSHF_N:
		case ENC_SQSHRUN_ASIMDSHF_N:
		case ENC_UQRSHRN_ASIMDSHF_N:
		case ENC_UQSHRN_ASIMDSHF_N:
			// x|Q=x|U=x|xxxxxx|immh=xxxx|immb=xxx|opcode[4:1]=xxxx|op=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->immh = (insword>>19)&15;
			ctx->immb = (insword>>16)&7;
			ctx->opcode = (insword>>12)&15;
			ctx->op = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SQSHLU_ASIMDSHF_R:
		case ENC_SQSHL_ASIMDSHF_R:
		case ENC_UQSHL_ASIMDSHF_R:
			// x|Q=x|U=x|xxxxxx|immh=xxxx|immb=xxx|opcode[4:2]=xxx|op=x|opcode[0]=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->immh = (insword>>19)&15;
			ctx->immb = (insword>>16)&7;
			ctx->opcode = (insword>>13)&7;
			ctx->op = (insword>>12)&1;
			ctx->opcode = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SRSHR_ASIMDSHF_R:
		case ENC_SRSRA_ASIMDSHF_R:
		case ENC_SSHR_ASIMDSHF_R:
		case ENC_SSRA_ASIMDSHF_R:
		case ENC_URSHR_ASIMDSHF_R:
		case ENC_URSRA_ASIMDSHF_R:
		case ENC_USHR_ASIMDSHF_R:
		case ENC_USRA_ASIMDSHF_R:
			// x|Q=x|U=x|xxxxxx|immh=xxxx|immb=xxx|opcode[4:3]=xx|o1=x|o0=x|opcode[0]=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->immh = (insword>>19)&15;
			ctx->immb = (insword>>16)&7;
			ctx->opcode = (insword>>14)&3;
			ctx->o1 = (insword>>13)&1;
			ctx->o0 = (insword>>12)&1;
			ctx->opcode = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FACGE_ASIMDSAME_ONLY:
		case ENC_FACGT_ASIMDSAME_ONLY:
		case ENC_FCMEQ_ASIMDSAME_ONLY:
		case ENC_FCMGE_ASIMDSAME_ONLY:
		case ENC_FCMGT_ASIMDSAME_ONLY:
			// x|Q=x|U=x|xxxxx|E=x|sz=x|x|Rm=xxxxx|opcode[4:1]=xxxx|ac=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->E = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>12)&15;
			ctx->ac = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FACGE_ASIMDSAMEFP16_ONLY:
		case ENC_FACGT_ASIMDSAMEFP16_ONLY:
		case ENC_FCMEQ_ASIMDSAMEFP16_ONLY:
		case ENC_FCMGE_ASIMDSAMEFP16_ONLY:
		case ENC_FCMGT_ASIMDSAMEFP16_ONLY:
			// x|Q=x|U=x|xxxxx|E=x|xx|Rm=xxxxx|xx|opcode[2:1]=xx|ac=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->E = (insword>>23)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>12)&3;
			ctx->ac = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMLAL_ASIMDSAME_F:
		case ENC_FMLAL2_ASIMDSAME_F:
		case ENC_FMLSL_ASIMDSAME_F:
		case ENC_FMLSL2_ASIMDSAME_F:
			// x|Q=x|U=x|xxxxx|S=x|sz=x|x|Rm=xxxxx|opcode[4]=x|opcode[3:0]=xxxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->S = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>15)&1;
			ctx->opcode = (insword>>11)&15;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SUDOT_ASIMDELEM_D:
		case ENC_USDOT_ASIMDELEM_D:
			// x|Q=x|U=x|xxxxx|US=x|x|L=x|M=x|Rm=xxxx|opcode=xxxx|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->US = (insword>>23)&1;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->opcode = (insword>>12)&15;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FABS_ASIMDMISCFP16_R:
		case ENC_FCMLT_ASIMDMISCFP16_FZ:
		case ENC_FCVTAS_ASIMDMISCFP16_R:
		case ENC_FCVTAU_ASIMDMISCFP16_R:
		case ENC_FNEG_ASIMDMISCFP16_R:
		case ENC_FRECPE_ASIMDMISCFP16_R:
		case ENC_FRSQRTE_ASIMDMISCFP16_R:
		case ENC_FSQRT_ASIMDMISCFP16_R:
		case ENC_SCVTF_ASIMDMISCFP16_R:
		case ENC_UCVTF_ASIMDMISCFP16_R:
			// x|Q=x|U=x|xxxxx|a=x|xxxxxx|opcode=xxxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->a = (insword>>23)&1;
			ctx->opcode = (insword>>12)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCMEQ_ASIMDMISCFP16_FZ:
		case ENC_FCMGE_ASIMDMISCFP16_FZ:
		case ENC_FCMGT_ASIMDMISCFP16_FZ:
		case ENC_FCMLE_ASIMDMISCFP16_FZ:
			// x|Q=x|U=x|xxxxx|a=x|xxxxxx|opcode[4:1]=xxxx|op=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->a = (insword>>23)&1;
			ctx->opcode = (insword>>13)&15;
			ctx->op = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMAXNMP_ASIMDSAMEFP16_ONLY:
		case ENC_FMAXNM_ASIMDSAMEFP16_ONLY:
		case ENC_FMINNMP_ASIMDSAMEFP16_ONLY:
		case ENC_FMINNM_ASIMDSAMEFP16_ONLY:
			// x|Q=x|U=x|xxxxx|a=x|xx|Rm=xxxxx|xx|Op3=xxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->a = (insword>>23)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->Op3 = (insword>>11)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FABD_ASIMDSAMEFP16_ONLY:
		case ENC_FADDP_ASIMDSAMEFP16_ONLY:
		case ENC_FADD_ASIMDSAMEFP16_ONLY:
		case ENC_FDIV_ASIMDSAMEFP16_ONLY:
		case ENC_FMLA_ASIMDSAMEFP16_ONLY:
		case ENC_FMLS_ASIMDSAMEFP16_ONLY:
		case ENC_FMULX_ASIMDSAMEFP16_ONLY:
		case ENC_FMUL_ASIMDSAMEFP16_ONLY:
		case ENC_FRECPS_ASIMDSAMEFP16_ONLY:
		case ENC_FRSQRTS_ASIMDSAMEFP16_ONLY:
		case ENC_FSUB_ASIMDSAMEFP16_ONLY:
			// x|Q=x|U=x|xxxxx|a=x|xx|Rm=xxxxx|xx|opcode=xxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->a = (insword>>23)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>11)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMAXNMV_ASIMDALL_ONLY_H:
		case ENC_FMINNMV_ASIMDALL_ONLY_H:
			// x|Q=x|U=x|xxxxx|o1=x|size[0]=x|xxxxx|opcode=xxxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->o1 = (insword>>23)&1;
			ctx->size = (insword>>22)&1;
			ctx->opcode = (insword>>12)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMAXNMV_ASIMDALL_ONLY_SD:
		case ENC_FMAXV_ASIMDALL_ONLY_SD:
		case ENC_FMINNMV_ASIMDALL_ONLY_SD:
		case ENC_FMINV_ASIMDALL_ONLY_SD:
			// x|Q=x|U=x|xxxxx|o1=x|sz=x|xxxxx|opcode=xxxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->o1 = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->opcode = (insword>>12)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMAXNMP_ASIMDSAME_ONLY:
		case ENC_FMAXNM_ASIMDSAME_ONLY:
		case ENC_FMAXP_ASIMDSAME_ONLY:
		case ENC_FMAX_ASIMDSAME_ONLY:
		case ENC_FMINNMP_ASIMDSAME_ONLY:
		case ENC_FMINNM_ASIMDSAME_ONLY:
		case ENC_FMINP_ASIMDSAME_ONLY:
		case ENC_FMIN_ASIMDSAME_ONLY:
			// x|Q=x|U=x|xxxxx|o1=x|sz=x|x|Rm=xxxxx|opcode=xxxxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->o1 = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>11)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMAXP_ASIMDSAMEFP16_ONLY:
		case ENC_FMAX_ASIMDSAMEFP16_ONLY:
		case ENC_FMINP_ASIMDSAMEFP16_ONLY:
		case ENC_FMIN_ASIMDSAMEFP16_ONLY:
			// x|Q=x|U=x|xxxxx|o1=x|xx|Rm=xxxxx|xx|opcode=xxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->o1 = (insword>>23)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>11)&7;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMAXV_ASIMDALL_ONLY_H:
		case ENC_FMINV_ASIMDALL_ONLY_H:
			// x|Q=x|U=x|xxxxx|o1=x|x|xxxxx|opcode=xxxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->o1 = (insword>>23)&1;
			ctx->opcode = (insword>>12)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCVTMS_ASIMDMISC_R:
		case ENC_FCVTMU_ASIMDMISC_R:
		case ENC_FCVTNS_ASIMDMISC_R:
		case ENC_FCVTNU_ASIMDMISC_R:
		case ENC_FCVTPS_ASIMDMISC_R:
		case ENC_FCVTPU_ASIMDMISC_R:
		case ENC_FCVTZS_ASIMDMISC_R:
		case ENC_FCVTZU_ASIMDMISC_R:
		case ENC_FRINTA_ASIMDMISC_R:
		case ENC_FRINTI_ASIMDMISC_R:
		case ENC_FRINTM_ASIMDMISC_R:
		case ENC_FRINTN_ASIMDMISC_R:
		case ENC_FRINTP_ASIMDMISC_R:
		case ENC_FRINTX_ASIMDMISC_R:
		case ENC_FRINTZ_ASIMDMISC_R:
			// x|Q=x|U=x|xxxxx|o2=x|sz=x|xxxxx|opcode[4:1]=xxxx|o1=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->o2 = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->opcode = (insword>>13)&15;
			ctx->o1 = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCVTMS_ASIMDMISCFP16_R:
		case ENC_FCVTMU_ASIMDMISCFP16_R:
		case ENC_FCVTNS_ASIMDMISCFP16_R:
		case ENC_FCVTNU_ASIMDMISCFP16_R:
		case ENC_FCVTPS_ASIMDMISCFP16_R:
		case ENC_FCVTPU_ASIMDMISCFP16_R:
		case ENC_FCVTZS_ASIMDMISCFP16_R:
		case ENC_FCVTZU_ASIMDMISCFP16_R:
		case ENC_FRINTA_ASIMDMISCFP16_R:
		case ENC_FRINTI_ASIMDMISCFP16_R:
		case ENC_FRINTM_ASIMDMISCFP16_R:
		case ENC_FRINTN_ASIMDMISCFP16_R:
		case ENC_FRINTP_ASIMDMISCFP16_R:
		case ENC_FRINTX_ASIMDMISCFP16_R:
		case ENC_FRINTZ_ASIMDMISCFP16_R:
			// x|Q=x|U=x|xxxxx|o2=x|xxxxxx|opcode[4:1]=xxxx|o1=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->o2 = (insword>>23)&1;
			ctx->opcode = (insword>>13)&15;
			ctx->o1 = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMLA_ASIMDSAME_ONLY:
		case ENC_FMLS_ASIMDSAME_ONLY:
			// x|Q=x|U=x|xxxxx|op=x|sz=x|x|Rm=xxxxx|opcode=xxxxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->op = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>11)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_BIF_ASIMDSAME_ONLY:
		case ENC_BIT_ASIMDSAME_ONLY:
		case ENC_BSL_ASIMDSAME_ONLY:
		case ENC_EOR_ASIMDSAME_ONLY:
			// x|Q=x|U=x|xxxxx|opc2=xx|x|Rm=xxxxx|opcode=xxxxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->opc2 = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>11)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_BFDOT_ASIMDELEM_E:
		case ENC_FMULX_ASIMDELEM_RH_H:
		case ENC_FMUL_ASIMDELEM_RH_H:
		case ENC_MUL_ASIMDELEM_R:
		case ENC_SDOT_ASIMDELEM_D:
		case ENC_SMULL_ASIMDELEM_L:
		case ENC_SQDMULL_ASIMDELEM_L:
		case ENC_UDOT_ASIMDELEM_D:
		case ENC_UMULL_ASIMDELEM_L:
			// x|Q=x|U=x|xxxxx|size=xx|L=x|M=x|Rm=xxxx|opcode=xxxx|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->opcode = (insword>>12)&15;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SQDMULH_ASIMDELEM_R:
		case ENC_SQRDMULH_ASIMDELEM_R:
			// x|Q=x|U=x|xxxxx|size=xx|L=x|M=x|Rm=xxxx|opcode[3:1]=xxx|op=x|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->opcode = (insword>>13)&7;
			ctx->op = (insword>>12)&1;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SQRDMLAH_ASIMDELEM_R:
		case ENC_SQRDMLSH_ASIMDELEM_R:
			// x|Q=x|U=x|xxxxx|size=xx|L=x|M=x|Rm=xxxx|opcode[3:2]=xx|S=x|opcode[0]=x|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->opcode = (insword>>14)&3;
			ctx->S = (insword>>13)&1;
			ctx->opcode = (insword>>12)&1;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMLA_ASIMDELEM_RH_H:
		case ENC_FMLS_ASIMDELEM_RH_H:
		case ENC_MLA_ASIMDELEM_R:
		case ENC_MLS_ASIMDELEM_R:
		case ENC_SMLAL_ASIMDELEM_L:
		case ENC_SMLSL_ASIMDELEM_L:
		case ENC_SQDMLAL_ASIMDELEM_L:
		case ENC_SQDMLSL_ASIMDELEM_L:
		case ENC_UMLAL_ASIMDELEM_L:
		case ENC_UMLSL_ASIMDELEM_L:
			// x|Q=x|U=x|xxxxx|size=xx|L=x|M=x|Rm=xxxx|opcode[3]=x|o2=x|opcode[1:0]=xx|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->opcode = (insword>>15)&1;
			ctx->o2 = (insword>>14)&1;
			ctx->opcode = (insword>>12)&3;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_BFMLAL_ASIMDELEM_F:
			// x|Q=x|U=x|xxxxx|size=xx|L=x|M=x|Rm=xxxx|opcode[3]=x|opcode[2]=x|opcode[1:0]=xx|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->opcode = (insword>>15)&1;
			ctx->opcode = (insword>>14)&1;
			ctx->opcode = (insword>>12)&3;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCMLA_ASIMDELEM_C_H:
		case ENC_FCMLA_ASIMDELEM_C_S:
			// x|Q=x|U=x|xxxxx|size=xx|L=x|M=x|Rm=xxxx|opcode[3]=x|rot=xx|opcode[0]=x|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->opcode = (insword>>15)&1;
			ctx->rot = (insword>>13)&3;
			ctx->opcode = (insword>>12)&1;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SMAXV_ASIMDALL_ONLY:
		case ENC_SMINV_ASIMDALL_ONLY:
		case ENC_UMAXV_ASIMDALL_ONLY:
		case ENC_UMINV_ASIMDALL_ONLY:
			// x|Q=x|U=x|xxxxx|size=xx|xxxxx|op=x|opcode[3:0]=xxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->op = (insword>>16)&1;
			ctx->opcode = (insword>>12)&15;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_ABS_ASIMDMISC_R:
		case ENC_ADDV_ASIMDALL_ONLY:
		case ENC_BFCVTN_ASIMDMISC_4S:
		case ENC_CLS_ASIMDMISC_R:
		case ENC_CLZ_ASIMDMISC_R:
		case ENC_CMLT_ASIMDMISC_Z:
		case ENC_CNT_ASIMDMISC_R:
		case ENC_MVN_NOT_ASIMDMISC_R:
		case ENC_NEG_ASIMDMISC_R:
		case ENC_NOT_ASIMDMISC_R:
		case ENC_RBIT_ASIMDMISC_R:
		case ENC_SADDLV_ASIMDALL_ONLY:
		case ENC_SHLL_ASIMDMISC_S:
		case ENC_SQABS_ASIMDMISC_R:
		case ENC_SQNEG_ASIMDMISC_R:
		case ENC_SQXTN_ASIMDMISC_N:
		case ENC_SQXTUN_ASIMDMISC_N:
		case ENC_SUQADD_ASIMDMISC_R:
		case ENC_UADDLV_ASIMDALL_ONLY:
		case ENC_UQXTN_ASIMDMISC_N:
		case ENC_USQADD_ASIMDMISC_R:
		case ENC_XTN_ASIMDMISC_N:
			// x|Q=x|U=x|xxxxx|size=xx|xxxxx|opcode=xxxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->opcode = (insword>>12)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_REV16_ASIMDMISC_R:
		case ENC_REV32_ASIMDMISC_R:
		case ENC_REV64_ASIMDMISC_R:
			// x|Q=x|U=x|xxxxx|size=xx|xxxxx|opcode[4:1]=xxxx|o0=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->opcode = (insword>>13)&15;
			ctx->o0 = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_CMEQ_ASIMDMISC_Z:
		case ENC_CMGE_ASIMDMISC_Z:
		case ENC_CMGT_ASIMDMISC_Z:
		case ENC_CMLE_ASIMDMISC_Z:
			// x|Q=x|U=x|xxxxx|size=xx|xxxxx|opcode[4:1]=xxxx|op=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->opcode = (insword>>13)&15;
			ctx->op = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SADALP_ASIMDMISC_P:
		case ENC_SADDLP_ASIMDMISC_P:
		case ENC_UADALP_ASIMDMISC_P:
		case ENC_UADDLP_ASIMDMISC_P:
			// x|Q=x|U=x|xxxxx|size=xx|xxxxx|opcode[4:3]=xx|op=x|opcode[1:0]=xx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->opcode = (insword>>15)&3;
			ctx->op = (insword>>14)&1;
			ctx->opcode = (insword>>12)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_ADDP_ASIMDSAME_ONLY:
		case ENC_ADD_ASIMDSAME_ONLY:
		case ENC_AND_ASIMDSAME_ONLY:
		case ENC_BIC_ASIMDSAME_ONLY:
		case ENC_CMEQ_ASIMDSAME_ONLY:
		case ENC_CMTST_ASIMDSAME_ONLY:
		case ENC_MLA_ASIMDSAME_ONLY:
		case ENC_MLS_ASIMDSAME_ONLY:
		case ENC_MOV_ORR_ASIMDSAME_ONLY:
		case ENC_MUL_ASIMDSAME_ONLY:
		case ENC_ORN_ASIMDSAME_ONLY:
		case ENC_ORR_ASIMDSAME_ONLY:
		case ENC_PMUL_ASIMDSAME_ONLY:
		case ENC_SHADD_ASIMDSAME_ONLY:
		case ENC_SHSUB_ASIMDSAME_ONLY:
		case ENC_SQADD_ASIMDSAME_ONLY:
		case ENC_SQDMULH_ASIMDSAME_ONLY:
		case ENC_SQRDMULH_ASIMDSAME_ONLY:
		case ENC_SQSUB_ASIMDSAME_ONLY:
		case ENC_SRHADD_ASIMDSAME_ONLY:
		case ENC_SUB_ASIMDSAME_ONLY:
		case ENC_UHADD_ASIMDSAME_ONLY:
		case ENC_UHSUB_ASIMDSAME_ONLY:
		case ENC_UQADD_ASIMDSAME_ONLY:
		case ENC_UQSUB_ASIMDSAME_ONLY:
		case ENC_URHADD_ASIMDSAME_ONLY:
			// x|Q=x|U=x|xxxxx|size=xx|x|Rm=xxxxx|opcode=xxxxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>11)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_PMULL_ASIMDDIFF_L:
		case ENC_SQDMULL_ASIMDDIFF_L:
			// x|Q=x|U=x|xxxxx|size=xx|x|Rm=xxxxx|opcode=xxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>12)&15;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_ADDHN_ASIMDDIFF_N:
		case ENC_RADDHN_ASIMDDIFF_N:
		case ENC_RSUBHN_ASIMDDIFF_N:
		case ENC_SADDL_ASIMDDIFF_L:
		case ENC_SADDW_ASIMDDIFF_W:
		case ENC_SMLAL_ASIMDDIFF_L:
		case ENC_SMLSL_ASIMDDIFF_L:
		case ENC_SQDMLAL_ASIMDDIFF_L:
		case ENC_SQDMLSL_ASIMDDIFF_L:
		case ENC_SSUBL_ASIMDDIFF_L:
		case ENC_SSUBW_ASIMDDIFF_W:
		case ENC_SUBHN_ASIMDDIFF_N:
		case ENC_UADDL_ASIMDDIFF_L:
		case ENC_UADDW_ASIMDDIFF_W:
		case ENC_UMLAL_ASIMDDIFF_L:
		case ENC_UMLSL_ASIMDDIFF_L:
		case ENC_USUBL_ASIMDDIFF_L:
		case ENC_USUBW_ASIMDDIFF_W:
			// x|Q=x|U=x|xxxxx|size=xx|x|Rm=xxxxx|opcode[3:2]=xx|o1=x|opcode[0]=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>14)&3;
			ctx->o1 = (insword>>13)&1;
			ctx->opcode = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SABAL_ASIMDDIFF_L:
		case ENC_SABDL_ASIMDDIFF_L:
		case ENC_UABAL_ASIMDDIFF_L:
		case ENC_UABDL_ASIMDDIFF_L:
			// x|Q=x|U=x|xxxxx|size=xx|x|Rm=xxxxx|opcode[3:2]=xx|op=x|opcode[0]=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>14)&3;
			ctx->op = (insword>>13)&1;
			ctx->opcode = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SMULL_ASIMDDIFF_L:
		case ENC_UMULL_ASIMDDIFF_L:
			// x|Q=x|U=x|xxxxx|size=xx|x|Rm=xxxxx|opcode[3]=x|opcode[2]=x|opcode[1]=x|opcode[0]=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>15)&1;
			ctx->opcode = (insword>>14)&1;
			ctx->opcode = (insword>>13)&1;
			ctx->opcode = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SABA_ASIMDSAME_ONLY:
		case ENC_SABD_ASIMDSAME_ONLY:
		case ENC_UABA_ASIMDSAME_ONLY:
		case ENC_UABD_ASIMDSAME_ONLY:
			// x|Q=x|U=x|xxxxx|size=xx|x|Rm=xxxxx|opcode[4:1]=xxxx|ac=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>12)&15;
			ctx->ac = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_CMGE_ASIMDSAME_ONLY:
		case ENC_CMGT_ASIMDSAME_ONLY:
		case ENC_CMHI_ASIMDSAME_ONLY:
		case ENC_CMHS_ASIMDSAME_ONLY:
			// x|Q=x|U=x|xxxxx|size=xx|x|Rm=xxxxx|opcode[4:1]=xxxx|eq=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>12)&15;
			ctx->eq = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SMAXP_ASIMDSAME_ONLY:
		case ENC_SMAX_ASIMDSAME_ONLY:
		case ENC_SMINP_ASIMDSAME_ONLY:
		case ENC_SMIN_ASIMDSAME_ONLY:
		case ENC_UMAXP_ASIMDSAME_ONLY:
		case ENC_UMAX_ASIMDSAME_ONLY:
		case ENC_UMINP_ASIMDSAME_ONLY:
		case ENC_UMIN_ASIMDSAME_ONLY:
			// x|Q=x|U=x|xxxxx|size=xx|x|Rm=xxxxx|opcode[4:1]=xxxx|o1=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>12)&15;
			ctx->o1 = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SQRSHL_ASIMDSAME_ONLY:
		case ENC_SQSHL_ASIMDSAME_ONLY:
		case ENC_SRSHL_ASIMDSAME_ONLY:
		case ENC_SSHL_ASIMDSAME_ONLY:
		case ENC_UQRSHL_ASIMDSAME_ONLY:
		case ENC_UQSHL_ASIMDSAME_ONLY:
		case ENC_URSHL_ASIMDSAME_ONLY:
		case ENC_USHL_ASIMDSAME_ONLY:
			// x|Q=x|U=x|xxxxx|size=xx|x|Rm=xxxxx|opcode[4:2]=xxx|R=x|S=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>13)&7;
			ctx->R = (insword>>12)&1;
			ctx->S = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_BFMLAL_ASIMDSAME2_F_:
			// x|Q=x|U=x|xxxxx|size=xx|x|Rm=xxxxx|x|opcode<3:2>=xx|opcode=xx|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>13)&3;
			ctx->opcode = (insword>>11)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_BFDOT_ASIMDSAME2_D:
		case ENC_BFMMLA_ASIMDSAME2_E:
		case ENC_SDOT_ASIMDSAME2_D:
		case ENC_UDOT_ASIMDSAME2_D:
		case ENC_USDOT_ASIMDSAME2_D:
			// x|Q=x|U=x|xxxxx|size=xx|x|Rm=xxxxx|x|opcode=xxxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>11)&15;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SQRDMLAH_ASIMDSAME2_ONLY:
		case ENC_SQRDMLSH_ASIMDSAME2_ONLY:
			// x|Q=x|U=x|xxxxx|size=xx|x|Rm=xxxxx|x|opcode[3:1]=xxx|S=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>12)&7;
			ctx->S = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_SMMLA_ASIMDSAME2_G:
		case ENC_UMMLA_ASIMDSAME2_G:
		case ENC_USMMLA_ASIMDSAME2_G:
			// x|Q=x|U=x|xxxxx|size=xx|x|Rm=xxxxx|x|xxx|B=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->B = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCMLA_ASIMDSAME2_C:
			// x|Q=x|U=x|xxxxx|size=xx|x|Rm=xxxxx|x|xx|rot=xx|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->rot = (insword>>11)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCADD_ASIMDSAME2_C:
			// x|Q=x|U=x|xxxxx|size=xx|x|Rm=xxxxx|x|xx|rot=x|x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->rot = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMULX_ASIMDELEM_R_SD:
		case ENC_FMUL_ASIMDELEM_R_SD:
			// x|Q=x|U=x|xxxxx|size[1]=x|sz=x|L=x|M=x|Rm=xxxx|opcode=xxxx|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->opcode = (insword>>12)&15;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMLAL_ASIMDELEM_LH:
		case ENC_FMLAL2_ASIMDELEM_LH:
		case ENC_FMLSL_ASIMDELEM_LH:
		case ENC_FMLSL2_ASIMDELEM_LH:
			// x|Q=x|U=x|xxxxx|size[1]=x|sz=x|L=x|M=x|Rm=xxxx|opcode[3]=x|S=x|opcode[1:0]=xx|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->opcode = (insword>>15)&1;
			ctx->S = (insword>>14)&1;
			ctx->opcode = (insword>>12)&3;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FMLA_ASIMDELEM_R_SD:
		case ENC_FMLS_ASIMDELEM_R_SD:
			// x|Q=x|U=x|xxxxx|size[1]=x|sz=x|L=x|M=x|Rm=xxxx|opcode[3]=x|o2=x|opcode[1:0]=xx|H=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->L = (insword>>21)&1;
			ctx->M = (insword>>20)&1;
			ctx->Rm = (insword>>16)&15;
			ctx->opcode = (insword>>15)&1;
			ctx->o2 = (insword>>14)&1;
			ctx->opcode = (insword>>12)&3;
			ctx->H = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FABS_ASIMDMISC_R:
		case ENC_FCMLT_ASIMDMISC_FZ:
		case ENC_FCVTAS_ASIMDMISC_R:
		case ENC_FCVTAU_ASIMDMISC_R:
		case ENC_FCVTL_ASIMDMISC_L:
		case ENC_FCVTN_ASIMDMISC_N:
		case ENC_FCVTXN_ASIMDMISC_N:
		case ENC_FNEG_ASIMDMISC_R:
		case ENC_FRECPE_ASIMDMISC_R:
		case ENC_FRSQRTE_ASIMDMISC_R:
		case ENC_FSQRT_ASIMDMISC_R:
		case ENC_SCVTF_ASIMDMISC_R:
		case ENC_UCVTF_ASIMDMISC_R:
		case ENC_URECPE_ASIMDMISC_R:
		case ENC_URSQRTE_ASIMDMISC_R:
			// x|Q=x|U=x|xxxxx|size[1]=x|sz=x|xxxxx|opcode=xxxxx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->opcode = (insword>>12)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FCMEQ_ASIMDMISC_FZ:
		case ENC_FCMGE_ASIMDMISC_FZ:
		case ENC_FCMGT_ASIMDMISC_FZ:
		case ENC_FCMLE_ASIMDMISC_FZ:
			// x|Q=x|U=x|xxxxx|size[1]=x|sz=x|xxxxx|opcode[4:1]=xxxx|op=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->opcode = (insword>>13)&15;
			ctx->op = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FABD_ASIMDSAME_ONLY:
		case ENC_FADDP_ASIMDSAME_ONLY:
		case ENC_FADD_ASIMDSAME_ONLY:
		case ENC_FDIV_ASIMDSAME_ONLY:
		case ENC_FMULX_ASIMDSAME_ONLY:
		case ENC_FMUL_ASIMDSAME_ONLY:
		case ENC_FRECPS_ASIMDSAME_ONLY:
		case ENC_FRSQRTS_ASIMDSAME_ONLY:
		case ENC_FSUB_ASIMDSAME_ONLY:
			// x|Q=x|U=x|xxxxx|size[1]=x|sz=x|x|Rm=xxxxx|opcode=xxxxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->size = (insword>>23)&1;
			ctx->sz = (insword>>22)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>11)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_FRINT32X_ASIMDMISC_R:
		case ENC_FRINT32Z_ASIMDMISC_R:
		case ENC_FRINT64X_ASIMDMISC_R:
		case ENC_FRINT64Z_ASIMDMISC_R:
			// x|Q=x|U=x|xxxxx|x|sz=x|xxxxx|xxxx|op=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->U = (insword>>29)&1;
			ctx->sz = (insword>>22)&1;
			ctx->op = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_BIC_ASIMDIMM_L_HL:
		case ENC_BIC_ASIMDIMM_L_SL:
		case ENC_FMOV_ASIMDIMM_H_H:
		case ENC_FMOV_ASIMDIMM_S_S:
		case ENC_FMOV_ASIMDIMM_D2_D:
		case ENC_MOVI_ASIMDIMM_N_B:
		case ENC_MOVI_ASIMDIMM_L_HL:
		case ENC_MOVI_ASIMDIMM_L_SL:
		case ENC_MOVI_ASIMDIMM_M_SM:
		case ENC_MOVI_ASIMDIMM_D_DS:
		case ENC_MOVI_ASIMDIMM_D2_D:
		case ENC_MVNI_ASIMDIMM_L_HL:
		case ENC_MVNI_ASIMDIMM_L_SL:
		case ENC_MVNI_ASIMDIMM_M_SM:
		case ENC_ORR_ASIMDIMM_L_HL:
		case ENC_ORR_ASIMDIMM_L_SL:
			// x|Q=x|op=x|xxxxxxxxxx|a=x|b=x|c=x|cmode=xxxx|o2=x|x|d=x|e=x|f=x|g=x|h=x|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->op = (insword>>29)&1;
			ctx->a = (insword>>18)&1;
			ctx->b = (insword>>17)&1;
			ctx->c = (insword>>16)&1;
			ctx->cmode = (insword>>12)&15;
			ctx->o2 = (insword>>11)&1;
			ctx->d = (insword>>9)&1;
			ctx->e = (insword>>8)&1;
			ctx->f = (insword>>7)&1;
			ctx->g = (insword>>6)&1;
			ctx->h = (insword>>5)&1;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_DUP_ASIMDINS_DV_V:
		case ENC_DUP_ASIMDINS_DR_R:
		case ENC_INS_ASIMDINS_IV_V:
		case ENC_INS_ASIMDINS_IR_R:
		case ENC_MOV_INS_ASIMDINS_IV_V:
		case ENC_MOV_INS_ASIMDINS_IR_R:
			// x|Q=x|op=x|xxxxxxxx|imm5=xxxxx|x|imm4=xxxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->op = (insword>>29)&1;
			ctx->imm5 = (insword>>16)&0x1f;
			ctx->imm4 = (insword>>11)&15;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_MOV_UMOV_ASIMDINS_W_W:
		case ENC_MOV_UMOV_ASIMDINS_X_X:
		case ENC_SMOV_ASIMDINS_W_W:
		case ENC_SMOV_ASIMDINS_X_X:
		case ENC_UMOV_ASIMDINS_W_W:
		case ENC_UMOV_ASIMDINS_X_X:
			// x|Q=x|op=x|xxxxxxxx|imm5=xxxxx|x|imm4[3:2]=xx|imm4[1]=x|imm4[0]=x|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->op = (insword>>29)&1;
			ctx->imm5 = (insword>>16)&0x1f;
			ctx->imm4 = (insword>>13)&3;
			ctx->imm4 = (insword>>12)&1;
			ctx->imm4 = (insword>>11)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_LD1R_ASISDLSOP_R1_I:
		case ENC_LD1R_ASISDLSOP_RX1_R:
		case ENC_LD1_ASISDLSOP_B1_I1B:
		case ENC_LD1_ASISDLSOP_BX1_R1B:
		case ENC_LD1_ASISDLSOP_H1_I1H:
		case ENC_LD1_ASISDLSOP_HX1_R1H:
		case ENC_LD1_ASISDLSOP_S1_I1S:
		case ENC_LD1_ASISDLSOP_SX1_R1S:
		case ENC_LD1_ASISDLSOP_D1_I1D:
		case ENC_LD1_ASISDLSOP_DX1_R1D:
		case ENC_LD2R_ASISDLSOP_R2_I:
		case ENC_LD2R_ASISDLSOP_RX2_R:
		case ENC_LD2_ASISDLSOP_B2_I2B:
		case ENC_LD2_ASISDLSOP_BX2_R2B:
		case ENC_LD2_ASISDLSOP_H2_I2H:
		case ENC_LD2_ASISDLSOP_HX2_R2H:
		case ENC_LD2_ASISDLSOP_S2_I2S:
		case ENC_LD2_ASISDLSOP_SX2_R2S:
		case ENC_LD2_ASISDLSOP_D2_I2D:
		case ENC_LD2_ASISDLSOP_DX2_R2D:
		case ENC_LD3R_ASISDLSOP_R3_I:
		case ENC_LD3R_ASISDLSOP_RX3_R:
		case ENC_LD3_ASISDLSOP_B3_I3B:
		case ENC_LD3_ASISDLSOP_BX3_R3B:
		case ENC_LD3_ASISDLSOP_H3_I3H:
		case ENC_LD3_ASISDLSOP_HX3_R3H:
		case ENC_LD3_ASISDLSOP_S3_I3S:
		case ENC_LD3_ASISDLSOP_SX3_R3S:
		case ENC_LD3_ASISDLSOP_D3_I3D:
		case ENC_LD3_ASISDLSOP_DX3_R3D:
		case ENC_LD4R_ASISDLSOP_R4_I:
		case ENC_LD4R_ASISDLSOP_RX4_R:
		case ENC_LD4_ASISDLSOP_B4_I4B:
		case ENC_LD4_ASISDLSOP_BX4_R4B:
		case ENC_LD4_ASISDLSOP_H4_I4H:
		case ENC_LD4_ASISDLSOP_HX4_R4H:
		case ENC_LD4_ASISDLSOP_S4_I4S:
		case ENC_LD4_ASISDLSOP_SX4_R4S:
		case ENC_LD4_ASISDLSOP_D4_I4D:
		case ENC_LD4_ASISDLSOP_DX4_R4D:
		case ENC_ST1_ASISDLSOP_B1_I1B:
		case ENC_ST1_ASISDLSOP_BX1_R1B:
		case ENC_ST1_ASISDLSOP_H1_I1H:
		case ENC_ST1_ASISDLSOP_HX1_R1H:
		case ENC_ST1_ASISDLSOP_S1_I1S:
		case ENC_ST1_ASISDLSOP_SX1_R1S:
		case ENC_ST1_ASISDLSOP_D1_I1D:
		case ENC_ST1_ASISDLSOP_DX1_R1D:
		case ENC_ST2_ASISDLSOP_B2_I2B:
		case ENC_ST2_ASISDLSOP_BX2_R2B:
		case ENC_ST2_ASISDLSOP_H2_I2H:
		case ENC_ST2_ASISDLSOP_HX2_R2H:
		case ENC_ST2_ASISDLSOP_S2_I2S:
		case ENC_ST2_ASISDLSOP_SX2_R2S:
		case ENC_ST2_ASISDLSOP_D2_I2D:
		case ENC_ST2_ASISDLSOP_DX2_R2D:
		case ENC_ST3_ASISDLSOP_B3_I3B:
		case ENC_ST3_ASISDLSOP_BX3_R3B:
		case ENC_ST3_ASISDLSOP_H3_I3H:
		case ENC_ST3_ASISDLSOP_HX3_R3H:
		case ENC_ST3_ASISDLSOP_S3_I3S:
		case ENC_ST3_ASISDLSOP_SX3_R3S:
		case ENC_ST3_ASISDLSOP_D3_I3D:
		case ENC_ST3_ASISDLSOP_DX3_R3D:
		case ENC_ST4_ASISDLSOP_B4_I4B:
		case ENC_ST4_ASISDLSOP_BX4_R4B:
		case ENC_ST4_ASISDLSOP_H4_I4H:
		case ENC_ST4_ASISDLSOP_HX4_R4H:
		case ENC_ST4_ASISDLSOP_S4_I4S:
		case ENC_ST4_ASISDLSOP_SX4_R4S:
		case ENC_ST4_ASISDLSOP_D4_I4D:
		case ENC_ST4_ASISDLSOP_DX4_R4D:
			// x|Q=x|xxxxxxx|L=x|R=x|Rm=xxxxx|opcode=xxx|S=x|size=xx|Rn=xxxxx|Rt=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->L = (insword>>22)&1;
			ctx->R = (insword>>21)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>13)&7;
			ctx->S = (insword>>12)&1;
			ctx->size = (insword>>10)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LD1R_ASISDLSO_R1:
		case ENC_LD1_ASISDLSO_B1_1B:
		case ENC_LD1_ASISDLSO_H1_1H:
		case ENC_LD1_ASISDLSO_S1_1S:
		case ENC_LD1_ASISDLSO_D1_1D:
		case ENC_LD2R_ASISDLSO_R2:
		case ENC_LD2_ASISDLSO_B2_2B:
		case ENC_LD2_ASISDLSO_H2_2H:
		case ENC_LD2_ASISDLSO_S2_2S:
		case ENC_LD2_ASISDLSO_D2_2D:
		case ENC_LD3R_ASISDLSO_R3:
		case ENC_LD3_ASISDLSO_B3_3B:
		case ENC_LD3_ASISDLSO_H3_3H:
		case ENC_LD3_ASISDLSO_S3_3S:
		case ENC_LD3_ASISDLSO_D3_3D:
		case ENC_LD4R_ASISDLSO_R4:
		case ENC_LD4_ASISDLSO_B4_4B:
		case ENC_LD4_ASISDLSO_H4_4H:
		case ENC_LD4_ASISDLSO_S4_4S:
		case ENC_LD4_ASISDLSO_D4_4D:
		case ENC_ST1_ASISDLSO_B1_1B:
		case ENC_ST1_ASISDLSO_H1_1H:
		case ENC_ST1_ASISDLSO_S1_1S:
		case ENC_ST1_ASISDLSO_D1_1D:
		case ENC_ST2_ASISDLSO_B2_2B:
		case ENC_ST2_ASISDLSO_H2_2H:
		case ENC_ST2_ASISDLSO_S2_2S:
		case ENC_ST2_ASISDLSO_D2_2D:
		case ENC_ST3_ASISDLSO_B3_3B:
		case ENC_ST3_ASISDLSO_H3_3H:
		case ENC_ST3_ASISDLSO_S3_3S:
		case ENC_ST3_ASISDLSO_D3_3D:
		case ENC_ST4_ASISDLSO_B4_4B:
		case ENC_ST4_ASISDLSO_H4_4H:
		case ENC_ST4_ASISDLSO_S4_4S:
		case ENC_ST4_ASISDLSO_D4_4D:
			// x|Q=x|xxxxxxx|L=x|R=x|xxxxx|opcode=xxx|S=x|size=xx|Rn=xxxxx|Rt=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->L = (insword>>22)&1;
			ctx->R = (insword>>21)&1;
			ctx->opcode = (insword>>13)&7;
			ctx->S = (insword>>12)&1;
			ctx->size = (insword>>10)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LD1_ASISDLSE_R1_1V:
		case ENC_LD1_ASISDLSE_R2_2V:
		case ENC_LD1_ASISDLSE_R3_3V:
		case ENC_LD1_ASISDLSE_R4_4V:
		case ENC_LD2_ASISDLSE_R2:
		case ENC_LD3_ASISDLSE_R3:
		case ENC_LD4_ASISDLSE_R4:
		case ENC_ST1_ASISDLSE_R1_1V:
		case ENC_ST1_ASISDLSE_R2_2V:
		case ENC_ST1_ASISDLSE_R3_3V:
		case ENC_ST1_ASISDLSE_R4_4V:
		case ENC_ST2_ASISDLSE_R2:
		case ENC_ST3_ASISDLSE_R3:
		case ENC_ST4_ASISDLSE_R4:
			// x|Q=x|xxxxxxx|L=x|xxxxxx|opcode=xxxx|size=xx|Rn=xxxxx|Rt=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->L = (insword>>22)&1;
			ctx->opcode = (insword>>12)&15;
			ctx->size = (insword>>10)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_LD1_ASISDLSEP_I1_I1:
		case ENC_LD1_ASISDLSEP_R1_R1:
		case ENC_LD1_ASISDLSEP_I2_I2:
		case ENC_LD1_ASISDLSEP_R2_R2:
		case ENC_LD1_ASISDLSEP_I3_I3:
		case ENC_LD1_ASISDLSEP_R3_R3:
		case ENC_LD1_ASISDLSEP_I4_I4:
		case ENC_LD1_ASISDLSEP_R4_R4:
		case ENC_LD2_ASISDLSEP_I2_I:
		case ENC_LD2_ASISDLSEP_R2_R:
		case ENC_LD3_ASISDLSEP_I3_I:
		case ENC_LD3_ASISDLSEP_R3_R:
		case ENC_LD4_ASISDLSEP_I4_I:
		case ENC_LD4_ASISDLSEP_R4_R:
		case ENC_ST1_ASISDLSEP_I1_I1:
		case ENC_ST1_ASISDLSEP_R1_R1:
		case ENC_ST1_ASISDLSEP_I2_I2:
		case ENC_ST1_ASISDLSEP_R2_R2:
		case ENC_ST1_ASISDLSEP_I3_I3:
		case ENC_ST1_ASISDLSEP_R3_R3:
		case ENC_ST1_ASISDLSEP_I4_I4:
		case ENC_ST1_ASISDLSEP_R4_R4:
		case ENC_ST2_ASISDLSEP_I2_I:
		case ENC_ST2_ASISDLSEP_R2_R:
		case ENC_ST3_ASISDLSEP_I3_I:
		case ENC_ST3_ASISDLSEP_R3_R:
		case ENC_ST4_ASISDLSEP_I4_I:
		case ENC_ST4_ASISDLSEP_R4_R:
			// x|Q=x|xxxxxxx|L=x|x|Rm=xxxxx|opcode=xxxx|size=xx|Rn=xxxxx|Rt=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->L = (insword>>22)&1;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->opcode = (insword>>12)&15;
			ctx->size = (insword>>10)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		case ENC_EXT_ASIMDEXT_ONLY:
			// x|Q=x|xxxxxx|op2=xx|x|Rm=xxxxx|x|imm4=xxxx|x|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->op2 = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->imm4 = (insword>>11)&15;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_TBL_ASIMDTBL_L2_2:
		case ENC_TBL_ASIMDTBL_L3_3:
		case ENC_TBL_ASIMDTBL_L4_4:
		case ENC_TBL_ASIMDTBL_L1_1:
		case ENC_TBX_ASIMDTBL_L2_2:
		case ENC_TBX_ASIMDTBL_L3_3:
		case ENC_TBX_ASIMDTBL_L4_4:
		case ENC_TBX_ASIMDTBL_L1_1:
			// x|Q=x|xxxxxx|op2=xx|x|Rm=xxxxx|x|len=xx|op=x|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->op2 = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->len = (insword>>13)&3;
			ctx->op = (insword>>12)&1;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_TRN1_ASIMDPERM_ONLY:
		case ENC_TRN2_ASIMDPERM_ONLY:
		case ENC_UZP1_ASIMDPERM_ONLY:
		case ENC_UZP2_ASIMDPERM_ONLY:
		case ENC_ZIP1_ASIMDPERM_ONLY:
		case ENC_ZIP2_ASIMDPERM_ONLY:
			// x|Q=x|xxxxxx|size=xx|x|Rm=xxxxx|x|op=x|opcode[1:0]=xx|xx|Rn=xxxxx|Rd=xxxxx
			ctx->Q = (insword>>30)&1;
			ctx->size = (insword>>22)&3;
			ctx->Rm = (insword>>16)&0x1f;
			ctx->op = (insword>>14)&1;
			ctx->opcode = (insword>>12)&3;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rd = insword&0x1f;
			break;
		case ENC_CASP_CP32_COMSWAPPR:
		case ENC_CASPA_CP32_COMSWAPPR:
		case ENC_CASPAL_CP32_COMSWAPPR:
		case ENC_CASPL_CP32_COMSWAPPR:
		case ENC_CASP_CP64_COMSWAPPR:
		case ENC_CASPA_CP64_COMSWAPPR:
		case ENC_CASPAL_CP64_COMSWAPPR:
		case ENC_CASPL_CP64_COMSWAPPR:
		case ENC_LDAXP_LP32_LDSTEXCLP:
		case ENC_LDAXP_LP64_LDSTEXCLP:
		case ENC_LDXP_LP32_LDSTEXCLP:
		case ENC_LDXP_LP64_LDSTEXCLP:
		case ENC_STLXP_SP32_LDSTEXCLP:
		case ENC_STLXP_SP64_LDSTEXCLP:
		case ENC_STXP_SP32_LDSTEXCLP:
		case ENC_STXP_SP64_LDSTEXCLP:
			// x|sz=x|xxxxxx|o2=x|L=x|o1=x|Rs=xxxxx|o0=x|Rt2=xxxxx|Rn=xxxxx|Rt=xxxxx
			ctx->sz = (insword>>30)&1;
			ctx->o2 = (insword>>23)&1;
			ctx->L = (insword>>22)&1;
			ctx->o1 = (insword>>21)&1;
			ctx->Rs = (insword>>16)&0x1f;
			ctx->o0 = (insword>>15)&1;
			ctx->Rt2 = (insword>>10)&0x1f;
			ctx->Rn = (insword>>5)&0x1f;
			ctx->Rt = insword&0x1f;
			break;
		default:
			break;
	}
}
