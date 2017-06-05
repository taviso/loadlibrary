#ifndef __INSTRUMENT_H
#define __INSTRUMENT_H
VOID instrument_basic_block(ADDRINT address, UINT32 size);

VOID instrument_repz_cmps_pre(ADDRINT address, ADDRINT count, UINT32 width);
VOID instrument_repz_cmps_post(ADDRINT address, ADDRINT count, UINT32 width);

VOID instrument_cmp_reg_imm(ADDRINT address, ADDRINT reg, UINT32 imm);

VOID instrument_fini_callback(INT32 code, VOID *v);
#else
#warning instrument.h multiple inclusion
#endif
