#ifndef __INSTRUMENT_H
#define __INSTRUMENT_H
#include <stdint.h>
void instrument_basic_block(uintptr_t address, uint32_t size);

void instrument_repz_cmps_pre(uintptr_t address, uintptr_t count, uint32_t width);
void instrument_repz_cmps_post(uintptr_t address, uintptr_t count, uint32_t width);

void instrument_cmp_reg_imm(uintptr_t address, uintptr_t reg, uint32_t imm);

void instrument_fini_callback(int32_t code, void *v);
#else
#warning instrument.h multiple inclusion
#endif
