CFLAGS=-O2 -ggdb3 -m32 -std=gnu99 -fshort-wchar -Wno-multichar -w -DHAVE_CONFIG_H -I.
LDFLAGS= $(CFLAGS) -m32

all: libdisasm.a

libdisasm.a: ia32_implicit.o        \
             ia32_modrm.o           \
             ia32_reg.o             \
             x86_format.o           \
             x86_misc.o             \
             ia32_insn.o            \
             ia32_opcode_tables.o   \
             ia32_settings.o        \
             x86_imm.o              \
             x86_operand_list.o     \
             ia32_invariant.o       \
             ia32_operand.o         \
             x86_disasm.o           \
             x86_insn.o
	$(AR) $(ARFLAGS) $@ $^

clean:
	rm -f *.o *.a
