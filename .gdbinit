define multichar
    printf "'%c%c%c%c'\n", (((uint32_t) $arg0 >> 24) & 0xff)   \
                         , (((uint32_t) $arg0 >> 16) & 0xff)   \
                         , (((uint32_t) $arg0 >>  8) & 0xff)   \
                         , (((uint32_t) $arg0 >>  0) & 0xff)
end
document multichar
Decode and display a multichar constant value.
end

alias mc = multichar

# The nexti instruction can be unrealiable when debugging Windows code, this is
# a hacky function to use hardware breakpoints instead.
define hnexti
    # Record the number of the last breapoint.
    set $_bpnum = $bpnum

    # Make sure its always defined.
    init-if-undefined $_bpnum = -1

    # Try to guess the location of the next instruction.
    if (*(uint8_t *) $pc == 0xe8)
        thb *($pc + 5)
    end

    if (*(uint8_t *) $pc == 0xff)
        set $_modrm = *(uint8_t *)($pc + 1)
        set $_mod = ($_modrm & 0b11000000) >> 6
        set $_reg = ($_modrm & 0b00111000) >> 3
        set $_rm  = ($_modrm & 0b00000111) >> 0

        # See "Table 2-2. 32-Bit Addressing Forms with the ModR/M Byte"
        printf "MODRM %#X => MOD %#X R/M %#X REG %#X\n",$_modrm,$_mod,$_reg,$_rm

        # These are all 1 byte operand except 0b101 and 0b100
        if ($_mod == 0b00)
            # disp32
            if ($_rm == 0b101)
                thb *($pc + 6)
            end
            # [--][--] Add one for SIB
            if ($_rm == 0b100)
                thb *($pc + 3)
            end
            # [r32]
            if ($bpnum == $_bpnum)
                thb *($pc + 2)
            end
        end
        # 0b11 is register direct, i.e. call r32
        if ($_mod == 0b11)
            thb *($pc + 2)
        end
    end

    if ($bpnum != $_bpnum)
        continue
    else
        print "Failed to set breakpoint, or unknown instruction"
    end
end
document hnexti
Like nexti, but use hardware breakpoints.
end

alias hni = hnexti

define ni
    print "Are you sure? nexti is unreliable when debugging Windows code..."
end

define trace
    while 1
        eval "set $_cond=!!(%s)",$arg0
        if ! $_cond
            loop_break
        end
        si
    end
end
document trace
Step until condition is true.
Ex: trace "$eax != 4"
end
