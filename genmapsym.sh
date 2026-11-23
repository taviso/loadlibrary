#!/bin/bash
#
# Copyright (C) 2017 Tavis Ormandy
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# This script generates a .o file that can be loaded as a symbol-file in gdb
# from an IDA .map file. This allows you to get symbols into a gdb session
# when you're debugging a windows DLL.
#
# Yes, this is insane. However, it actually works.
#

awk -v base="$1" '
    BEGIN {
        print ".macro symbol name, address"
        print ".set \\name, \\address"
        print ".func \\name"
        print ".endfunc"
        print ".endm"
    }

    /Publics by Value/,/Program entry point/ {
        if ($1 !~ /^[[:xdigit:]]+:[[:xdigit:]]+$/)
            next

        split($1, address, ":")
        name = $2
        gsub(/[^[:alnum:]_]/, "_", name)
        if (name == "")
            next
        if (name ~ /^[[:digit:]]/)
            name = "_" name
        if (++seen[name] > 1)
            name = name "_" seen[name]

        printf "symbol %s,%s+0x%s\n", name, base, address[2]
    }
' | as -o "$2" -gstabs+ -W --32
