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

awk 'BEGIN { printf ".macro symbol name, address\n.set \\name, \\address\n.func \\name\n.endfunc\n.endm\n" }

    /Publics by Value/,/Program entry point/ {

        if (gsub(/^ ....:/,"'${1}'+0x")) {
            gsub(/[\"/^}{\[\]$?:@()><`\'\''|~,=!+&*-]/, "_",$2);
            printf "symbol %s,%s\n",$2,$1
        }
}' | as -o ${2} -gstabs+ --32
