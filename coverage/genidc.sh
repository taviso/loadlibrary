#!/bin/sh
#
cat << EOF
#include <idc.idc>
#define PAGE_SIZE 0x1000
static main() {
EOF

# colour functions with coverage differently
cut -d: -f1 ${1} | sed 's/^\(.*\)$/\tSetColor(MinEA()-PAGE_SIZE+\1, 2, 0xECFCB0);/g'

# colour block start slightly bolder
cut -d: -f1 ${1} | sed 's/^\(.*\)$/\tSetColor(MinEA()-PAGE_SIZE+\1, 1, 0xD3FE32);/g'

# insert a comment which file hit this block
sed -e 's/^\(.*\):\(.*\)$/\tMakeComm(MinEA()-PAGE_SIZE+\1, "Sample: \2");/g' ${1}

cat << EOF
    Refresh();
    RefreshLists();
}
EOF

