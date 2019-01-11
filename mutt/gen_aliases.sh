#!/bin/bash

if [ -z $1 ]; then
    exit
fi

grep -r ^"From: " $1 | awk '{$1=""; if (NF == 3) {print "alias" $0;} else if (NF == 2) {print "alias" $0 $0;} else if (NF > 3) {print "alias", tolower($(NF-1))"-"tolower($2) $0;}}'
