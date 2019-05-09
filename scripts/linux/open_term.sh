#!/bin/bash
if [[ -d ${1} ]]; then
    termite -d "${@}" &>/dev/null &
else
    termite -e "${@}" &>/dev/null &
fi
