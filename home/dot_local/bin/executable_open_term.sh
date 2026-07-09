#!/bin/bash
if [[ -d ${1} ]]; then
    /Applications/kitty.app/Contents/MacOS/kitty --single-instance -d "${@}"
else
    /Applications/kitty.app/Contents/MacOS/kitty --single-instance -d ~ ${@}
fi


