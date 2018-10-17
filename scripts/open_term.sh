#!/bin/bash
uname_out=`uname`

if [[ "$uname_out" == "Darwin" ]]; then
    $HOME/.dotfiles/scripts/macos/open_term.sh ${@}
elif [[ "$uname_out" == "Linux" ]]; then
    $HOME/.dotfiles/scripts/linux/open_term.sh ${@}
fi
