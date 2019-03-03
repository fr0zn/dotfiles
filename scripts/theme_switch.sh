#!/bin/bash

theme-switch () {
    uname_out=`uname`

    set_dark="true"
    if [[ "$uname_out" == "Darwin" ]]; then
        echo -e "\033]50;SetProfile=$1\a"; export ITERM_PROFILE=$1;
        #if  [ "$1" = "light" ]; then
            #set_dark="false"
        #fi
        #/usr/bin/osascript -e "tell application \"System Events\" to tell appearance preferences to set dark mode to $set_dark"
    elif [[ "$uname_out" == "Linux" ]]; then
        echo "TODO"
    fi
}

