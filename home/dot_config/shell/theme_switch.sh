#!/bin/bash

theme-switch () {
    uname_out=`uname`

    if [[ "$uname_out" == "Darwin" ]]; then
        echo $1 > $HOME/.config/theme
        if  [ "$1" = "light" ]; then
            set_dark="false"
        else
            set_dark="true"
        fi
        /usr/bin/osascript -e "tell application \"System Events\" to tell appearance preferences to set dark mode to $set_dark"
    fi
}
