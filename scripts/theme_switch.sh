#!/bin/bash

theme-switch () {
    uname_out=`uname`

    set_dark="true"
    if [[ "$uname_out" == "Darwin" ]]; then
        echo -e "\033]50;SetProfile=$1\a"; export TERM_PROFILE=$1;
        #if  [ "$1" = "light" ]; then
            #set_dark="false"
        #fi
        #/usr/bin/osascript -e "tell application \"System Events\" to tell appearance preferences to set dark mode to $set_dark"
    elif [[ "$uname_out" == "Linux" ]]; then
        theme=$HOME/.dotfiles/termite/themes/$1
        if [ -f $theme ]; then
            unlink $HOME/.dotfiles/termite/config 2>/dev/null
            ln -s $theme $HOME/.dotfiles/termite/config
            killall -USR1 termite
            export TERM_PROFILE=$1
        fi
    fi
}

