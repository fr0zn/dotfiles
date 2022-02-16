#!/bin/bash

theme-switch () {
    uname_out=`uname`

    if [[ "$uname_out" == "Darwin" ]]; then
        #echo -e "\033]50;SetProfile=$1\a";
        echo $1 > $HOME/.dotfiles/theme
        if  [ "$1" = "light" ]; then
            set_dark="false"
        else
            set_dark="true"
        fi
        /usr/bin/osascript -e "tell application \"System Events\" to tell appearance preferences to set dark mode to $set_dark"
        theme=$HOME/.dotfiles/kitty/themes/$1
        #if [ -f $theme ]; then
            #kitty @ set-colors --all --configured ~/.dotfiles/kitty/themes/$1
        #fi
    elif [[ "$uname_out" == "Linux" ]]; then
        theme=$HOME/.dotfiles/termite/themes/$1
        if [ -f $theme ]; then
            unlink $HOME/.dotfiles/termite/config 2>/dev/null
            ln -s $theme $HOME/.dotfiles/termite/config
            killall -USR1 termite
            echo $1 > $HOME/.dotfiles/theme
        fi
    fi
}

