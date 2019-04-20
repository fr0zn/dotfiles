#!/bin/bash

theme-switch () {
    uname_out=`uname`

    set_dark="true"
    if [[ "$uname_out" == "Darwin" ]]; then
        #echo -e "\033]50;SetProfile=$1\a";
        echo $1 > $HOME/.dotfiles/theme
        if  [ "$1" = "light" ]; then
            osascript -e 'tell application "System Events" to key code 99 using {command down}'
        else
            osascript -e 'tell application "System Events" to key code 118 using {command down}'
        fi
        #/usr/bin/osascript -e "tell application \"System Events\" to tell appearance preferences to set dark mode to $set_dark"
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
