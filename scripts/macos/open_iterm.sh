if [ ! -z $1 ]; then
    if [[ "$1" == "tab"  ]]; then
        /usr/bin/osascript $HOME/.dotfiles/scripts/macos/open_iterm_tab.scpt ${@:2}
    elif [[ "$1" == "window" ]]; then
        /usr/bin/osascript $HOME/.dotfiles/scripts/macos/open_iterm_window.scpt ${@:2}
    else
        /usr/bin/osascript $HOME/.dotfiles/scripts/macos/open_iterm_window.scpt ${@}
    fi
else
    /usr/bin/osascript $HOME/.dotfiles/scripts/macos/open_iterm_window.scpt
fi
