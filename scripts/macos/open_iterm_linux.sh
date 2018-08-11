if [[ ${1} = *"fr0zn"* ]]; then
    string=${1}
    prefix="/Users/fr0zn"
    foo=${string#$prefix}
    foo=${foo%$suffix}
    /usr/bin/osascript $HOME/.dotfiles/scripts/macos/open_iterm_window.scpt "ssh u64 -t \"cd /mnt/host_home/${foo};clear;bash -l\""
else
    /usr/bin/osascript $HOME/.dotfiles/scripts/macos/open_iterm_window.scpt "ssh u64 -t \"clear;bash -l\""
fi
