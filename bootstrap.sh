# vim: set sw=4 ts=4 sts=4 et tw=78 foldmarker={,} foldlevel=0 foldmethod=marker :
#!/bin/bash

DOTFILE_REPO="https://github.com/fr0zn/dotfiles.git"
DOTFILE_DESTINATION="$HOME/.dotfiles"
DOTFILE_BACKUP="$HOME/.dotfiles-backup"

msg() {
    printf '%b\n' "$1" >&2
}

action() {
    if [[ "$ret" -eq '0' ]]; then
        msg "\33[32m[✔]\33[0m ${1}"
    else
        msg "\33[31m[✘]\33[0m ${1}: ${2}"
    fi
}

lnif() {
    if [ -e "$1" ]; then
        ln -sf "$1" "$2"
    fi
    ret="$?"
}

program_exists() {

    local ret='0'
    command -v $1 >/dev/null 2>&1 || { local ret='1'; }

    # fail on non-zero return value
    if [ "$ret" -ne 0 ]; then
        return 1
    fi

    return 0
}

program_must_exist() {

    program_exists $1
    ret="$?"

    # throw error on non-zero return value
    if [ "$ret" -ne 0 ]; then
        action "Not Found" "You must have '$1' installed to continue."
        exit 1
    fi
}

function symlink(){
    lnif $DOTFILE_DESTINATION/$1 $2
}

function clone(){
    FROM=$1
    WHERE=$2

    if [ ! -e "$WHERE" ]; then
        mkdir -p "$WHERE" 2> /dev/null
        ERROR=$(git clone "$FROM" "$WHERE" 2>&1 > /dev/null)
        ret=$?
        action "$WHERE" "$ERROR"
    else
        ERROR=$(cd "$WHERE" && git pull origin 2>&1 > /dev/null)
        action "$WHERE" "$ERROR"
    fi

}

backup() {
    msg "Attempting to back up your original configuration."
    mkdir $DOTFILE_BACKUP 2> /dev/null
    today=`date +%Y%m%d_%s`
    for i in "$@"; do
        [ -e "$i" ] && [ ! -L "$i" ] && mv -v "$i" "$DOTFILE_BACKUP/$i.$today" > /dev/null 2>&1;
    done
    ret="0"
    action "Your original configuration has been backed up."
}

run() {
    ./$1
}

## Pre-Install
pre_nix() {
    program_must_exist "git"
    program_must_exist "vim"
    program_must_exist "tmux"
    program_must_exist "python"
    program_must_exist "zsh"
    program_must_exist "curl"
    #program_must_exist "make"
    #program_must_exist "ctags"
}
pre_macOS() {
    program_must_exist "exa"
    return 0
}
pre_linux() {
    return 0
}
## End Pre-Install

## Backups
bak_nix() {
    # Backup old configurations
    backup "$HOME/.vimrc" \
           "$HOME/.vim" \
           "$HOME/.tmux.conf" \
           "$HOME/.zshrc"
}
bak_macOS() {
    return 0
}
bak_linux() {
    return 0
}
## End Backups

## Installation
ins_nix() {
    # Clone dotfile repo
    clone $DOTFILE_REPO $DOTFILE_DESTINATION

    run $DOTFILE_DESTINATION/antigen/install.sh
    run $DOTFILE_DESTINATION/fzf/install.sh
    run $DOTFILE_DESTINATION/vim/install.sh
}
ins_macOS() {
    return 0
}
ins_linux() {
    return 0
}
## End Installation

## Symlinks
ln_nix() {
    symlink "vim/vimrc" "$HOME/.vimrc"
    symlink "tmux/tmux.conf" "$HOME/.tmux.conf"
    symlink "zsh/zshrc" "$HOME/.zshrc"
}
ln_macOS() {
    return 0
}
ln_linux() {
    return 0
}
## End Symlinks

## Post-Link
post_nix() {
    touch $HOME/.z
    mkdir -p ~/.vim/backup 2> /dev/null
    mkdir -p ~/.vim/swap 2> /dev/null
    mkdir -p ~/.vim/undo 2> /dev/null

    # vim plugins
    vim +PlugInstall +qall

    # Set zsh default and run-it
    msg "Changing the default shell to /bin/zsh (Enter password): "
    chsh -s /bin/zsh
    /bin/zsh
}
post_macOS() {
    return 0
}
post_linux() {
    return 0
}
## End Post-Link

OS_TYPE=`uname`

# Backup and link shared config
pre_nix
bak_nix
ins_nix
ln_nix
post_nix


if [[ "$OS_TYPE" == "Darwin" ]]; then
    # MacOS
    pre_macOS
    bak_macOS
    ins_macOS
    ln_macOS
    post_macOS
else
    # Linux
    pre_linux
    bak_linux
    ins_macOS
    ln_linux
    post_linux
fi
