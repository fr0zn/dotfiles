# vim: set sw=4 ts=4 sts=4 et tw=78 foldmarker={,} foldlevel=0 foldmethod=marker :
#!/bin/bash

DOTFILE_REPO="https://github.com/fr0zn/dotfiles.git"
DOTFILE_DESTINATION="$HOME/.dotfiles"
DOTFILE_BACKUP="$HOME/.dotfiles-backup"

msg() {
    printf '%b\n' "$1" >&2
}

msg_info() {
    msg "\33[34m[*]\33[0m ${1}"
}

msg_ok() {
    msg "\33[32m[+]\33[0m ${1}"
}

msg_error() {
    msg "\33[31m[-]\33[0m ${1}: ${2}"
}

lnif() {
    if [ -e "$1" ]; then
        ln -sf "$1" "$2"
    fi
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

    # throw error on non-zero return value
    if [[ $? -ne 0 ]]; then
        msg_error "Not Found" "You must have '$1' installed to continue."
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
        if [[ $? -ne 0 ]]; then
            msg_error "$WHERE" "Not cloned"
        else
            msg_ok "$WHERE"
        fi
    else
        ERROR=$(cd "$WHERE" && git pull origin 2>&1 > /dev/null)
        if [[ $? -ne 0 ]]; then
            msg_error "$WHERE" "Pull error"
        else
            msg_ok "$WHERE"
        fi
    fi

}

backup() {
    msg_info "Attempting to back up your original configuration."
    mkdir $DOTFILE_BACKUP 2> /dev/null
    today=`date +%Y%m%d_%s`
    for i in "$@"; do
        [ -e "$i" ] && [ ! -L "$i" ] && mv -v "$i" "$DOTFILE_BACKUP/$i.$today" > /dev/null 2>&1;
    done
    msg_ok "Your original configuration has been backed up."
}

install() {
    . $DOTFILE_DESTINATION/$1/install.sh
}

run_level() {
    list=$(find $DOTFILE_DESTINATION/install -maxdepth 1 -name "${1}*")
    for element in $list; do
        if [[ $element == *"$OS_TYPE"* || $element == *"all"* ]]
            . $element
        fi
        echo msg_info "Installed `basename $element`"
    done
}

## 0 - Pre-Install
pre_run() {
    run_level "0"
}


## 1 - Backups
bak_run() {
    run_level "1"
}

## 2 - Installation
ins_run() {
    run_level "2"
}

## 3 - Symlinks
sym_run() {
    run_level "3"
}

## 4 - Post-Link/Installation
pos_run() {
    run_level "4"
}

uname_out=`uname`

OS_TYPE=""

if [[ "$uname_out" == "Darwin" ]]; then
    $OS_TYPE="mac"
elif [[ "$uname_out" == "Linux" ]]; then
    $OS_TYPE="linux"
    // Check distro
fi


pre_run
bak_run
ins_run
sym_run
pos_run

msg_ok "Done!"

# Get the new shell
/bin/zsh
