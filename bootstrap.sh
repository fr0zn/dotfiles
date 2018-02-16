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

has_sudo() {
    local prompt

    prompt=$(sudo -nv 2>&1)
    if [ $? -eq 0 ]; then
    echo "has_sudo__pass_set"
    elif echo $prompt | grep -q '^sudo:'; then
    echo "has_sudo__needs_pass"
    else
    echo "no_sudo"
    fi
}

sudo_run(){
    if [[ "$UID" == "0" ]]; then
        ${@}
        return $?
    else
        HAS_SUDO=$(has_sudo)

        case "$HAS_SUDO" in
        has_sudo__pass_set)
            sudo -S ${@}
            ;;
        has_sudo__needs_pass)
            msg_info "Please supply your user password for the following command: \"${@}\""
            sudo -S "${@}"
            ;;
        *)
            msg_info "Please supply root password for the following command: \"${@}\""
            su -c "${@}"
            ;;
        esac
        return $?
    fi
}

install_package() {
    msg_info "Installing ${@} (${OS_TYPE})"
    case "${OS_TYPE}" in
        "macos")
            brew install "${@}"
            ;;
        "ubuntu" | "debian")
            sudo_run "apt -y install ${@}"
            ;;
        "arch")
            sudo_run "pacman -S --noconfirm ${@}"
            ;;
        *)
            msg_error "Auto-Installation not supported" "${OS_TYPE}"
            return 1
    esac
    if [[ $? -ne 0 ]];then
        msg_error "Error auto-installing" "${@} (maybe no permissions, or wrong package)"
        return 1
    fi
    return 0
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

    program_exists ${1}
    if [[ $? -ne 0 ]]; then
        install_package ${1}
        program_exists $1
        if [[ $? -ne 0 ]]; then
            msg_error "Not Found" "You must have '$1' installed to continue."
            exit 1
        fi
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
            msg_error "Error on clone" "$WHERE"
            exit 1
        else
            msg_ok "Cloned $WHERE"
        fi
    else
        ERROR=$(cd "$WHERE" && git pull origin 2>&1 > /dev/null)
        if [[ $? -ne 0 ]]; then
            msg_error "Pull error" "$WHERE"
            exit 1
        else
            msg_ok "Pulled $WHERE"
        fi
    fi
    return

}

backup() {
    msg_info "Attempting to back up your original configuration."
    mkdir $DOTFILE_BACKUP 2> /dev/null
    today=`date +%Y%m%d_%s`
    for i in "$@"; do
        [ -e "$i" ] && [ ! -L "$i" ] && mv -v "$i" "$DOTFILE_BACKUP/$i.$today" > /dev/null 2>&1;
    done
    msg_ok "Your original configuration has been backed up on $DOTFILE_BACKUP"
}

install() {
    . $DOTFILE_DESTINATION/$1/install.sh
}

run_level() {
    list=$(find $DOTFILE_DESTINATION/install -maxdepth 1 -name "${1}*")
    for element in $list; do
        if [[ $element == *"${OS_TYPE}.sh" || $element == *"all.sh" ]]; then
            msg_info "Running `basename $element`"
            . $element
        fi
    done
}

pre_check_run() {
    if [[ "$OS_TYPE" == "macos" ]]; then
        if [ ! -d "/Applications/Xcode.app" ]; then
          msg_error "Not Found" "You must have Xcode installed to continue."
          exit 1
        fi

        if xcode-select --install 2>&1 | grep installed; then
          msg_ok "Xcode CLI tools installed";
        else
          msg_error "Xcode CLI tools not installed" "Installing..."
        fi
    fi

    program_must_exist "git"
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
    OS_TYPE="macos"
elif [[ "$uname_out" == "Linux" ]]; then
    OS_TYPE="linux"
    if type lsb_release >/dev/null 2>&1 ; then
        distro=$(lsb_release -i -s)
        if [[ "$distro" == "Debian" || "$distro" == "Ubuntu" ]]; then
            OS_TYPE="debian"
        fi
    elif [ -f "/etc/arch-release" ]; then
        OS_TYPE="arch"
    fi
fi

msg_info "Running installation for OS: ${OS_TYPE}"

pre_check_run

clone $DOTFILE_REPO $DOTFILE_DESTINATION

pre_run
bak_run
ins_run
sym_run
pos_run

msg_ok "Done!"

# Get the new shell
/bin/zsh

# vim: set sw=4 ts=4 sts=4 et tw=78 foldmarker={,} foldlevel=0 foldmethod=marker :
