#!/bin/bash

DOTFILE_REPO="https://github.com/fr0zn/dotfiles.git"
DOTFILE_PATH="$HOME/.dotfiles"
DOTFILE_BACKUP="$HOME/.dotfiles-backup"
DOTFILE_SRC="$DOTFILE_PATH/src"
DOTFILE_BIN="$DOTFILE_PATH/bin"
DB_SYNC=0
OS_TYPE=""

STEPS="pre backup symlink install post"

msg() {
    printf '%b\n' "$1" >&2
}

msg_info() {
    if [[ "${2}" == "in" ]]; then
        msg "\33[94m  ->\33[0m ${1}"
    else
        msg "\33[94m==>\33[0m ${1}"
    fi
}

msg_debug() {
    if [[ "$DEBUG" == "1" ]]; then
        if [[ "${2}" == "in" ]]; then
            msg "\33[96m  ->\33[0m ${1}"
        else
            msg "\33[96m==>\33[0m ${1}"
        fi
    fi
}

msg_ok() {
    if [[ "${2}" == "in" ]]; then
        msg "\33[92m  ->\33[0m ${1}"
    else
        msg "\33[92m==>\33[0m ${1}"
    fi
}

msg_error() {
    if [[ "${2}" == "in" ]]; then
        msg "\33[91m  -> ERROR:\33[0m ${1}"
    else
        msg "\33[91m==> ERROR:\33[0m ${1}"
    fi
}

die(){
    msg_error "${@}"
    exit 1
}

lnif() {
    if [ -e "$1" ]; then
        ln -sf "$1" "$2"
        if [[ ! -L ${2} ]]; then
            return 1
        fi
        return 0
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

clean(){
    if [[ "$DEBUG" != "1" ]]; then
        $@ > /dev/null
    else
        $@
    fi
}

sudo_run(){
    if [[ "$UID" == "0" ]]; then
        ${@}
    else
        HAS_SUDO=$(has_sudo)
        case "$HAS_SUDO" in
        has_sudo__pass_set)
            sudo bash <<EOF
            $@
EOF
            ;;
        has_sudo__needs_pass)
            msg_info "Please supply your user password for the following command: \"${*}\"" "in"
            sudo bash <<EOF
            $@
EOF
            ;;
        *)
            msg_info "Please supply root password for the following command: \"${*}\"" "in"
            su -c "${@}"
            ;;
        esac
    fi
}

sync_database() {
    if [[ "$DB_SYNC" == "0"  ]]; then
        msg_info "Updating database packages"
        case "${OS_TYPE}" in
            "macos")
                clean brew update
                ;;
            "ubuntu" | "debian" | "rpi")
                clean sudo_run 'apt-get update'
                ;;
            "arch")
                clean sudo_run 'pacman -Sy --noconfirm'
                ;;
        esac
        if [[ "$?" == "0" ]]; then
            msg_ok "Database synced" "in"
            DB_SYNC=1
        else
            die "Error syncing and updating packages" "in"
        fi
    fi
}

install_cask() {

    sync_database

    msg_info "Installing cask ${*} (${OS_TYPE})"

    to_install_str=$(_get_packages_not_installed "${*}")

    if [[ "$to_install_str" == "0" ]]; then
        # All installed
        return 0
    fi

    msg_info "Installing only casks '${to_install_str}' (${OS_TYPE})" "in"

    case "${OS_TYPE}" in
        "macos")
            clean brew cask install "${*}"
            ;;
        *)
            msg_error "brew cask not supported ${OS_TYPE}" "in"
            return 1
    esac
    if [[ $? -ne 0 ]];then
        msg_error "Error auto-installing '${*}', no permission, wrong package, or already installed" "in"
        return 1
    fi
    return 0
}

_get_packages_not_installed(){
    local is_installed
    local packages=(${@})
    local to_install=()
    local already_installed=()

    for i in "${!packages[@]}"; do
        out=$(is_package_installed "${packages[$i]}")
        is_installed="$?"
        if [[ "$is_installed" == "1" ]]; then
            to_install+=("${packages[$i]}")
        else
            already_installed+=("${packages[$i]}")
        fi
    done

    to_install_str=$(IFS=":" echo "${to_install[*]}")
    already_installed_str=$(IFS=":" echo "${already_installed[*]}")
    if [[ -z "${to_install_str}" ]]; then
        # Everything installed
        msg_ok "All packages already installed, skipping" "in"
        echo "0"
    else
        if [[ ! -z "${already_installed_str}" ]]; then
            msg_ok "Packages already installed '${already_installed_str}'" "in"
        fi
    fi

    echo "$to_install_str"
}

install_package() {

    sync_database

    msg_info "Installing packages '$*' (${OS_TYPE})"

    to_install_str=$(_get_packages_not_installed "$*")

    if [[ "$to_install_str" == "0" ]]; then
        # All installed
        return 0
    fi

    msg_info "Installing only packages '${to_install_str}' (${OS_TYPE})" "in"

    case "${OS_TYPE}" in
        "macos")
            clean brew install "${to_install_str}"
            ;;
        "ubuntu" | "debian" | "rpi")
            clean sudo_run "apt-get -y install ${to_install_str}"
            ;;
        "arch")
            clean sudo_run "pacman -S --noconfirm ${to_install_str}"
            ;;
        *)
            msg_error "Auto-Installation not supported ${OS_TYPE}" "in"
            return 1
    esac
    if [[ $? -ne 0 ]];then
        msg_error "Error auto-installing '${to_install_str}', no permission, wrong package, or already installed" "in"
        return 1
    fi
    return 0

}

y_n(){
    read -p "$1 (y/n)?: " -n 1 -r
    echo    # (optional) move to a new line
    if [[ $REPLY =~ ^[Yy]$ ]]
    then
        $"$2"
    else
        $"$3"
    fi
}

is_package_installed(){
    msg_debug "Checking if ${1} is installed"
    case "${OS_TYPE}" in
        "macos")
            brew ls --versions ${1} > /dev/null 2>&1
            if [[ "$?" == "1" ]]; then
                brew cask ls --versions ${1} > /dev/null 2>&1
            fi
            ;;
        "ubuntu" | "debian" | "rpi")
            dpkg -l | grep -w ${1} > /dev/null 2>&1
            ;;
        "arch")
            pacman -Qi ${1} > /dev/null 2>&1
            ;;
        *)
            msg_error "Check if package is installed not supported ${OS_TYPE}" "in"
            return 1
    esac
}

package_must_exist(){
    is_package_installed $1
    if [[ $? -ne 0 ]]; then
        die "Not Found You must have '${1}' installed to continue." "in"
        exit 1
    fi
}

is_app_installed() {
    if [[ "$OS_TYPE" == "macos" ]]; then
        if [ -d "/Applications/${1}.app" ]; then
            return 0
        fi
        return 1
    else
        msg_info "Not a macOS, can't check if ${1}.app is installed" "in"
        return 1
    fi
}

open_app(){
    if [[ "$OS_TYPE" == "macos" ]]; then
        if [ -d "/Applications/${1}.app" ]; then
            bundle=$(mdls -name kMDItemCFBundleIdentifier -r /Applications/${1}.app)
            /usr/bin/open -b "${bundle}"
        else
            msg_error "Application ${1}.app does not exist" "in"
        fi
    else
        msg_info "Not a macOS, can't run app ${1}.app" "in"
        return 1
    fi
}

add_app_login(){
    if [[ "$OS_TYPE" == "macos" ]]; then
        if [ -d "/Applications/${1}.app" ]; then
            tell="tell application \"System Events\" to make login item at end with properties {name: \"${1}\",path:\"/Applications/${1}.app\", hidden:false}"
            /usr/bin/osascript -e "${tell}" >/dev/null
            if [[ "$?" == "0" ]]; then
                msg_ok "Application '${1}' set on startup" "in"
            else
                msg_error "Application '${1}' not set on startup" "in"
            fi
        else
            msg_error "Application ${1}.app does not exist" "in"
        fi
    else
        msg_info "Not a macOS, can't link app ${1}.app" "in"
        return 1
    fi
}

add_line(){
    local file="${1}"
    local line="${2}"
    if [ ! -f "$file" ]; then
        echo "$line" >> "$file"
    else
        grep -qF -- "$line" "$file" || echo "$line" >> "$file"
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
    if [[ $? -ne 0 ]]; then
        die "Not Found You must have '$1' installed to continue." "in"
        exit 1
    fi
}

symlink_file(){
    local path=$(dirname "${2}")
    if [ ! -d "$path" ]; then
        mkdir -p $path 2> /dev/null
    fi
    lnif "$DOTFILE_PATH/$1" "$2"
    return $?
}

function clone(){
    msg_info "Retrieving sources..."

    FROM=$1
    WHERE=$2

    if [ ! -e "$WHERE" ]; then
        mkdir -p "$WHERE" 2> /dev/null
        ERROR=$(git clone "$FROM" "$WHERE" 2>&1 > /dev/null)
        if [[ $? -ne 0 ]]; then
            msg_error "Error on clone $WHERE" "in"
            return 1
        else
            msg_ok "Cloned $WHERE" "in"
            return 0
        fi
    else
        ERROR=$(cd "$WHERE" && git pull origin 2>&1 > /dev/null)
        if [[ $? -ne 0 ]]; then
            msg_error "Pull error: $WHERE" "in"
            return 1
        else
            msg_ok "Pulled $WHERE" "in"
            return 0
        fi
    fi
    return

}

function clone_src(){
    clone ${1} "$DOTFILE_SRC/${2}"
}

_function_exists() {
    declare -f -F $1 > /dev/null
    return $?
}

backup_file() {
    msg_ok "Backing up files" "in"
    mkdir -p $DOTFILE_BACKUP 2> /dev/null
    local file_name
    today=`date +%Y%m%d_%s`
    for i in "$@"; do
        file_name=$(basename $i)
        if [[ -e "$i" ]]; then
            cp "$i" "${DOTFILE_BACKUP}/${file_name}.${today}" 2>/dev/null 2>&1;
            if [[ ! -f "${DOTFILE_BACKUP}/${file_name}.${today}" ]]; then
                msg_error "Backup file ${i}" "in"
                exit 1
            fi
        fi
    done
    return 0
}

# Loads all install.sh script from the dotfiles folder
_load() {
    list=$(find "$DOTFILE_PATH" -maxdepth 2 -name install.sh)
    for element in $list; do
        . $element
    done
    list=$(find "$DOTFILE_PATH/packages" -maxdepth 2 -name "*.sh")
    for element in $list; do
        . $element
    done
}

_template() {
    if _function_exists "${1}_${2}_$OS_TYPE"; then
        msg_debug "${2}: ${1} ($OS_TYPE)" "in"
        $"${1}_${2}_$OS_TYPE"
    elif _function_exists "${1}_${2}"; then
        msg_debug "${2}: ${1} (generic)" "in"
        $"${1}_${2}"
    else
        msg_debug "${2}: Tried to run ${1}_${2}, but it doesn't exist" "in"
        return 0
    fi
    return $?
}

install() {
    local steps
    steps=$STEPS
    msg_info "Installing: '$1'"
    if [[ ! -z "$2" ]]; then
        msg_info "$1: Custom steps installation, steps: ${@:2}"
        steps="${@:2}"
    fi

    for step in $steps; do
        _template "$step" "$1"
        cd $HOME
        if [[ $? -ne 0 ]]; then
            msg_error "Error installing '$1' in step: $step"
            return 1
        fi
    done

    msg_ok "Done: '$1'" "in"
    return 0
}

install_aur(){

    sync_database

    msg_info "Installing AUR package ${1} (${OS_TYPE})"

    to_install_str=$(_get_packages_not_installed "$*")

    if [[ "$to_install_str" == "0" ]]; then
        # All installed
        return 0
    fi

    case "${OS_TYPE}" in
        "arch")
            local path="${DOTFILE_SRC}/${1}"
            clone https://aur.archlinux.org/${1}.git $path
            cd $path
            makepkg -si --noconfirm
            ;;
        *)
            msg_error "AUR package not supported ${OS_TYPE}" "in"
            return 1
    esac
    if [[ $? -ne 0 ]];then
        msg_error "Error auto-installing '${*}', wrong package, failed build or missing dependencies" "in"
        return 1
    fi
    return 0

}

install_brew_macos(){
    program_exists "brew"
    if [[ $? -ne 0 ]]; then
        msg_info "Brew not found, installing ..."
        /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
    fi
    program_exists "brew"
    if [[ $? -ne 0 ]]; then
        return 1
    fi
    return 0
}

ctrl_c() {
    echo
    echo
    msg_error "Aborted by user! Exiting..."
    exit 1
}

_pre_run() {
    if [[ "$OS_TYPE" == "macos" ]]; then
        if ! is_app_installed "Xcode"; then
          msg_error "Not Found: you must have Xcode installed to continue."
          exit 1
        fi

        if xcode-select --install 2>&1 | grep installed > /dev/null; then
          msg_ok "Xcode CLI tools installed";
        else
          msg_error "Xcode CLI tools not installed Installing..."
        fi

        install "brew"
    fi

    program_exists "git"
    if [[ $? -ne 0 ]]; then
        install_package "git"
        program_must_exist "git"
    fi

    clone $DOTFILE_REPO $DOTFILE_PATH
}

_get_os(){
    uname_out=`uname`

    if [[ "$uname_out" == "Darwin" ]]; then
        OS_TYPE="macos"
    elif [[ "$uname_out" == "Linux" ]]; then
        OS_TYPE="linux"
        if type lsb_release >/dev/null 2>&1 ; then
            distro=$(lsb_release -i -s)
            if [[ "$distro" == "Debian" ]]; then
                OS_TYPE="debian"
            elif [[ "$distro" == "Ubuntu" ]]; then
                OS_TYPE="ubuntu"
            elif [[ "$distro" == "Raspbian" ]]; then
                OS_TYPE="rpi"
            fi
        elif [ -f "/etc/arch-release" ]; then
            OS_TYPE="arch"
        fi
    fi

    msg_info "Running installation for OS: ${OS_TYPE}"
}

_run(){

    sync_database

    . "$DOTFILE_PATH/install.sh"

    if _function_exists "install_$OS_TYPE"; then
        $"install_$OS_TYPE"
    fi

    $"install_all"

    if [[ $? -eq 0 ]]; then
        msg_ok "Done installing dotfiles!"
    else
        msg_error "Finished with some errors"
    fi
}

_edit(){
    vi "$DOTFILE_PATH/install.sh"
    y_n "Run installation now" _run return
}

_run_no(){
    y_n "Edit installation" _edit return
}

# trap ctrl-c and call ctrl_c()
trap ctrl_c INT

_get_os
_pre_run
_load # Load all installation files

if [[ "$1" != "SOURCED" ]]; then
    y_n "Run installation" _run _run_no
else
    # Interactive
    while true; do
        read -p "cmd: " cmd
        echo "$cmd"
        $cmd
    done
fi

# vim: set sw=4 ts=4 sts=4 et tw=78 foldmarker={,} foldlevel=0 foldmethod=marker :
