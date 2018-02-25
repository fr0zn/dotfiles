DOTFILE_PATH="$HOME/.dotfiles"
TEMPLATES_PATH="$HOME/.dotfiles/templates"
PACKAGES_PATH="$HOME/.dotfiles/packages"

msg() {
    printf '%b\n' "$1" >&2
}

msg_info() {
    msg "\33[34m[*]\33[0m ${1}"
}

msg_debug() {
    msg "\33[36m[d]\33[0m ${1}"
}

msg_ok() {
    msg "\33[32m[+]\33[0m ${1}"
}

msg_error() {
    msg "\33[31m[-]\33[0m ${1}: ${2}"
}

echo "1 - New package"
echo "2 - New package (with configs)"
read -p "Action: " -n 1 action
echo
read -p "Package name: " pname
echo
read -p "Only one distro? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]];then
    read -p "Distro name: " distro
fi
echo

if [[ ! -z $distro ]]; then
    distro="_${distro}"
fi

if [[ "$action" == "1" ]];then
    msg_debug "New package"
    cp "${TEMPLATES_PATH}/install.sh" "${PACKAGES_PATH}/${pname}.sh"
    sed -i '' -e "s/program/${pname}${distro}/g" "${PACKAGES_PATH}/${pname}.sh"
    if [[ $? -eq 0 ]]; then
        msg_ok "Created template configuration for '${pname}' in '${PACKAGES_PATH}/${pname}.sh'"
    else
        msg_error "Unable to create the '${PACKAGES_PATH}/${pname}.sh' template"
    fi
elif [[ "$action" == "2" ]];then
    msg_debug "New package (with configs)"
    mkdir -p "${DOTFILE_PATH}/${pname}"
    if [[ $? -eq 0 ]]; then
        msg_ok "Created folder ${DOTFILE_PATH}/${pname}"
        cp "${TEMPLATES_PATH}/install.sh" "${DOTFILE_PATH}/${pname}"
        sed -i '' -e "s/program/${pname}${distro}/g" "${DOTFILE_PATH}/${pname}/install.sh"
        if [[ $? -eq 0 ]]; then
            msg_ok "Created template configuration for '${pname}' in '${DOTFILE_PATH}/${pname}/install.sh'"
        else
            msg_error "Unable to create the '${DOTFILE_PATH}/${pname}/install.sh' template"
        fi
    else
        msg_error "Folder '${DOTFILE_PATH}/${pname}', not created (already exists?)"
    fi
fi

