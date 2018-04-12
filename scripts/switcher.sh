#/bin/bash

msg() {
    echo -e "$1" >&2
}

msg_info() {
    msg "\e[1;94m==>\e[1;0m ${1}"
}

msg_ok() {
    msg "\e[1;92m==>\e[1;0m ${1}"
}

msg_error() {
    msg "\e[1;91m==> ERROR:\e[1;0m ${1}"
}

_get_versions(){
    pyenv versions
}

_set_version(){
    if [ -z ${1} ]; then
        msg_error "No version given"
        return 1
    fi
    _get_versions | cut -b 3- | cut -d' ' -f 1 | grep "^${1}$" > /dev/null
    if [ "$?" -eq "0" ]; then
        msg_ok "Changed to version ${1}"
        export PYENV_VERSION=${1}
    else
        msg_error "Version ${1} not found"
    fi
}

_get_current(){
    version=$(pyenv version | awk '{print $1}')
    bits=$(python -c 'import struct; print(struct.calcsize("P") * 8)')
    msg_info "Current: Python ${version} (${bits} bits)"
}

_switch(){
    if [ -z ${1} ]; then
        _get_versions
        return 0
    fi

    if [[ ${1} == "python" ]]; then
        if [ ! -z "${2}" ]; then
            _set_version ${2}
        else
            _get_versions
        fi
    else
        msg_info "What to switch? python"
    fi
}

_get_current
