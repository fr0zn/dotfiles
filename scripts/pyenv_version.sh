#/bin/bash

_msg() {
    echo -e "$1" >&2
}

_msg_info() {
    _msg "\e[1;94m==>\e[1;0m ${1}"
}

_get_versions(){
    pyenv versions
}

_set_version(){
    export PYENV_VERSION="${@}"
}

_get_current(){
    version=$(pyenv version | awk '{print $1}' ORS=', ' | sed '$s/..$//')
    #bits=$(python -c 'import struct; print(struct.calcsize("P") * 8)')
    _msg_info "Current Python: ${version}" #(${bits} bits)"
}

_get_current
