#/bin/bash

_msg() {
    echo -e "$1" >&2
}

_msg_info() {
    _msg "\e[1;94m==>\e[1;0m ${1}"
}

_get_current_py(){
    version=$(pyenv version | awk '{print $1}' ORS=', ' | sed '$s/..$//')
    #bits=$(python -c 'import struct; print(struct.calcsize("P") * 8)')
    _msg_info "Current Python: ${version}" #(${bits} bits)"
}

_get_current_rb(){
    version=$(rbenv version | awk '{print $1}' ORS=', ' | sed '$s/..$//')
    #bits=$(python -c 'import struct; print(struct.calcsize("P") * 8)')
    _msg_info "Current Ruby: ${version}" #(${bits} bits)"
}

_get_current_py
_get_current_rb
