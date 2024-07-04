#/bin/bash

_msg() {
    echo -e "$1" >&2
}

_msg_info() {
    _msg "\e[1;94m==>\e[1;0m ${1}"
}

_exists(){
    out=$(command -v ${1})
    return $?
}

_get_current_py(){
    if _exists pyenv; then
        export PYENV_ROOT="$HOME/.pyenv"
        export PATH="$PYENV_ROOT/bin:$PATH"
        eval "$(pyenv init --path)"
        eval "$(pyenv init -)"
        if which pyenv-virtualenv-init > /dev/null; then eval "$(pyenv virtualenv-init -)"; fi
        version=$(pyenv version | awk '{print $1}' ORS=', ' | sed '$s/..$//')
        #bits=$(python -c 'import struct; print(struct.calcsize("P") * 8)')
        _msg_info "Current Python: ${version}" #(${bits} bits)"
    fi
}

_get_current_rb(){
    if _exists rbenv; then
        eval "$(rbenv init -)"
        version=$(rbenv version | awk '{print $1}' ORS=', ' | sed '$s/..$//')
        #bits=$(python -c 'import struct; print(struct.calcsize("P") * 8)')
        _msg_info "Current Ruby: ${version}" #(${bits} bits)"
    fi
}

_get_current_node(){
    export NVM_DIR="$HOME/.nvm"
    [ -s "/opt/homebrew/opt/nvm/nvm.sh" ] && \. "/opt/homebrew/opt/nvm/nvm.sh"  # This loads nvm
    [ -s "/opt/homebrew/opt/nvm/etc/bash_completion.d/nvm" ] && \. "/opt/homebrew/opt/nvm/etc/bash_completion.d/nvm"  # This loads nvm bash_completion
    version=$(nvm version)
    _msg_info "Current Node: ${version}" #(${bits} bits)"
}

_get_current_go(){
    if _exists goenv; then
        eval "$(goenv init -)"
        export PATH="$GOROOT/bin:$PATH"
        export PATH="$PATH:$GOPATH/bin"
        version=$(goenv version | awk '{print $1}' ORS=', ' | sed '$s/..$//')
        _msg_info "Current Go: ${version}" #(${bits} bits)"
    fi
}

_get_current_py
_get_current_rb
_get_current_node
_get_current_go
