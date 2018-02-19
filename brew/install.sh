install_brew(){
    program_exists "brew"
    if [[ $? -ne 0 ]]; then
        msg_info "Brew not found, installing ..."
        /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
    fi
}
