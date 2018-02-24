install_gef(){
    program_must_exist wget
    wget -q -O- https://github.com/hugsy/gef/raw/master/gef.sh | sh
}
