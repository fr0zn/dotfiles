install_pwndbg(){
    clone_src https://github.com/pwndbg/pwndbg pwndbg
    pushd $DOTFILE_SRC/pwndbg
    ./setup.sh
    popd
}
