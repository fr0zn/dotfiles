install_radare2(){
    clone_src https://github.com/radare/radare2.git radare2
    pushd $DOTFILE_SRC/radare2
    sys/install.sh
    popd
}
