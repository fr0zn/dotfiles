install_radare2(){
    clone https://github.com/radare/radare2.git $DOTFILE_SRC/radare2
    cd $DOTFILE_SRC/radare2
    sys/install.sh
}
