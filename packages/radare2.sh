install_radare2(){
    sudo_run 'mkdir -p /usr/local/src'
    sudo_run clone https://github.com/radare/radare2.git /usr/local/src/radare2
    cd /usr/local/src/radare2
    sys/install.sh
}
