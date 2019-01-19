install_fixenv(){
    curl https://raw.githubusercontent.com/hellman/fixenv/master/r.sh > $DOTFILE_PATH/bin/fixenv
    chmod +x $DOTFILE_PATH/bin/fixenv
}
