symlink_mutt(){
    msg_debug "Symlink mutt"
    mkdir -p "~/.mutt/" 2> /dev/null
    symlink_file "mutt/muttrc" "$HOME/.muttrc"
}

install_mutt_ubuntu(){
    install_package mutt-patched
}

post_mutt(){
    msg_debug "Post mutt"
    #mkdir -p "~/.mutt/alias"         2> /dev/null
    #mkdir -p "~/.mutt/cache/headers" 2> /dev/null
    #mkdir -p "~/.mutt/cache/bodies"  2> /dev/null
    #mkdir -p "~/.mutt/certificates"  2> /dev/null
    #mkdir -p "~/.mutt/mailcap"       2> /dev/null
    #mkdir -p "~/.mutt/temp"          2> /dev/null
    #mkdir -p "~/.mutt/sig"           2> /dev/null
}
