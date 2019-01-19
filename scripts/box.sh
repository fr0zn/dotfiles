#!/bin/sh
vagrant_path=$HOME/.dotfiles/vagrant

ProgName=$(basename $0)

box_sub_help(){
    echo "Usage: $ProgName <subcommand> [options]\n"
    echo "Subcommands:"
    echo "    status   Lists running boxes"
    echo "    edit     Edits Vagrantfile"
    echo "    ls       Lists available boxes"
    echo ""
    vagrant --help
}

box_sub_status(){
    vagrant global-status | sed '/^\s$/,$d'
}

box_sub_ls(){
    valid_vagrants=`find $vagrant_path -type d -maxdepth 1 -mindepth 1 -exec basename {} \;`
    echo $valid_vagrants
}

box_sub_edit(){
    if [ ! -z "$1" ]; then
        machine_name="${@: -1}"
        machines_running=`vagrant global-status | tail -n +3 | sed '/^\s$/,$d'`
        matched=`echo $machines_running | grep -w $machine_name`
        if [ $? = 0 ]; then
            box_path=`echo $matched | awk '{print $5}'`
        else
            valid_vagrants=`find $vagrant_path -type d -maxdepth 1 -mindepth 1 -exec basename {} \;`
            matched=`echo $valid_vagrants | grep -w $machine_name`
            if [ $? = 0 ]; then
                box_path="$vagrant_path/$machine_name"
            else
                echo "No valid box name, use 'ls' or 'status'"
                return
            fi
        fi
    else
        echo "Usage: $ProgName edit <box-name>"
        return
    fi

    $EDITOR $box_path/Vagrantfile
}

box_sub_others(){
    machine_name="${@: -1}"
    machines_running=`vagrant global-status | tail -n +3 | sed '/^\s$/,$d'`
    matched=`echo $machines_running | grep -w $machine_name`
    if [ $? = 0 ]; then
        box_path=`echo $matched | awk '{print $5}'`
    else
        valid_vagrants=`find $vagrant_path -type d -maxdepth 1 -mindepth 1 -exec basename {} \;`
        matched=`echo $valid_vagrants | grep -w $machine_name`
        if [ $? = 0 ]; then
            box_path="$vagrant_path/$machine_name"
        else
            echo "No valid box name, use 'ls' or 'status'"
            return
        fi
    fi

    pushd $box_path >/dev/null
    vagrant ${@:1:$#-1}
    popd >/dev/null

}

box () {
    subcommand=$1
    case $subcommand in
        "" | "-h" | "--help")
            box_sub_help
            ;;
        *)
            shift
            box_sub_${subcommand} $@ 2>/dev/null
            if [ $? = 127 ]; then
                box_sub_others $subcommand $@
            fi
            ;;
    esac
}
