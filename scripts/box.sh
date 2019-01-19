#!/bin/sh
vagrant_path=~/.dotfiles/vagrant

ProgName=$(basename $0)

box_sub_help(){
    echo "Usage: $ProgName <subcommand> [options]\n"
    echo "Subcommands:"
    echo "    status   Lists running boxes"
    echo "    ls       Lists available boxes"
    echo "    up       Starts a box"
    echo "    ssh      SSH to a running box"
    echo "    destroy  Destroys a box"
    echo "    suspend  Stops a box"
    echo "    resume   Starts an stopped box"
    echo ""
}

box_sub_status(){
    vagrant global-status | sed '/^\s$/,$d'
}

box_sub_ls(){
    valid_vagrants=`find $vagrant_path -maxdepth 1 -mindepth 1 -type d -printf "%f\n"`
    echo $valid_vagrants
}

box_sub_suspend(){
    if [ ! -z $1 ]; then
        machines_running=`vagrant global-status | tail -n +3 | sed '/^\s$/,$d'`
        matched=`echo $machines_running | grep -w $1`
        if [ $? = 0 ]; then
            id=`echo $matched | awk '{print $1}'`
            stat=`echo $matched | awk '{print $4}'`
            if [ $stat = "running" ]; then
                vagrant suspend $id
            else
                echo "Machine already suspended"
            fi
        else
            echo "Machine '$1' is not on, start it with '$ProgName up $1'"
        fi
    else
        echo "Usage: suspend <box-name>"
    fi
}

box_sub_resume(){
    if [ ! -z $1 ]; then
        machines_running=`vagrant global-status | tail -n +3 | sed '/^\s$/,$d'`
        matched=`echo $machines_running | grep -w $1`
        if [ $? = 0 ]; then
            id=`echo $matched | awk '{print $1}'`
            stat=`echo $matched | awk '{print $4}'`
            if [ $stat = "running" ]; then
                echo "Machine already running"
            else
                vagrant resume $id
            fi
        else
            echo "Machine '$1' is not on, start it with '$ProgName up $1'"
        fi
    else
        echo "Usage: resume <$ProgName-name>"
    fi
}


box_sub_ssh(){
    if [ ! -z $1 ]; then
        machines_running=`vagrant global-status | tail -n +3 | sed '/^\s$/,$d'`
        matched=`echo $machines_running | grep -w $1`
        if [ $? = 0 ]; then
            id=`echo $matched | awk '{print $1}'`
            stat=`echo $matched | awk '{print $4}'`
            if [ $stat = "running" ]; then
                vagrant ssh $id
            else
                echo "Machine '$1' is not running, use '$ProgName resume $1' to start it"
            fi
        else
            echo "Machine '$1' does not exist"
        fi
    else
        echo "Usage: ssh <box-name>"
    fi
}

box_sub_up(){
    valid_vagrants=`find $vagrant_path -maxdepth 1 -mindepth 1 -type d -printf "%f\n"`
    if [ ! -z $1 ]; then
        machines_running=`vagrant global-status | tail -n +3 | sed '/^\s$/,$d'`
        matched=`echo $machines_running | grep -w $1`
        if [ $? = 0 ]; then
            id=`echo $matched | awk '{print $1}'`
            stat=`echo $matched | awk '{print $4}'`
            if [ $stat = "running" ]; then
                echo "Already running"
            else
                echo "Machine is not running, starting it"
                vagrant resume $id
            fi
        else
            matched=`echo $valid_vagrants | grep -w $1`
            if [ $? = 0 ]; then
                echo "Starting box '$1'"
                pushd $vagrant_path/$1 >/dev/null
                vagrant up
                popd >/dev/null
            else
                echo "Machine '$1' does not exist"
            fi

        fi
    else
        echo "Usage: up <box-name>"
    fi
}

box_sub_destroy(){
    valid_vagrants=`find $vagrant_path -maxdepth 1 -mindepth 1 -type d -printf "%f\n"`
    if [ ! -z $1 ]; then
        machines_running=`vagrant global-status | tail -n +3 | sed '/^\s$/,$d'`
        matched=`echo $machines_running | grep -w $1`
        if [ $? = 0 ]; then
            id=`echo $matched | awk '{print $1}'`
            stat=`echo $matched | awk '{print $4}'`
            vagrant destroy $id
        else
            echo "Machine '$1' does not exist"
        fi
    else
        echo "Usage: destroy <box-name>"
    fi
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
                echo "Error: '$subcommand' is not a known subcommand." >&2
                echo "       Run '$ProgName --help' for a list of known subcommands." >&2
            fi
            ;;
    esac
}
