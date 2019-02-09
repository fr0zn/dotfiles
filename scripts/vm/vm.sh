#!/bin/bash

vm_path="$DOTFILE_PATH/scripts/vm"

prog_name="vm"

_valid_commands="start stop suspend pause unpause ssh"
_valid_vmtypes="vmware qemu virtualbox"

vm_list (){
    find "$vm_path" -maxdepth 2 -name "*.vm" -execdir sh -c 'printf "%s\n" "${0%.*}"' {} ';'
}

_vm_valid (){
    all_vms=`vm_list`
    if [ ! -z $1 ]; then
        echo $all_vms | grep $1 2>&1 >/dev/null
        if [ "$?" = "0" ]; then
            return 0
        fi
    fi

    echo "Invalid vm"
    return 1
}

_vm_load (){
    if [ ! -z $1 ]; then
        . $vm_path/$1.vm
        return 0
    fi

    echo "Invalid vm"
    return 1
}

vm_qemu_start (){
    $vmpath
}

vm_qemu_stop (){
    echo 'TODO'
    pkill qemu-system-aarch64
    pkill qemu-system-arm
}

vm_qemu_suspend (){
    echo 'TODO'
}

vm_qemu_pause (){
    echo 'TODO'
}

vm_qemu_unpause (){
    echo 'TODO'
}

vm_qemu_ssh (){
    ssh localhost -p $vmport
}

vm_vmware_start (){
    vmrun start "$vmpath" nogui
}

vm_vmware_stop (){
    vmrun stop "$vmpath" nogui
}

vm_vmware_suspend (){
    vmrun suspend "$vmpath" nogui
}

vm_vmware_pause (){
    vmrun pause "$vmpath" nogui
}

vm_vmware_unpause (){
    vmrun unpause "$vmpath" nogui
}

vm_vmware_ssh (){
    ip=`vmrun getGuestIPAddress $vmpath`
    ssh -p $vmport $ip
}

vm () {
    subcommand=$1
    case $subcommand in
        ("" | "-h" | "--help") vm_sub_help ;;
        ("list") vm_list ;;
        (*) shift
            echo $_valid_commands | grep $subcommand 2>&1 >/dev/null
            if [ "$?" = "0" ]
            then
                if [ -z $1 ]; then
                    echo "Usage: $prog_name $subcommand <vmname>"
                    return
                fi
                _vm_valid $1 || return
                _vm_load $1

                echo $_valid_vmtypes | grep $vmtype 2>&1 >/dev/null
                if [ "$?" = "0" ]
                then
                    vm_${vmtype}_${subcommand} $@ 2> /dev/null
                else
                    echo "Invalid vmtype, valids are '$_valid_vmtypes'"
                fi
            else
                vm_sub_help
            fi;;
    esac
}

vm_sub_help () {
    echo "Usage: $prog_name <subcommand> [vmname]\n"
    echo "Subcommands:"
    echo "    list     Lists available vms"
    echo "    start    Starts the vm"
    echo "    stop     Stops the vm"
    echo "    suspend  Suspends the vm"
    echo "    pause    Pauses the vm"
    echo "    unpause  Unpauses the vm"
    echo "    ssh      SSH shell to the vm"
    echo ""
}
