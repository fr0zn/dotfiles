#!/bin/bash

vm_path="$HOME/.dotfiles/scripts/vm"

prog_name="vm"

_valid_commands="start stop ssh mount umount ip"
_valid_vmtypes="vmware qemu virtualbox"

vm_list (){
    find "$vm_path" -maxdepth 2 -name "*.vm" -execdir sh -c 'printf "%s\n" "${0%.*}" | sed "s/.\///g"' {} ';'
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
    echo "Starting vm $vmname"
    $vmpath
}

vm_qemu_stop (){
    echo "Stopping vm $vmname"
    vm_qemu_umount $@
    pkill qemu-system-aarch64
    pkill qemu-system-arm
}

vm_qemu_mount (){
    echo "Mounting vm $vmname"
    sudo sshfs -o allow_other,defer_permissions -p $vmport fr0zn@localhost:/home/fr0zn/shared /Volumes/VMNet/SHARED/$vmname
}

vm_qemu_umount (){
    echo "Umounting vm $vmname"
    umount /Volumes/VMNet/SHARED/$vmname
}

vm_qemu_ssh (){
    # vm_qemu_mount $@
    ssh -t localhost -p $vmport "cd \$HOME/shared; exec \$SHELL -l"
}

vm_qemu_ip (){
    echo "localhost"
}

vm_vmware_start (){
    echo "Starting vm $vmname"
    vmrun start "$vmpath" nogui
}

vm_vmware_stop (){
    echo "Stopping vm $vmname"
    # vm_vmware_umount $@
    vmrun stop "$vmpath" nogui
}

vm_vmware_mount (){
    echo "Mounting vm $vmname"
    ip=`vmrun getGuestIPAddress $vmpath`
    sudo sshfs -o allow_other,defer_permissions -p $vmport fr0zn@$ip:/home/fr0zn/shared /Volumes/VMNet/SHARED/$vmname
}

vm_vmware_ip() {
    ip=`vmrun getGuestIPAddress $vmpath`
    echo "$ip"
}

vm_vmware_umount (){
    echo "Umounting vm $vmname"
    umount /Volumes/VMNet/SHARED/$vmname
}

vm_vmware_ssh (){
    ip=`vmrun getGuestIPAddress $vmpath`
    ssh -t -p $vmport $ip "cd \$HOME/shared; exec \$SHELL -l"
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
                    vm_${vmtype}_${subcommand} $@
                else
                    echo "Invalid vmtype, valids are ':$_valid_vmtypes'"
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
    echo "    mount    Mount the shared folder"
    echo "    umount   Umount the shared folder"
    echo "    ip       Get VM ip"
    echo "    stop     Stops the vm"
    echo "    ssh      SSH shell to the vm"
    echo ""
}

if [ ! -z $1 ]; then
    vm $@
fi
