#!/bin/bash

vm_path="$HOME/.dotfiles/scripts/vm"

prog_name="vm"
os=`uname -s`

_valid_commands="start stop ssh mount umount ip"
_valid_vmtypes="vmware qemu virtualbox"

ip=""

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

vm_general_mount() {
    echo "Mounting vm $vmname"
    ssh -t fr0zn@$ip -p $vmport "mkdir -p \$HOME/shared"
    mkdir -p /Volumes/VMNet/SHARED/$vmname 2>/dev/null
    if [ "$os" = "Darwin" ]; then
        sudo sshfs -o allow_other,defer_permissions -p $vmport fr0zn@$ip:/home/fr0zn/shared /Volumes/VMNet/SHARED/$vmname
    else
        sudo sshfs -o allow_other -p $vmport fr0zn@$ip:/home/fr0zn/shared /Volumes/VMNet/SHARED/$vmname
    fi
}

vm_general_umount() {
    echo "Umounting vm $vmname"
    sudo umount /Volumes/VMNet/SHARED/$vmname
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
    pkill qemu-system-aar
}

vm_qemu_mount (){
    ip="localhost"
    vm_general_mount
}

vm_qemu_umount (){
    vm_general_umount
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
    ip=`vmrun getGuestIPAddress $vmpath`
    vm_general_mount
}

vm_vmware_ip() {
    ip=`vmrun getGuestIPAddress $vmpath`
    echo "$ip"
}

vm_vmware_umount (){
    vm_general_umount
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
