fullpath="$(cd "$(dirname "$1")"; pwd)/$(basename "$1")"
if [[ ${fullpath} = *"fr0zn"* ]]
then
    string=${fullpath}
    prefix="/Users/fr0zn"
    foo=${string#$prefix}
    foo=${foo%$suffix}
    ssh u64 -t "bash -ic \"cd /mnt/host_home/${foo};bash\""
else
    ssh u64 -t "bash -i"
fi
