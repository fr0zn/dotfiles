
while true; do
    ranger_cd () {
        tempfile="$(mktemp -t tmp.XXXXXX)"
        ranger --choosedir="$tempfile" "${@:-$(pwd)}" "${@:-$(pwd)}"
        test -f "$tempfile" &&
        if [ "$(cat -- "$tempfile")" != "$(echo -n `pwd`)" ]; then
            cd -- "$(cat "$tempfile")"
        fi
        rm -f -- "$tempfile"
    }
    ranger_cd
done
