#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
    printf 'Usage: %s AGENT BUSYBOX OUTPUT.cpio\n' "$0" >&2
    exit 2
fi

agent=$(realpath -- "$1")
busybox=$(realpath -- "$2")
output=$(realpath -m -- "$3")
if [[ -e $output ]]; then
    printf 'Refusing to overwrite existing initramfs: %s\n' "$output" >&2
    exit 1
fi
if [[ ! -x $agent || ! -x $busybox ]]; then
    printf 'Agent and BusyBox must be executable files\n' >&2
    exit 1
fi

staging=$(mktemp -d)
chmod 0755 "$staging"
trap 'rm -rf -- "$staging"' EXIT
install -D -m 0755 -- "$agent" "$staging/agent"
install -D -m 0755 -- "$busybox" "$staging/busybox"
mkdir -p -- "$staging/proc" "$staging/sys" "$staging/dev" "$staging/tmp/vf-work"

while IFS= read -r library; do
    [[ -z $library ]] && continue
    install -D -m 0755 -- "$library" "$staging/${library#/}"
done < <(ldd -- "$agent" | awk '/=> \// { print $3 } /^[[:space:]]*\// { print $1 }')

cat > "$staging/init" <<'EOF'
#!/busybox sh
set -eu
/busybox mount -t proc proc /proc
/busybox mount -t sysfs sysfs /sys
/busybox mount -t devtmpfs devtmpfs /dev
/busybox mount -t tmpfs -o mode=1777 tmpfs /tmp/vf-work
/busybox chmod 0600 /dev/hvc0
exec 3<> /dev/hvc0
/busybox stty raw -echo <&3
exec 0<&3 1>&3 3>&-
/busybox echo vf-agent-ready > /dev/console
exec /agent --workspace /tmp/vf-work --stdio 2> /dev/console
EOF
chmod 0755 "$staging/init"

(
    cd -- "$staging"
    export LC_ALL=C
    find . -print | sort | cpio --quiet -o -H newc --owner 0:0 > "$output"
)
printf 'Agent initramfs built at %s\n' "$output"
