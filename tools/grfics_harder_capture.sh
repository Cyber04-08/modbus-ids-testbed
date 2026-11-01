#!/bin/bash
# Capture harder-attack sessions on the GRFICSv2 plant (run ON the ids-sensor VM,
# repo shared at /media/sf_ids). One independent tcpdump window per session; each
# waits for the capture to finish before the next attack (overlapping windows
# merged runs in the first GRFICS experiment).
#
#   sudo bash tools/grfics_harder_capture.sh val          # 3 min normal-only validation
#   sudo bash tools/grfics_harder_capture.sh attacks 10   # 10 attack sessions
#   sudo bash tools/grfics_harder_capture.sh attacks 10 paced
set -u
REPO=${REPO:-/media/sf_ids}
OUT=$REPO/data/grfics/harder
IFACE=${IFACE:-eth1}
TARGET=${TARGET:-192.168.95.11}
mkdir -p "$OUT"
ip addr show "$IFACE" | grep -q 192.168.95.50 || ip addr add 192.168.95.50/24 dev "$IFACE"

capture() {   # capture <name> <seconds-or-command...>
    local name=$1; shift
    tcpdump -i "$IFACE" -nn -s 0 -w "$OUT/$name.pcap" port 502 >/dev/null 2>&1 &
    local TPID=$!
    sleep 2
    "$@"
    sleep 2
    kill -INT $TPID
    wait $TPID 2>/dev/null
}

case ${1:-} in
    val)
        capture normal_val sleep 180 ;;
    attacks)
        n=${2:-10}
        mode=${3:-}            # "paced": replay copies the PLC's rhythm
        pre=attack
        [ "$mode" = paced ] && pre=paced
        for i in $(seq -f "%02g" 1 "$n"); do
            echo "session $i"
            capture "${pre}_$i" python3 "$REPO/tools/grfics_harder_attack.py" "$TARGET" \
                "$OUT/${pre}_$i.json" "$((1000 + 10#$i))" $mode
        done ;;
    *) echo "usage: $0 val | attacks N" >&2; exit 2 ;;
esac
