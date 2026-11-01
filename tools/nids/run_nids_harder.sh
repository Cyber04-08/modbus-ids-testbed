#!/bin/bash
# Run off-the-shelf Suricata and Zeek over the GRFICSv2 harder-attack pcaps
# (data/grfics/harder/*.pcap, captured live on the plant) and count the alerts
# each raises. Run ON the ids-sensor VM as root, repo shared at /media/sf_ids.
#
# The harder attacks are all protocol-valid Modbus writes (right function code,
# in-range values, valid register) from the wrong sender, or replays with fresh
# transaction IDs. Stock signature/anomaly IDS has nothing malformed to fire
# on; this script measures exactly that. The project Suricata rules
# (tools/nids/modbus_project.rules) were written for the Python testbed's
# register map and are included to show what a stock-style rule catches here.
#
#   sudo bash tools/nids/run_nids_harder.sh
set -u
REPO=${REPO:-/media/sf_ids}
IN=$REPO/data/grfics/harder
OUT=$IN/nids
ZEEK=/opt/zeek/bin/zeek
SUR_SET="--set app-layer.protocols.modbus.enabled=yes --set app-layer.protocols.modbus.detection-enabled=yes"
WORK=/tmp/nids_harder
STOCK=$WORK/stock.rules
mkdir -p "$OUT" "$WORK"
rm -rf "$OUT"/*

if [ ! -s /var/lib/suricata/rules/suricata.rules ]; then
    echo "missing ET Open rules: run 'sudo suricata-update' first" >&2; exit 1
fi
cat /var/lib/suricata/rules/suricata.rules \
    /etc/suricata/rules/modbus-events.rules 2>/dev/null \
    | grep -v '^#' | grep -v '^$' > "$STOCK"

printf '%-12s %14s %16s %12s\n' session suricata-stock suricata-project zeek-stock
for pcap in "$IN"/*.pcap; do
    s=$(basename "$pcap" .pcap)
    for cfg in suricata-stock suricata-project zeek-stock; do
        d=$OUT/$cfg/$s; mkdir -p "$d"
        case $cfg in
            suricata-stock)
                suricata -r "$pcap" -l "$d" -k none $SUR_SET -S "$STOCK" >/dev/null 2>&1 ;;
            suricata-project)
                suricata -r "$pcap" -l "$d" -k none $SUR_SET \
                    -S "$REPO/tools/nids/modbus_project.rules" >/dev/null 2>&1 ;;
            zeek-stock)
                (cd "$d" && $ZEEK -C -r "$pcap" >/dev/null 2>&1) ;;
        esac
    done
    printf '%-12s %14s %16s %12s\n' "$s" \
        "$(grep -c '"event_type":"alert"' "$OUT/suricata-stock/$s/eve.json" 2>/dev/null || echo 0)" \
        "$(grep -c '"event_type":"alert"' "$OUT/suricata-project/$s/eve.json" 2>/dev/null || echo 0)" \
        "$(grep -vc '^#' "$OUT/zeek-stock/$s/modbus.log" 2>/dev/null || echo 0)"
done
echo
echo "(suricata alerts = eve.json alert events; zeek-stock = modbus.log request lines,"
echo " i.e. traffic parsed, not alerts - stock Zeek has no Modbus notice for valid writes)"
