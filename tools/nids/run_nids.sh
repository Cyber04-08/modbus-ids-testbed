#!/bin/bash
# Run the off-the-shelf network IDS tools over every exported session
# (data/pcap/*.pcap, made by tools/export_pcap.py) on the ids-sensor VM.
#
# Four configurations per pcap:
#   suricata-stock   - Suricata with the free Emerging Threats Open ruleset
#                      plus Suricata's own Modbus protocol-anomaly rules
#                      (modbus-events.rules); no project-specific rules
#   suricata-project - Suricata with only tools/nids/modbus_project.rules
#   zeek-stock       - Zeek's default scripts (logs Modbus traffic; any
#                      notice/weird entries count as alerts)
#   zeek-project     - Zeek + tools/nids/modbus_project.zeek
# Suricata's Modbus parser is off in its default config; it is switched on
# for both Suricata runs (a plant monitoring Modbus would enable it).
#
# Output: data/nids/<config>/<session>/ (tool logs) and
#         data/nids/timing.csv (wall-clock seconds per tool run).
#
# Usage (inside the VM, repo shared at /media/sf_ids):
#   bash /media/sf_ids/tools/nids/run_nids.sh
set -u
REPO=${REPO:-/media/sf_ids}
OUT=$REPO/data/nids
WORK=/tmp/nids_work
ZEEK=/opt/zeek/bin/zeek
STOCK_RULES=$WORK/stock.rules
SUR_SET="--set app-layer.protocols.modbus.enabled=yes --set app-layer.protocols.modbus.detection-enabled=yes"

mkdir -p "$OUT" "$WORK"
rm -rf "$OUT"/suricata-* "$OUT"/zeek-*

# Stock ruleset: ET Open (fetched by suricata-update) + Modbus anomaly rules.
if [ ! -s /var/lib/suricata/rules/suricata.rules ]; then
    echo "missing ET Open rules: run 'sudo suricata-update' first" >&2
    exit 1
fi
cat /var/lib/suricata/rules/suricata.rules \
    /etc/suricata/rules/modbus-events.rules 2>/dev/null \
    | grep -v '^#' | grep -v '^$' > "$STOCK_RULES"
echo "stock ruleset: $(wc -l < "$STOCK_RULES") rules"

echo "config,session,seconds" > "$OUT/timing.csv"
for pcap in "$REPO"/data/pcap/*.pcap; do
    s=$(basename "$pcap" .pcap)
    for cfg in suricata-stock suricata-project zeek-stock zeek-project; do
        d=$OUT/$cfg/$s
        mkdir -p "$d"
        t0=$(date +%s%N)
        case $cfg in
            suricata-stock)
                suricata -r "$pcap" -l "$d" -k none $SUR_SET -S "$STOCK_RULES" >/dev/null 2>&1 ;;
            suricata-project)
                suricata -r "$pcap" -l "$d" -k none $SUR_SET \
                    -S "$REPO/tools/nids/modbus_project.rules" >/dev/null 2>&1 ;;
            zeek-stock)
                (cd "$d" && $ZEEK -C -r "$pcap" >/dev/null 2>&1) ;;
            zeek-project)
                (cd "$d" && $ZEEK -C -r "$pcap" "$REPO/tools/nids/modbus_project.zeek" >/dev/null 2>&1) ;;
        esac
        t1=$(date +%s%N)
        echo "$cfg,$s,$(awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.3f", (b - a) / 1e9 }')" >> "$OUT/timing.csv"
    done
    printf '%-20s suricata-stock alerts=%s  suricata-project alerts=%s  zeek-project alerts=%s  zeek modbus.log lines=%s\n' "$s" \
        "$(grep -c '"event_type":"alert"' "$OUT/suricata-stock/$s/eve.json" 2>/dev/null)" \
        "$(grep -c '"event_type":"alert"' "$OUT/suricata-project/$s/eve.json" 2>/dev/null)" \
        "$(grep -vc '^#' "$OUT/zeek-project/$s/modbus_project.log" 2>/dev/null)" \
        "$(grep -vc '^#' "$OUT/zeek-stock/$s/modbus.log" 2>/dev/null)"
done
