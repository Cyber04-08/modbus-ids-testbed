#!/bin/sh
# Set up the monitoring-sensor VM ("ids-sensor": a fresh Kali 2026.2 import,
# separate from any other VM) with the two off-the-shelf network IDS tools
# compared against our detectors:
#   * Suricata 8 - signature-based IDS, from the Kali/Debian repository
#   * Zeek 9     - scriptable network monitor, from the Zeek project's own
#                  repository (Kali's own zeek package, 5.1.1, is built for an
#                  older C library and cannot be installed on Kali 2026.2)
#   * tshark     - command-line Wireshark, to inspect the pcap files
#
# Run inside the VM as a sudo-capable user:  sudo sh tools/setup_sensor.sh
set -e

hostnamectl set-hostname ids-sensor 2>/dev/null || true
grep -q ids-sensor /etc/hosts || echo "127.0.1.1 ids-sensor" >> /etc/hosts

curl -fsSL https://download.opensuse.org/repositories/security:zeek/Debian_Testing/Release.key \
    | gpg --dearmor > /etc/apt/trusted.gpg.d/security_zeek.gpg
echo "deb http://download.opensuse.org/repositories/security:/zeek/Debian_Testing/ /" \
    > /etc/apt/sources.list.d/zeek.list
chmod 644 /etc/apt/trusted.gpg.d/security_zeek.gpg /etc/apt/sources.list.d/zeek.list

apt-get update -q
DEBIAN_FRONTEND=noninteractive apt-get install -y -q suricata zeek tshark

# Free Emerging Threats Open ruleset -> /var/lib/suricata/rules/suricata.rules
suricata-update -q --no-test

/opt/zeek/bin/zeek --version
suricata -V
tshark --version | head -1
