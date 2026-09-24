#!/bin/bash
# Verifies that arnika successfully injected matching SAKs into MACsec interfaces.
set -e

echo "====== MACsec Integration Test - Verification ======"

echo "Waiting for key exchange (30 seconds)..."
sleep 30

# Dump MACsec state from both namespaces
ip netns exec ns-a ip macsec show > /tmp/macsec-test/macsec-a.txt 2>&1
ip netns exec ns-b ip macsec show > /tmp/macsec-test/macsec-b.txt 2>&1

echo ""
echo "====== MACsec State (ns-a) ======"
cat /tmp/macsec-test/macsec-a.txt

echo ""
echo "====== MACsec State (ns-b) ======"
cat /tmp/macsec-test/macsec-b.txt

echo ""
echo "====== Verification Results ======"

# Key ID of the SA a node currently transmits with: the TXSC line names the
# encoding SA ("TXSC: <sci> on SA <n>"), its SA line carries the key ID.
tx_keyid() {
    awk '
        /TXSC:/ { for (i = 1; i <= NF; i++) if ($i == "SA") enc = $(i + 1); tx = 1; next }
        /RXSC:/ { tx = 0 }
        tx && $1 == enc ":" { for (i = 1; i <= NF; i++) if ($i == "key") print $(i + 1) }
    ' "$1"
}

KEY_A="$(tx_keyid /tmp/macsec-test/macsec-a.txt)"
KEY_B="$(tx_keyid /tmp/macsec-test/macsec-b.txt)"
for node in a b; do
    key_var="KEY_${node^^}"
    if [ -z "${!key_var}" ]; then
        echo "FAILED: node-$node has no TX SA at its encoding SA"
        cat "/tmp/macsec-test/node-$node/arnika.log" || true
        exit 1
    fi
    echo "OK: node-$node transmits with key ID ${!key_var}"
    if ! grep -q "RXSC:" "/tmp/macsec-test/macsec-$node.txt"; then
        echo "FAILED: node-$node has no RX SC configured"
        exit 1
    fi
    echo "OK: node-$node has an RX SC"
done

if [ "$KEY_A" != "$KEY_B" ]; then
    echo "FAILED: the nodes transmit with different keys ($KEY_A vs $KEY_B)"
    exit 1
fi
echo "OK: both nodes transmit with the same key"

echo ""
echo "====== Tunnel Connectivity ======"
if ! ip netns exec ns-a ping -c 3 -W 2 172.16.0.2 > /dev/null 2>&1; then
    echo "FAILED: node-a cannot ping node-b through the MACsec tunnel"
    exit 1
fi
echo "OK: node-a can ping node-b through the MACsec tunnel"

echo ""
echo "SUCCESS: MACsec keys installed and in use on both nodes"
exit 0
