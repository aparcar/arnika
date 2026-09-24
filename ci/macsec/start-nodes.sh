#!/bin/bash
# Starts arnika in both namespaces: node-a and node-b, which negotiate the PRIMARY role per interval.
set -e

# Shared secret authenticating the UDP key_id exchange between the peers.
ARNIKA_PSK="mJNYzLNLRCl9jRRkP/Qsa74v4bem4BC+KbqQz+Ft9lQ="

ARNIKA="$(pwd)/build/arnika"
SCI_A=$(cat /tmp/macsec-test/sci-a)
SCI_B=$(cat /tmp/macsec-test/sci-b)

# Start node-a — receives from node-b, so RX SCI = node-b's SCI
ip netns exec ns-a env \
    LISTEN_ADDRESS=10.0.0.1:9998 \
    ARNIKA_ID=9998 \
    SERVER_ADDRESS=10.0.0.2:9998 \
    INTERVAL=5s \
    ARNIKA_PSK="$ARNIKA_PSK" \
    KMS_URL="http://192.168.100.1:8080/api/v1/keys/CONSB" \
    MACSEC_INTERFACE=macsec0 \
    MACSEC_RX_SCI="$SCI_B" \
    "$ARNIKA" &> /tmp/macsec-test/node-a/arnika.log &
echo $! > /tmp/macsec-test/node-a/arnika.pid
echo "Started arnika node-a pid=$(cat /tmp/macsec-test/node-a/arnika.pid)"

# Start node-b — receives from node-a, so RX SCI = node-a's SCI
ip netns exec ns-b env \
    LISTEN_ADDRESS=10.0.0.2:9998 \
    ARNIKA_ID=9999 \
    SERVER_ADDRESS=10.0.0.1:9998 \
    INTERVAL=5s \
    ARNIKA_PSK="$ARNIKA_PSK" \
    KMS_URL="http://192.168.101.1:8080/api/v1/keys/CONSB" \
    MACSEC_INTERFACE=macsec0 \
    MACSEC_RX_SCI="$SCI_A" \
    "$ARNIKA" &> /tmp/macsec-test/node-b/arnika.log &
echo $! > /tmp/macsec-test/node-b/arnika.pid
echo "Started arnika node-b pid=$(cat /tmp/macsec-test/node-b/arnika.pid)"
