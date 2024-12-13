#!/bin/bash

DEST_IP="192.168.0.100"
SRC_IP="192.168.0.50"
HTTP_PORT=80
DNS_PORT=53
SSH_PORT=22

IFACE="eth0"

log_message() {
    echo "[TEST] $1"
}

#test 1 continuous ping to destination ip
log_message "starting ping to $DEST_IP (be blocked as destination IP)"
while true; do
    ping -c 1 $DEST_IP >/dev/null 2>&1
    sleep 1
done &

#test 2 curl to destination ip http server
log_message "sending http requests to $DEST_IP:$HTTP_PORT (be blocked as incoming)"
while true; do
    curl -m 1 http://$DEST_IP:$HTTP_PORT >/dev/null 2>&1
    sleep 1
done &

#test 3 iperf traffic to and from destination ip
log_message "starting iperf traffic to and from $DEST_IP (various protocols and ports)"
iperf3 -s -p $HTTP_PORT -B $DEST_IP >/dev/null 2>&1 &
sleep 2

while true; do
    iperf3 -c $DEST_IP -p $HTTP_PORT >/dev/null 2>&1
    sleep 1
    iperf3 -u -c $DEST_IP -p $DNS_PORT >/dev/null 2>&1
    sleep 1
done &

#test 4 ssh to destination ip
log_message "Testing SSH traffic to $DEST_IP:$SSH_PORT (be blocked for both directions)"
while true; do
    ssh -o ConnectTimeout=1 $DEST_IP >/dev/null 2>&1
    sleep 1
done &

#test 5 traffic with source ip spoofing, priv needed
log_message "Sending traffic spoofed as SRC_IP $SRC_IP (blocked as source IP)..."
while true; do
    hping3 -S -a $SRC_IP -p $HTTP_PORT $DEST_IP >/dev/null 2>&1
    sleep 1
done &

log_message "traffic generator has started"
