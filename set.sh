#!/bin/sh

sudo ip tuntap add mode tap user $USER name tap0
sudo ip addr add 192.0.2.1/24 dev tap0
sudo ip link set tap0 up

sudo bash -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
sudo iptables -A FORWARD -o tap0 -j ACCEPT
sudo iptables -A FORWARD -i tap0 -j ACCEPT
sudo iptables -t nat -A POSTROUTING -s 192.0.2.0/24 -o enp0s3 -j MASQUERADE

