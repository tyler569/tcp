sudo ip tuntap add tun0 mode tun user tyler
sudo ip addr add 10.0.0.1/24 dev tun0
sudo ip link set tun0 up
