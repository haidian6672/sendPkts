# send-tcp
Building TCP/IP packet from commandline using pcap.  
Usage: sudo ./send-tcp -i \<interface> -m \<dst-mac-address> -s \<src-ipv4-address>:\<port> -d \<dst-ipv4-address>:\<port> \[-f \<tcp-flag>] \[-q \<tcp-seq-num>] \[-v \<vlan-tag>]

# send-ip
Building TCP/IP packet from commandline using pcap.  
example: sendIP -i eth0 -m 00:11:22:33:44:55 -s 1.2.3.4 -d 5.6.7.8 -n 10000 -l 100 -r 3

# send-abc
Building ABC packet from commandline using pcap.  
example: sendABC -i eth0 -m 00:11:22:33:44:55 -s 11:22:33:44:55:66:77:88 -d 00:11:22:33:44:55:66:77 -n 10000 -l 100 -r 3

# send-abc-arp
Building ABC-ARP packet from commandline using pcap.  
example: sendABCARP -i eth0 -m 00:11:22:33:44:55 -s 11:22:33:44:55:66:77:88 -d 00:11:22:33:44:55:66:77 -n 10000 -l 100 -r 3 -p 1
