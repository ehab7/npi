# npi (Nim Packet Inspector)

This is an experimental project to expose packets into user space through netfliter and using Nim language. also it uses raw socket to resend the packet which may also alert the headers or payload for example send fake ACK and different tcp window size in response to tcp PSH similar to most tcp accelerators.

# To compile:
nim c --threads:on --L:/PathTo/libnetfilter_queue.so -L:/PathTo/customchecksum.so --cincludes:./ tdpi.nim

# To find out the interface index:
cat /sys/class/net/xxx/ifindex

# To build customchecksum:
gcc -c -Wall -Werror -fpic customchecksum.c
gcc -shared -o customchecksum.so customchecksum.o

# to add netfliter queue on certain tcp packets: 
iptables -t raw -I PREROUTING -p tcp -d x.x.x.x -j NFQUEUE - queue-num y 
iptables -t raw -I PREROUTING -p tcp -s x.x.x.x -j NFQUEUE - queue-num y
it depends on usage and configuration, the above using raw table to queue packet before hit nat for masquerade 

# simple setup up using pc1 as packet source and pc2 as tpi as gateway 
    _________                    ________________
   |         |                   |               | 
   |   PC1   | ------------>     |eth1  PC2 eth2 | ----> actual internet gw
   |_________|                   |_______________|
                                        npi
   default gw  is PC2


 
usage npi <queuenum> <ifindex> <out mac> <gw mac> <ipaddr> <len>
./npi 1 1  "08:00:28:f7:ce:83" "e2:f5:a9:cc:8b:41" "192.168.0.2" 1024
# the ipaddr and len just to distinguish between local and remote packet 
 
sudo tcpdump -i lo -p tcp -v -x -n -e -s 64
03:45:35.236345 08:00:28:f7:ce:83 > e2:f5:a9:cc:8b:41, ethertype IPv4 (0x0800), length 54: (tos 0x0, ttl 4, id 0, offset 0, flags [none], proto TCP (6), length 40)
    192.168.0.2.46906 > 173.194.203.103.443: Flags [.], cksum 0xfde3 (correct), ack 2742262603, win 100, length 0
    0x0000:  4500 0028 0000 0000 0406 7cfc c0a8 0002
    0x0010:  adc2 cb67 b73a 01bb ca8b a134 1c9b 3667
    0x0020:  5010 0064 fde3 0000
    