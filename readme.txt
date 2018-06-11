# npi (Nim Packet Inspector)

This is an experimental project to intercept and expose packets into user space through netfliter and Nim language. it uses raw socket to resend the packets to the destination and also can alert the headers or payload if needed for example send back fake ACK or different tcp window size in similar fashion to most tcp accelerators.

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

# to test used a simple setup up PC1 as packet source and PC1 as tpi as gateway 
    _________                    ________________
   |         |                   |               | 
   |   PC1   | ------------>     |eth1  PC2 eth2 | ----> actual internet gw
   |_________|                   |_______________|
                                        npi
   default gw  is PC2


 
usage:
npi <queuenum> <ifindex> <out mac> <gw mac> <ipaddr> <len>
./npi 1 1  "08:00:28:f7:ce:83" "e2:f5:a9:6c:8b:41" "192.168.0.2" 1024

to observe the traffic:
sudo tcpdump -i lo -p tcp -v -x -n -e -s 64
    