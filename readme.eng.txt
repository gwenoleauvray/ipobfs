This project is intended to fight DPI protocol analysis and bypass protocol blocking.

One of the possible ways to overcome DPI signature analysis is to modify the protocol.
The fastest but not the easiest way is to modify the software itself.
For TCP, obfsproxy exists. However, in the case of VPN - only not very fast solutions (openvpn) work over TCP.

What to do in case of udp?
If both endpoints are on a external IP, then its possible to modify packets on IP level.
For example, if you have a VPS, and you have an openwrt router at home and external IP from ISP,
then you can use this technique. If one endpoint is behind NAT, then ablities are limited,
but its still possible to tamper with udp/tcp headers and data payload.

The scheme is as follows:
 peer 1 <=> IP obfuscator/deobfuscator <=> network <=> IP obfuscator/deobfuscator <=> peer 2

In order for a packet to be delivered from peer 1 to peer 2, both having external IPs,
it is enough to have correct IP headers. You can set any protocol number, obfuscate or encrypt IP payload,
including tcp / udp headers. DPI will not understand what it is dealing with.
It will see non-standard IP protocols with unknown content.

ipobfs
------

NFQUEUE queue handler, IP obfuscator/deobfuscator.

 --qnum=<nfqueue_number>
 --daemon                       ; daemonize
 --pidfile=<filename>           ; write pid to file
 --user=<username>              ; drop root privs
 --debug                        ; print debug info
 --uid=uid[:gid]                ; drop root privs
 --ipproto-xor=0..255|0x00-0xFF ; xor protocol ID with given value
 --data-xor=0xDEADBEAF          ; xor IP payload (after IP header) with 32-bit HEX value
 --data-xor-offset=<position>   ; start xoring at specified position after IP header end
 --data-xor-len=<bytes>         ; xor block max length. xor entire packet after offset if not specified
 --csum=none|fix|valid          ; transport header checksum : none = dont touch, fix = ignore checksum on incoming packets, valid = always make checksum valid

The XOR operation is symmetric, therefore the same parameters are set for the obfuscator and deobfuscator.
On each side, one instance of the program is launched.

Filtering outgoing packets is easy because they go open, however, some u32 is required for incoming.
The protocol number ("-p") in the filter is the result of the xor of the original protocol with ipproto-xor.

server ipv4 udp:16 :
iptables -t mangle -I PREROUTING -i eth0 -p 145 -m u32 --u32 "0>>22&0x3C@0&0xFFFF=16" -j NFQUEUE --queue-num 300 --queue-bypass
iptables -t mangle -I POSTROUTING -o eth0 -p udp --sport 16  -j NFQUEUE --queue-num 300 --queue-bypass

client ipv4 udp:16 :
iptables -t mangle -I PREROUTING -i eth0 -p 145 -m u32 --u32 "0>>22&0x3C@0>>16&0xFFFF=16" -j NFQUEUE --queue-num 300 --queue-bypass
iptables -t mangle -I POSTROUTING -o eth0 -p udp --dport 16  -j NFQUEUE --queue-num 300 --queue-bypass

ipobfs --qnum=300 --ipproto-xor=128 --data-xor=0x458A2ECD --data-xor-offset=4 --data-xor-len=44

Why data-xor-offset = 4: tcp and udp protocol headers start with source and destination port numbers, 2 bytes each.
To make it easier to write u32 do not touch the port numbers. You can touch, but then you have to figure out into what
numbers original ports will be transformed and write those values to u32.
Why data-xor-len = 44: an example is given for wireguard. 44 bytes is enough to XOR the udp header and all wireguard headers.
Next come the encrypted wireguard data, it makes no sense to XOR it.

You can even turn udp into "tcp trash" with ipproto-xor = 23. According to the ip header, this is tcp, but in place of the tcp header is garbage.
On the one hand, such packets can go through middle-boxes, and conntrack can go crazy.
On the other hand, it may even be good.

There are nuances with ipv6. In ipv6 there is no concept of a protocol number. But there is the concept of "next header".
As in ipv4, you can write anything there. But in practice, this can cause ICMPv6 Type 4 - Parameter Problem messages.
To avoid this, you can cast the protocol to the value 59. It means "no Next Header".
To get "ipproto-xor" parameter, XOR original protocol number with 59.

udp : ipproto-xor=17^59=42
tcp : ipproto-xor=6^59=61

server ipv6 tcp:12345 :
ip6tables -t mangle -I PREROUTING -i eth0 -p 59 -m u32 --u32 "40&0xFFFF=12345" -j NFQUEUE --queue-num 300 --queue-bypass
ip6tables -t mangle -I POSTROUTING -o eth0 -p tcp --sport 12345 -j NFQUEUE --queue-num 300 --queue-bypass

client ipv6 tcp:12345 :
ip6tables -t mangle -I PREROUTING -i eth0 -p 59 -m u32 --u32 "38&0xFFFF=12345" -j NFQUEUE --queue-num 300 --queue-bypass
ip6tables -t mangle -I POSTROUTING -o eth0 -p tcp --dport 12345 -j NFQUEUE --queue-num 300 --queue-bypass

ipobfs --qnum=300 --ipproto-xor=61 --data-xor=0x458A2ECD --data-xor-offset=4


CHECKSUMS :
Work with checksums begins when a tcp/udp packet is received or sent (before obfuscation / deobfuscation).
If a packet with an ip protocol other than tcp or udp is received, nothing is done with the checksum, even if after
deobfuscation packet turns into tcp or udp.
It is assumed that if the packet is transmitted over the network with the modified ip protocol,
then no one will look for tcp or udp header in it to fix the checksum.
--csum=none - do not touch checksums at all. if after deobfuscation checksum is invalid, the system will discard the packet.
--csum=fix - checksum ignore mode. its not possible to disable checking of checksum inside NFQUEUE.
Instead, on incoming packets checksum is recomputed and replaced, so the system will accept the packet.
--csum=valid - bring the checksum to a valid state for all packets - incoming and outgoing. mode is useful when working through cgnat
Recomputing checksum increases cpu usage.
See also section "NAT break".


DISADVANTAGE :
Each packet will be thrown into nfqueue, therefore the speed will decrease significantly. 2-3 times.
If you compare wireguard + ipobfs with openvpn on a soho router, then openvpn will still be slower.


ipobfs_mod
-----------

The same as ipobfs, but implemented as a linux kernel module. It gives a performance drop of only 20%.
It duplicates ipobfs logic and is compatible with it.
Its possible to use ipobfs on peer1 and ipobfs_mod on peer2, they will work together.
The iptables commands are the same, but instead of "-j NFQEUEUE" use "-j MARK --set-xmark".
ipobfs_mod performs packet processing based on fwmark bits.

Settings are passed through the kernel module parameters specified in the insmod command.

server ipv4 udp:16 :
iptables -t mangle -I PREROUTING -i eth0 -p 145 -m u32 --u32 "0>>22&0x3C@0&0xFFFF=16" -j MARK --set-xmark 0x100/0x100
iptables -t mangle -I POSTROUTING -o eth0 -p udp --sport 16 -j MARK --set-xmark 0x100/0x100

client ipv4 udp:16 :
iptables -t mangle -I PREROUTING -i eth0 -p 145 -m u32 --u32 "0>>22&0x3C@0>>16&0xFFFF=16" -j MARK --set-xmark 0x100/0x100
iptables -t mangle -I POSTROUTING -o eth0 -p udp --dport 16 -j MARK --set-xmark 0x100/0x100

rmmod ipobfs
insmod /lib/modules/`uname -r`/extra/ipobfs.ko  mark=0x100 ipp_xor=128 data_xor=0x458A2ECD data_xor_offset=4 data_xor_len=44

The module supports up to 32 profiles. Parameter settings for each profile are separated by commas.
For example, the following command combines the functions of 2 NFQUEUE handlers from the previous examples:
insmod /lib/modules/`uname -r`/extra/ipobfs.ko  mark=0x100,0x200 ipp_xor=128,61 data_xor=0x458A2ECD,0x458A2ECD data_xor_offset=4,4 data_xor_len=44,0
It is possible to use different profiles for outgoing and incoming packets.
This will confuse DPI even more by reducing the correlation of in/out streams.
If parameter 'markmask' is set, profile with mask/markmask wins, otherwise mask/mask is searched.
Use markmask if profiles are numerous to not waste single bit for each one.
For example : 0x00/0xf0, 0x10/0xf0, ..., 0x0f/0x0f

By default, the module sets a hook on incoming packets with priority mangle+1, so that the table mangle was already processed
by the time of the call. If non-standard IP protocols arrive at the input, everything is OK. But if there are packets with 
the transport protocol that support checksumming, such as tcp or udp, then modified packets with invalid checksum
will not reach the mangle+1 hook. The module will not receive them.
To solve this problem, specify the pre = raw parameter and do : iptables -t raw -I PREROUTING ...
Outgoing packets can be processed in the usual manner through mangle.

The module disables OS-level checksum checking and computing for all processed packets, in some cases
recomputing tcp and udp checksums independently.
If the parameter csum=none, module does not compute checksum at all, allowing sending packets with invalid checksum
before obfuscation. Deobfuscated packets can contain invalid checksum.
If csum=fix, the module takes over the recalculation of the checksum on outgoing packets before the payload is modified,
thereby repeating the functions of the OS or hardware offload. Otherwise OS or hw offload would spoil 2 bytes of data
and after deobfuscation packet would contain incorrect checksum.
If csum=valid, the recalculation of the checksum is done after modifying the payload for both outgoing and incoming packets.
This ensures the visibility of the transmission of packets with a valid checksum.
Checksum correction on the incoming packet is necessary if the device with ipobfs is not the receiver,
but performs the function of a router (forward). So that there is a valid packet on the output interface.
The regular recipient will not accept packets with incorrect checksum.

The debug = 1 parameter enables debugging output. You will see what is done with each processed packet in dmesg.
It should be used only for debugging. With a large number of packets, the system will slow down significantly
due to excessive output in dmesg.

You can view and change ipobfs parameters without reloading the module : /sys/module/ipobfs/parameters

COMPILING MODULE on traditional linux system :
At first install kernel headers. for debian :
sudo apt-get install linux-headers.....
cd ipobfs_mod
make
sudo make install

SPEED NOTICE
If only ipproto-xor is specified, slowdown is very close to zero.
With data-xor its preferred not to xor offsets after 100-140 bytes.
This way you can avoid linearizing skb's and save lots of cpu time.
debug=1 option can show whether linearizing happens.

openwrt
-------

On a x64 linux system, download and unzip the SDK from your firmware version for your device.
The SDK version must exactly match the firmware version, otherwise you will not build a suitable kernel module.
If you built the firmware yourself, instead of the SDK, you can and should use that buildroot.
scripts/feeds update -a
scripts/feeds install -a
Copy openwrt/* to SDK folder, preserving directory structure.
Copy ipobfs и ipobfs_mod (source code) to packages/ipobfs (the one there openwrt Makefile is).
From SDK root run : make package/ipobfs/compile V=99
Look for 2 ipk : bin/packages/..../ipobfs..ipk и bin/targets/..../kmod-ipobfs..ipk
Copy selected version to the device, install via "opkg install ...ipk".
If reinstalling, first "opkg remove ipobfs" / "opkg remove kmod-ipobfs".

NAT break
------------

In the general case, its safe to assume that NAT can only pass tcp and udp traffic.
Some NATs also contain helpers for special protocols (GRE). But not all NATs and not on all devices.
Therefore, ipproto-xor cannot be used.

Consider linux-based NAT (almost all home routers) without helpers.
As the study shows, transport header fields containing payload length and flags are important.
Therefore, the minimum xor-data-offset for tcp is 14, for udp it is 6. Otherwise, the packet will not pass NAT at all.
Linux NAT does not check the checksum in the transport header, tcp options are not analyzed.
Any NAT will definitely follow the tcp flags, because conntrack determines the start of the connection.
Conntrack is vital part of any NAT. Flags field offset in tcp header is 13.

Without exception, all NATs will correct the 2-byte checksum in tcp (offset 18) and udp (offset 6) header,
since it is computed using ip source and destination. NAT changes the source ip when sending, source port
can also change. To save resources, a full checksum recalculation is usually not performed.
The initial checksum is taken as a basis, the difference between the initial and changed values​is added to it.
The recipient receives a packet with an invalid checksum, then packet is deobfuscated by ipobfs and checksum becomes
valid again, but only if the initial checksum was not changed during obfuscation, that is,
data-xor-offset> = 20 for tcp and data-xor-offset> = 8 for udp.
The obfuscator XORs, checksum is additive, so they are incompatible.
ipobfs by default does not recalculate the checksums of transport headers, so if it is used at the receiving end, then
data-xor-offset must not cover checksum field, otherwise the packet will be discarded by the system after deobfuscation
As an alternative use --csum=fix option.
ipobfs_mod disables checking of checksums, so there is no such problem when using it. default behavior is similar to --csum=fix

Many routers perform mss fix (-j TCPMSS --clamp-mss-to-pmtu or -j TCPMSS --set-mss).
mss is in the tcp header options. Windows and linux send mss as the first option. The option itself takes 4 bytes.
It turns out that the minimum xor-data-offset for tcp rises to 24, because bytes 22-23 can be changed by router.

SUMMARY :
 tcp : data-xor-offset>=24
 udp : data-xor-offset>=8

Not all NATs will pass invalid packets. Tests on some ISPs behind NAT show that packets with invalid
checksum do not reach the target at all. Some routers do hardware NAT offloading. Whether invalid packets
can pass through such devices is still not tested.
But even if not, then hardware NAT can usually be disabled in the firmware settings, thereby leaving regular linux NAT.

If NAT doesn’t pass packets with invalid checkыгь, use --csum=valid option.
In terms of cpu load, it would be preferable not to use the --csum=valid mode if NAT passes packets with invalid checksum.

There is information that some mobile operators terminate tcp on their servers for later proxying to the original
destination. In this case, any tcp modification not at the data flow level is doomed to failure.
A terminating middlebox will reject packets with a corrupted header or invalid checksum.
An outgoing connection from middlebox will not repeat the same packetization as the original connection.
Use obfsproxy.
