#!/usr/bin/env python3
import os
import sys

from scapy.all import *

TYPE_MYTUNNEL = 0x1212
TYPE_IPV4 = 0x0800

class MyTunnel(Packet):
    name = "MyTunnel"
    fields_desc = [
        ShortField("pid", 0),
        ShortField("dst_id", 0)
    ]
    def mysummary(self):
        return self.sprintf("pid=%pid%, dst_id=%dst_id%")

class Vector(Packet):
   fields_desc = [
       BitField("bos", 0, 1),
       BitField("val", 0, 31)
    ]

bind_layers(Ether, MyTunnel, type=TYPE_MYTUNNEL)
bind_layers(MyTunnel, Vector, pid=0x1234)
bind_layers(Vector, Vector, bos=0)
bind_layers(Vector, IP, bos=1)


def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" or "lo" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def handle_pkt(pkt):
    if MyTunnel in pkt or (TCP in pkt and pkt[TCP].dport == 1234):
        print("got a packet")
        pkt.show2()
#        hexdump(pkt)
#        print "len(pkt) = ", len(pkt)
        sys.stdout.flush()


def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = ifaces[0]
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
