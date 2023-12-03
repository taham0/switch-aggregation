#!/usr/bin/env python3
import argparse
import random
import socket

from scapy.all import *

TYPE_MYTUNNEL = 0x1212
TYPE_IPV4 = 0x0800

class MyTunnel(Packet):
    name = "MyTunnel"
    fields_desc = [
        ShortField("pid", 0),
        ShortField("dst_id", 0),
        LongField("count", 0)
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
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('ip_addr', type=str, help="The destination IP address to use")
    parser.add_argument('message', type=str, help="The message to include in packet")
    parser.add_argument('--dst_id', type=int, default=None, help='The myTunnel dst_id to use, if unspecified then myTunnel header will not be included in packet')
    args = parser.parse_args()

    addr = socket.gethostbyname(args.ip_addr)
    dst_id = args.dst_id
    iface = get_if()

    vector = list(range(4))

    addr_table = {
        1: "08:00:00:00:01:11",
        2: "08:00:00:00:02:22",
        3: "08:00:00:00:03:33"
    }

    if (dst_id is not None):
        print("sending on interface {} to dst_id {}".format(iface, str(dst_id)))
        pkt =  Ether(src=get_if_hwaddr(iface), dst=addr_table[dst_id])
        pkt = pkt / MyTunnel(dst_id=dst_id)

        i = 0
        for p in vector:
            try:
                pkt = pkt / Vector(bos=0, val=p)
                i = i+1
            except ValueError:
                pass
        if pkt.haslayer(Vector):
            pkt.getlayer(Vector, i).bos = 1
    
    pkt = pkt / IP(dst=addr)

    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
