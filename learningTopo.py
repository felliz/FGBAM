__author__ = 'Fel1iZ'
import threading
import struct
from FGBAM import eth_addr
from collections import namedtuple
import socket


#neighbor = namedtuple('neighbor', ['in_port','connectedWith'])


class handle_packetIn(object):
    def __init__(self,packetIn):
        self.packetIn = packetIn
        self.buffer_id = None
        self.total_len = None
        self.in_port = None
        self.reason = None
        self.frame_data = None
        self.unpack()
        self.neighbor = None
        self.sender_mac_addr = None


    def analyse_packet(self):
        if len(self.frame_data) >=14 :
            ethernetII = self.frame_data[:14]
            ethernetII_unpack = struct.unpack('!6s6sH',ethernetII)

            dest_mac = eth_addr(ethernetII_unpack[0])
            src_mac = eth_addr(ethernetII_unpack[1])
            ethernet_type = ethernetII_unpack[2]
            #print dest_mac
            #print src_mac
            #print "ethernetType: " + str(ethernet_type)
            #print "type: " + str(int("0x88cc",16))

            if str(ethernet_type) == str(int("0x88cc",16)): # 0x88cc = Link Layer Discovery Protocol (LLDP)
                #print "LLDP"
                self.neighbor = src_mac
            elif str(ethernet_type) == str(int("0x0806",16)): # 0x0806 = Address Resolution Protocol (ARP)
                #print "ARP"
                arp = self.frame_data[14:42]
                arp_unpack = struct.unpack('!HHBBH6s4s6s4s',arp)

                HW_type = arp_unpack[0]
                protocol_type = arp_unpack[1]
                HW_size = arp_unpack[2]
                protocol_size = arp_unpack[3]
                opcode = arp_unpack[4]
                sender_mac_addr = eth_addr(arp_unpack[5])
                sender_ip_addr = socket.inet_ntoa(arp_unpack[6])
                target_mac_addr = eth_addr(arp_unpack[7])
                target_ip_addr = socket.inet_ntoa(arp_unpack[8])

                #print "opcode: " + str(opcode)
                if opcode == 2:
                    self.neighbor = sender_ip_addr
                    self.sender_mac_addr = sender_mac_addr

            """
            elif ethernet_type == int("0x86dd",16):
                print "ICMPv6"
                icmpv6 = self.frame_data[54:70]
                icmpv6_unpack = struct.unpack('!BBHLBB6s',icmpv6)

                #ICMPv6
                icmpv6_type = icmpv6_unpack[0]
                code = icmpv6_unpack[1]
                checksum = icmpv6_unpack[2]
                reserved = icmpv6_unpack[3]

                #ICMPv6 Option
                icmpv6_option_type = icmpv6_unpack[4]
                icmpv6_option_len = icmpv6_unpack[5]
                link_layer_addr = icmpv6_unpack[6]


                print icmpv6_type
                if icmpv6_type == 135:
                    self.neighbor = src_mac
            """

    def unpack(self):
        # 8 = size of header openflow protocol
        # 17 = size of header(8) + size of buffer_id(4) + size of total_len(2) + size of in_port(2) + size of reason(1)
        packetIn_noHeader = self.packetIn[8:17]

        packetIn_noHeader_unpack = struct.unpack('!LHHB',packetIn_noHeader)

        self.buffer_id = packetIn_noHeader_unpack[0]
        self.total_len = packetIn_noHeader_unpack[1]
        self.in_port = packetIn_noHeader_unpack[2]
        self.reason = packetIn_noHeader_unpack[3]
        self.frame_data = self.packetIn[18:]
        #print self.buffer_id
        #print self.total_len
        #print self.in_port
        #print self.reason
