#coding=utf-8

# read and parse pcap file
# see http://wiki.wireshark.org/Development/LibpcapFileFormat
import sys
import struct
import socket

# see http://www.tcpdump.org/linktypes.html
# http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html#appendixLinkTypes
class Protocol(object):
    ETHERNET = 1
    LINUX_SLL = 113

    IP = 2048
    IPV6 = 34525
    P802_1Q = 33024  # Virtual Bridged Local Area Networks

    TCP = 6

'''
L3 : trans  TCP/UDP
L2 : ip     IP
L1 : link   ethernet/linux_sll
'''

class Pack(object):
    def __init__(self, ts, length, body):
        self.ts          = ts
        self.length      = length
        self.body        = body
        self.offset      = 0  # current levle offset

        self.L2_protocol = None
        self.L3_protocol = None
        #ip
        self.source      = None
        self.dest        = None
        #tcp
        self.source_port = None
        self.dest_port   = None
        self.seq         = None
        self.ack_seq     = None

        self.flags       = 0
        self.fin         = 0
        self.syn         = 0
        self.rst         = 0
        self.psh         = 0
        self.ack         = 0
        self.urg         = 0

    def __str__(self):
        return str(vars(self))

class PcapFile(object):
    def __init__(self, fname):
        self.fin = file(fname)
        self.byteorder = b'@'
        self.L1_type = None

        if not self._read_file_header():
            raise Exception("Can't recognize this PCAP file format")

    # http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
    def _read_file_header(self):
        """check the header of cap file, see it is a ledge pcap file.."""
        pcap_file_header_len = 24
        global_head = self.fin.read(pcap_file_header_len)
        if not global_head:
            raise StopIteration()

        magic_num, = struct.unpack(b'<I', global_head[0:4])
        if magic_num == 0xA1B2C3D4:
            self.byteorder = b'<'
        elif magic_num == 0x4D3C2B1A:
            self.byteorder = b'>'
        else:
            return False

        version_major, version_minor, timezone, timestamp, max_package_len, self.L1_type \
            = struct.unpack(self.byteorder + b'4xHHIIII', global_head)
        return True

    def _read_raw_packet(self):
        """
        read pcap header.
        return the total package length.
        """
        # package header
        pcap_header_len = 16
        package_header = self.fin.read(pcap_header_len)

        # end of file.
        if not package_header:
            return None

        sec, usec, packet_len, raw_len = struct.unpack(self.byteorder + b'IIII', package_header)
        ts = sec+usec/1000000.
        # note: packet_len contains padding.
        body = self.fin.read(packet_len)
        if len(body) < packet_len:
            return None
        return Pack(ts, packet_len, body)

    # http://standards.ieee.org/about/get/802/802.3.html
    def _parse_L1_ethernet(self, pack):
        body = pack.body[pack.offset:]

        eth_header_len = 14
        ethernet_header = body[0:eth_header_len]

        (protocol, ) = struct.unpack(b'!12xH', ethernet_header)
        if protocol == Protocol.P802_1Q:
            # 802.1q, we need to skip two bytes and read another two bytes to get protocal/len
            type_or_len = body[eth_header_len:eth_header_len + 4]
            eth_header_len += 4
            protocol, = struct.unpack(b'!2xH', type_or_len)

        pack.L2_protocol = protocol
        pack.offset += eth_header_len

    # http://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
    def _parse_L1_sll(self, pack):
        """ parse linux sll packet """
        body = pack.body[pack.offset:]
        sll_header_len = 16
        sll_header = body[0:sll_header_len]

        packet_type, link_type_address_type, link_type_address_len, link_type_address, protocol \
            = struct.unpack(b'!HHHQH', sll_header)

        pack.L2_protocol = protocol
        pack.offset += sll_header_len

    def _parse_ip(self, pack):
        body = pack.body[pack.offset:]

        ip_base_header_len = 20
        ip_header = body[0:ip_base_header_len]
        (ip_info, ip_length, protocol) = struct.unpack(b'!BxH5xB10x', ip_header)
        # real ip header len.
        ip_header_len = (ip_info & 0xF) * 4

        pack.source = socket.inet_ntoa(ip_header[12:16])
        pack.dest = socket.inet_ntoa(ip_header[16:])
        pack.L3_protocol = protocol
        pack.offset += ip_header_len

    def _parse_tcp(self, pack):
        body = pack.body[pack.offset:]

        tcp_base_header_len = 20
        tcp_header = body[0:tcp_base_header_len]
        source_port, dest_port, seq, ack_seq, t_f, flags = struct.unpack(b'!HHIIBB6x', tcp_header)
        # real tcp header len
        tcp_header_len = ((t_f >> 4) & 0xF) * 4

        pack.flags       = flags
        pack.fin         = flags & 1
        pack.syn         = (flags >> 1) & 1
        pack.rst         = (flags >> 2) & 1
        pack.psh         = (flags >> 3) & 1
        pack.ack         = (flags >> 4) & 1
        pack.urg         = (flags >> 5) & 1

        pack.source_port = source_port
        pack.dest_port   = dest_port
        pack.seq         = seq
        pack.ack_seq     = ack_seq

        pack.offset += tcp_header_len

    def _read_tcp_packet(self):
        pack = self._read_raw_packet()
        if not pack:
            return -1
        if self.L1_type == Protocol.ETHERNET:
            self._parse_L1_ethernet(pack)
        elif self.L1_type == Protocol.LINUX_SLL:
            self._parse_L1_sll(pack)

        if pack.L2_protocol != Protocol.IP:
            return None
        self._parse_ip(pack)

        if pack.L3_protocol != Protocol.TCP:
            return None
        self._parse_tcp(pack)

        return pack

    def tcp_packets(self):
        while True:
            pack = self._read_tcp_packet()
            if pack == -1:
                return
            if pack:
                pack.body = pack.body[pack.offset:]
                yield pack

if __name__ == "__main__":
    pcap = PcapFile('test.pcap')
    for p in pcap.tcp_packets():
        print p
