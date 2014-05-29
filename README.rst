a simple implement of pacp parser, for TCP only, in 200 lines of python

theirs code too long, try this one.

the main parse logic is based on : https://github.com/xiaxiaocao/pyhttpcap, thanks @xiaxiaocao

usage::

    from pypcap import PcapFile
    pcap = PcapFile('test.pcap')
    for p in pcap.tcp_packets():
        print p

result::

    $ python pypcap/__init__.py
    {'body': '', 'psh': 0, 'urg': 0, 'ack': 0, 'seq': 3564969520, 'dest': '10.0.1.146', 'L2_protocol': 2048, 'ack_seq': 0, 'ts': 1092256609.926555, 'syn': 1, 'rst': 0, 'source': '10.0.1.130', 'length': 62, 'flags': 2, 'offset': 62, 'source_port': 1668, 'L3_protocol': 6, 'fin': 0, 'dest_port': 443}
    {'body': '', 'psh': 0, 'urg': 0, 'ack': 1, 'seq': 0, 'dest': '10.0.1.130', 'L2_protocol': 2048, 'ack_seq': 3564969521, 'ts': 1092256609.926576, 'syn': 0, 'rst': 1, 'source': '10.0.1.146', 'length': 54, 'flags': 20, 'offset': 54, 'source_port': 443, 'L3_protocol': 6, 'fin': 0, 'dest_port': 1668}
    {'body': '', 'psh': 0, 'urg': 0, 'ack': 0, 'seq': 3564969520, 'dest': '10.0.1.146', 'L2_protocol': 2048, 'ack_seq': 0, 'ts': 1092256610.332396, 'syn': 1, 'rst': 0, 'source': '10.0.1.130', 'length': 62, 'flags': 2, 'offset': 62, 'source_port': 1668, 'L3_protocol': 6, 'fin': 0, 'dest_port': 443}
    {'body': '', 'psh': 0, 'urg': 0, 'ack': 1, 'seq': 0, 'dest': '10.0.1.130', 'L2_protocol': 2048, 'ack_seq': 3564969521, 'ts': 1092256610.332416, 'syn': 0, 'rst': 1, 'source': '10.0.1.146', 'length': 54, 'flags': 20, 'offset': 54, 'source_port': 443, 'L3_protocol': 6, 'fin': 0, 'dest_port': 1668}
    {'body': '', 'psh': 0, 'urg': 0, 'ack': 0, 'seq': 3564969520, 'dest': '10.0.1.146', 'L2_protocol': 2048, 'ack_seq': 0, 'ts': 1092256610.833073, 'syn': 1, 'rst': 0, 'source': '10.0.1.130', 'length': 62, 'flags': 2, 'offset': 62, 'source_port': 1668, 'L3_protocol': 6, 'fin': 0, 'dest_port': 443}
    {'body': '', 'psh': 0, 'urg': 0, 'ack': 1, 'seq': 0, 'dest': '10.0.1.130', 'L2_protocol': 2048, 'ack_seq': 3564969521, 'ts': 1092256610.833095, 'syn': 0, 'rst': 1, 'source': '10.0.1.146', 'length': 54, 'flags': 20, 'offset': 54, 'source_port': 443, 'L3_protocol': 6, 'fin': 0, 'dest_port': 1668}


