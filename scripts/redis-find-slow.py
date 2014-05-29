#!/usr/bin/env python
#coding: utf-8
#file   : run.py
#author : ning
#date   : 2014-05-29 15:41:56

import os
import re
import sys
import time
import copy
import thread
import logging

PWD = os.path.dirname(os.path.realpath(__file__))
WORKDIR = os.path.join(PWD,  '../')
LOGPATH = os.path.join(WORKDIR, 'log/run.log')

sys.path.append(os.path.join(WORKDIR, '../'))

from string import Template
def TT(template, args): #todo: modify all
    return Template(template).substitute(args)

from pypcap import *

def gen_key(pack):
    if pack.source_port < pack.dest_port:
        return TT('$source:$source_port-$dest:$dest_port', vars(pack))
    else:
        return TT('$dest:$dest_port-$source:$source_port', vars(pack))

def filter(pack):
    if pack.source_port < 5000 or pack.dest_port < 5000:
        return False
    return True

last_active = {}

def main():
    pcap = PcapFile('/home/ning/test/a.pcap')
    cnt = 0
    for p in pcap.tcp_packets():
        cnt += 1
        if cnt % 1000 == 0:
            print '%d done' % cnt

        if not p.body:
            continue
        if filter(p):
            continue

        p.body = p.body.replace('\r\n', ' ')
        #print TT('$ts $source:$source_port-$dest:$dest_port  # $body', vars(p))

        if gen_key(p) in last_active:
            diff = p.ts - last_active[gen_key(p)]
            #print diff
            if diff > 15:
                print 'diff: ', diff,  TT('$ts $source:$source_port-$dest:$dest_port  # $body', vars(p))
        last_active[gen_key(p)] = p.ts

if __name__ == "__main__":
    main()

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

