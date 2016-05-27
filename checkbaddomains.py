#!/usr/bin/env python2
import sys
try:
    import requests
except ImportError:
    print '\n requests not found \n try "sudo pip install requests"'
try:
    import pyshark
except ImportError:
    print '\n pyshark not found \n try "sudo pip install pyshark"'

ouput_file = 'baddomain_hits.txt'
url = 'http://malwaredomains.lehigh.edu/files/domains.txt'

if len(sys.argv) > 1:
    pcap = sys.argv[1]
else:
    print "You must specify a packet file -> checkbaddomains.py packetfile.pcap"
    exit(1)


def print_to_screen(pkt, dns, f_object):
    protocol = pkt.transport_layer
    src_addr = pkt.ip.src
    src_port = pkt[pkt.transport_layer].srcport
    dst_addr = pkt.ip.dst
    dst_port = pkt[pkt.transport_layer].dstport
    sniff_time = str(pkt.sniff_time)
    print '%s  %s  %s:%s --> %s:%s  %s' % (sniff_time, protocol, src_addr, src_port, dst_addr, dst_port, dns)
    f_object.write('%s  %s  %s:%s --> %s:%s  %s \n' % (sniff_time, protocol, src_addr, src_port, dst_addr, dst_port, dns))

# download a current domain blacklist and add to list
bad_list = []
r = requests.get(url)
data = r.content.split('\n')
for line in data:
    bad_list.append(line.split()[0])

# create empty set
bad_domains = set()
bad_domains.update(bad_list)

# load capture file
capture = pyshark.FileCapture(pcap)

f = open(ouput_file, 'a')

count = 0

for pkt in capture:
    if hasattr(pkt, 'dns'):
        if pkt.dns.qry_name:
            if pkt.dns.qry_name in bad_domains:
                dns = pkt.dns.qry_name
                print_to_screen(pkt, dns, f)
                count += 1
        elif pkt.dns.resp_name:
            if pkt.dns_resp_name in bad_domains:
                dns = pkt.dns.resp_name
                print_to_screen(pkt, dns, f)
                count += 1

f.close()
print 'Complete: %d bad domains found' % count
