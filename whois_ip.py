#!/usr/bin/env python
# vim:fileencoding=utf-8

from bulkwhois.shadowserver import BulkWhoisShadowserver
import fileinput

def cidr2netmask(cidr):
    mask = [0,0,0,0]
    for i in range(cidr):
        mask[i/8] = mask[i/8] + (1 << (7 - i % 8))
    return ".".join(map(str, mask))

ips = []
for line in fileinput.input():
    ips.append(line.rstrip("\n"))

bulk_whois = BulkWhoisShadowserver()
records = bulk_whois.lookup_ips(ips)

for record in records:

    r = records[record]
    org_name    = r["org_name"]
    cc          = r["cc"]
    ip          = r["ip"]
    register    = r["register"]
    as_name     = r["as_name"]
    (bgp_prefix_ip, _bgp_prefix_cidr)  = r["bgp_prefix"].split('/')
    bgp_prefix_cidr = int(_bgp_prefix_cidr)
    bgp_prefix_netmask = cidr2netmask(bgp_prefix_cidr)
    asn         = r["asn"]
    print "\t".join([ip, bgp_prefix_ip, bgp_prefix_netmask, register, as_name])

