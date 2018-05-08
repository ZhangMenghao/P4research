# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from scapy.all import *
import subprocess
import os
import re

CLI_PATH = None

connections = {}

def send_to_CLI(cmd):
    this_dir = os.path.dirname(os.path.realpath(__file__))
    p = subprocess.Popen(os.path.join(this_dir, 'sswitch_CLI.sh'), stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    output = p.communicate(input=cmd)[0]
    print output
    return output

# This is a very basic implementation of a full-cone NAT for TCP traffic
# We do not maintain a state machine for each connection, so we are not able to
# cleanup the port mappings, but this is sufficient for demonstration purposes
def process_cpu_pkt(p):
    p_str = str(p)
    # 0  : destination (0xff)
    # 1-4 : seq_no_offset
    # 0-  : data packet (TCP)
    if p_str[:5] != '\xff' * 5:
        return

    ip_hdr = None
    tcp_hdr = None
    try:
        p2 = Ether(p_str)
        ip_hdr = p2['IP']
        tcp_hdr = p2['TCP']
    except:
        print 'exception!'
        return
    print "Packet received"
    print p2.summary()
    connection = (ip_hdr.src, ip_hdr.dst, tcp_hdr.sport, tcp_hdr.dport)
    offset = int(tcp_hdr.seq)
    if connection not in connections:
        print "Adding new items into flow table..."
        # incoming packet should be syn+ack from server
        # server to client rule for this mapping
        send_to_CLI("table_add valid_connection_table set_passthrough_syn_proxy_from_server \
                     %s %s %d %d => %d" %\
                    (ip_hdr.src, ip_hdr.dst, tcp_hdr.sport, tcp_hdr.dport, offset))
        # client to server rule for this mapping
        cmd_return = send_to_CLI("table_add valid_connection_table set_passthrough_syn_proxy_from_client \
                     %s %s %d %d => %d" %\
                    (ip_hdr.dst, ip_hdr.src, tcp_hdr.dport, tcp_hdr.sport, offset))
        # pattern = re.compile(r"handle (\d+)")
        # match = pattern.search(cmd_return)
        # if(match):
        #     handle = int(match.group(1))
        #     # print 'handle num is %d' % handle
        #     connections[connection] = handle
        # send_to_CLI("table_dump_entry valid_connection_table %d" % (handle - 1))


def main():
    sniff(iface="cpu-veth-0", prn=lambda x: process_cpu_pkt(x))

if __name__ == '__main__':
    main()
