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

CLI_PATH = None

connections = []
client_server_established_connections = []

def send_to_CLI(cmd):
    this_dir = os.path.dirname(os.path.realpath(__file__))
    p = subprocess.Popen(os.path.join(this_dir, 'sswitch_CLI.sh'), stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    output = p.communicate(input=cmd)[0]
    # print output

# This is a very basic implementation of a full-cone NAT for TCP traffic
# We do not maintain a state machine for each connection, so we are not able to
# cleanup the port mappings, but this is sufficient for demonstration purposes
def process_cpu_pkt(p):

    p_str = str(p)
    # 0-7  : destination (0xff)
    # 8-39 : seq_no_offset
    # 40-  : data packet (TCP)
    if p_str[:8] != '\xff':
        return
    ip_hdr = None
    tcp_hdr = None
    try:
        p2 = Ether(p_str[40:])
        ip_hdr = p2['IP']
        tcp_hdr = p2['TCP']
    except:
        return
    print "Packet received"
    print p2.summary()
    connection = (ip_hdr.src, ip_hdr.dst, tcp_hdr.sport, tcp_hdr.dport)
    reverse_connection = (ip_hdr.dst, ip_hdr.src, tcp_hdr.dport, tcp_hdr.sport)
    if connection not in connections:
        print "Adding new items into flow table..."
        # client to server rule for this mapping (no action data)
        send_to_CLI("table_add valid_connection_table set_passthrough_syn_proxy_from_client \
                     %s %s %d %d %d" %\
                    (ip_hdr.src, ip_hdr.dst, tcp_hdr.sport, tcp_hdr.dport, tcp_hdr.flags))
        # external to internal rule for this mapping
        send_to_CLI("table_add valid_connection_table set_passthrough_syn_proxy_from_server_for_new_connection \
                     %s %s %d %d %d" %\
                    (ip_hdr.dst, ip_hdr.src, tcp_hdr.dport, tcp_hdr.sport, tcp_hdr.flags))
        client_confirmed_connections.append(connection) 
    else if reverse_connection in connections:
        # means this is syn+ack packet from server
        offset = int(p_str[9:40])
        send_to_CLI("table_add valid_connection_table set_passthrough_syn_proxy_from_server \
                     %s %s %d %d %d => %d" %\
                    (ip_hdr.src, ip_hdr.dst, tcp_hdr.sport, tcp_hdr.dport, tcp_hdr.flags, offset))

        send_to_CLI("table_remove valid_connection_table set_passthrough_syn_proxy_from_server_for_new_connection \
                     %s %s %d %d %d" %\
                    (ip_hdr.src, ip_hdr.dst, tcp_hdr.sport, tcp_hdr.dport, tcp_hdr.flags))


    # a little bit hacky, this essentially ensures that the packet we re-inject
    # in the CPU iface will not be processed again by this method
    new_p = '\x00' + p_str[8:]
    sendp(new_p, iface="cpu-veth-0", verbose=0)

def main():
    sniff(iface="cpu-veth-0", prn=lambda x: process_cpu_pkt(x))

if __name__ == '__main__':
    main()
