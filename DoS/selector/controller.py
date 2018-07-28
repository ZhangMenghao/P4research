#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
from time import sleep

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2

bucket_size = 10000
switch_virtual_ips = ['11.0.0.1', '11.0.0.2', '11.0.0.3']
switch_count = 3

class Bucket:
    belongs = -1
    table_entrys = []
    def __init__(self, belongs):
        self.belongs = belongs
    def add_table_entry(self, switch_index, entry_num):
        self.table_entrys.append((switch_index, entry_num))

buckets = []

def insertNextHopRule(p4info_helper, sw, dst_ip, mask, next_hop):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "meta.midHopAddr": (dst_ip, mask)
        },
        action_name="MyIngress.set_nhop",
        action_params={
            "nextHop": next_hop,
        }
    )
    sw.WriteTableEntry(table_entry)
    print "Installed ipv4_lpm table rule on %s" % sw.name

def insertForwardingRule(p4info_helper, sw, next_hop, dmac, port):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.forward_table",
        match_fields={
            "meta.nextHop": next_hop
        },
        action_name="MyIngress.set_dmac",
        action_params={
            "dmac": dmac,
            "port": port,
        }
    )
    sw.WriteTableEntry(table_entry)
    print "Installed forward_table table rule on %s" % sw.name

def insertSendFrameRule(p4info_helper, sw, port, smac):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyEgress.send_frame",
        match_fields={
            "standard_metadata.egress_spec": port
        },
        action_name="MyEgress.rewrite_mac",
        action_params={
            "smac": smac,
        }
    )
    sw.WriteTableEntry(table_entry)
    print "Installed send_frame table rule on %s" % sw.name

def insertCheckBucketRule(p4info_helper, sw, bucket_index, midHopAddr):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyEgress.checkBucket",
        match_fields={
            "meta.bucketIndex": bucket_index
        },
        action_name="MyEgress.setAnotherMidHop",
        action_params={
            "midHopAddr": midHopAddr,
        }
    )
    sw.WriteTableEntry(table_entry)
    print "Installed checkBucket table rule on %s" % sw.name


def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print '\n----- Reading tables rules for %s -----' % sw.name
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            # TODO For extra credit, you can use the p4info_helper to translate
            #      the IDs in the entry to names
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print '%s: ' % table_name,
            for m in entry.match:
                print p4info_helper.get_match_field_name(table_name, m.field_id),
                print '%r' % (p4info_helper.get_match_field_value(m),),
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print '->', action_name,
            for p in action.params:
                print p4info_helper.get_action_param_name(action_name, p.param_id),
                print '%r' % p.value,
            print

def printCounter(p4info_helper, sw, counter_name, index):
    """
    Reads the specified counter at the specified index from the switch. In our
    program, the index is the tunnel ID. If the index is 0, it will return all
    values from the counter.

    :param p4info_helper: the P4Info helper
    :param sw:  the switch connection
    :param counter_name: the name of the counter from the P4 program
    :param index: the counter index (in our case, the tunnel ID)
    """
    for response in sw.ReadCounters(p4info_helper.get_counters_id(counter_name), index):
        for entity in response.entities:
            counter = entity.counter_entry
            print "%s %s %d: %d packets (%d bytes)" % (
                sw.name, counter_name, index,
                counter.data.packet_count, counter.data.byte_count
            )

def printGrpcError(e):
    print "gRPC Error:", e.details(),
    status_code = e.code()
    print "(%s)" % status_code.name,
    traceback = sys.exc_info()[2]
    print "[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        switches = []

        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        switches.append(s1)
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')
        switches.append(s2)
        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='logs/s3-p4runtime-requests.txt')
        switches.append(s3)


        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s3.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s1"
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s2"
        s3.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s3"

        # install basic forwarding rules
        # s1
        insertNextHopRule(p4info_helper, s1, '10.0.0.1', 32, '10.0.0.1')
        insertNextHopRule(p4info_helper, s1, '11.0.0.2', 32, '11.0.0.2')
        insertNextHopRule(p4info_helper, s1, '10.0.0.2', 32, '11.0.0.2')
        insertNextHopRule(p4info_helper, s1, '12.0.0.0', 8, '11.0.0.2')
        insertNextHopRule(p4info_helper, s1, '11.0.0.3', 32, '11.0.0.3')
        insertNextHopRule(p4info_helper, s1, '10.0.0.3', 32, '11.0.0.3')
        insertNextHopRule(p4info_helper, s1, '13.0.0.0', 8, '11.0.0.3')
        insertForwardingRule(p4info_helper, s1, '10.0.0.1', '10:00:00:00:01:01', 1)
        insertForwardingRule(p4info_helper, s1, '11.0.0.2', '11:00:00:00:02:01', 2)
        insertForwardingRule(p4info_helper, s1, '11.0.0.3', '11:00:00:00:03:01', 3)
        insertSendFrameRule(p4info_helper, s1, 1, '11:00:00:00:01:01')
        insertSendFrameRule(p4info_helper, s1, 2, '11:00:00:00:01:02')
        insertSendFrameRule(p4info_helper, s1, 3, '11:00:00:00:01:03')
        # s2
        insertNextHopRule(p4info_helper, s2, '10.0.0.1', 32, '11.0.0.1')
        insertNextHopRule(p4info_helper, s2, '11.0.0.1', 32, '11.0.0.1')
        insertNextHopRule(p4info_helper, s2, '11.0.0.3', 32, '11.0.0.1')
        insertNextHopRule(p4info_helper, s2, '10.0.0.3', 32, '11.0.0.1')
        insertNextHopRule(p4info_helper, s2, '13.0.0.0', 8, '11.0.0.1')
        insertNextHopRule(p4info_helper, s2, '10.0.0.2', 32, '10.0.0.2')
        insertNextHopRule(p4info_helper, s2, '12.0.0.0', 8, '10.0.0.2')
        insertForwardingRule(p4info_helper, s2, '11.0.0.1', '11:00:00:00:01:02', 1)
        insertForwardingRule(p4info_helper, s2, '10.0.0.2', '10:00:00:00:02:01', 2)
        insertSendFrameRule(p4info_helper, s2, 1, '11:00:00:00:02:01')
        insertSendFrameRule(p4info_helper, s2, 2, '11:00:00:00:02:02')
        # s3
        insertNextHopRule(p4info_helper, s3, '10.0.0.1', 32, '11.0.0.1')
        insertNextHopRule(p4info_helper, s3, '11.0.0.1', 32, '11.0.0.1')
        insertNextHopRule(p4info_helper, s3, '10.0.0.2', 32, '11.0.0.1')
        insertNextHopRule(p4info_helper, s3, '11.0.0.2', 32, '11.0.0.1')
        insertNextHopRule(p4info_helper, s3, '12.0.0.0', 8, '11.0.0.1')
        insertNextHopRule(p4info_helper, s3, '10.0.0.3', 32, '10.0.0.3')
        insertNextHopRule(p4info_helper, s3, '13.0.0.0', 8, '10.0.0.3')
        insertForwardingRule(p4info_helper, s3, '11.0.0.1', '11:00:00:00:01:03', 1)
        insertForwardingRule(p4info_helper, s3, '10.0.0.3', '10:00:00:00:03:01', 2)
        insertSendFrameRule(p4info_helper, s3, 1, '11:00:00:00:03:01')
        insertSendFrameRule(p4info_helper, s3, 2, '11:00:00:00:03:02')

        # install initial bucket rules
        for bucket in range(0, bucket_size):
            # switch_index: 0, 1 or 2
            switch_index = bucket % switch_count
            buckets.append(Bucket(switch_index))
            # insert rules into switches that don't deal with the flow
            for i in range(len(switch_count)):
                if i != switch_index:
                    insertCheckBucketRule(p4info_helper, switches[switch_index], bucket, switch_virtual_ips[switch_index])
                    # TODO record bucket distribution among switches
                    # get entry number and insert into buckets
                    # buckets[bucket].add_table_entry(i, entry_index)

    except KeyboardInterrupt:
        print " Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/advanced_tunnel.p4info')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/advanced_tunnel.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nHave you run 'make'?" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
