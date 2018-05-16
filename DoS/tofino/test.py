# Copyright 2013-present Barefoot Networks, Inc.
# # Licensed under the Apache License, Version 2.0 (the "License");
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

"""
Simple PTF test for synproxy.p4
"""

import pd_base_tests

from ptf import config
from ptf.testutils import *
from ptf.thriftutils import *

from synproxy.p4_pd_rpc.ttypes import *
from res_pd_rpc.ttypes import *

class SYNProxyTest(pd_base_tests.ThriftInterfaceDataPlane):
    def __init__(self):
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self,
                                                        ["synproxy"])

    # The setUp() method is used to prepare the test fixture. Typically
    # you would use it to establich connection to the Thrift server.
    #
    # You can also put the initial device configuration there. However,
    # if during this process an error is encountered, it will be considered
    # as a test error (meaning the test is incorrect),
    # rather than a test failure
    def setUp(self):
        pd_base_tests.ThriftInterfaceDataPlane.setUp(self)

        self.sess_hdl = self.conn_mgr.client_init()
        self.dev      = 0
        self.dev_tgt  = DevTarget_t(self.dev, hex_to_i16(0xFFFF))

        print("\nConnected to Device %d, Session %d" % (
            self.dev, self.sess_hdl))

    # This method represents the test itself. Typically you would want to
    # configure the device (e.g. by populating the tables), send some
    # traffic and check the results.
    #
    # For more flexible checks, you can import unittest module and use
    # the provided methods, such as unittest.assertEqual()
    #
    # Do not enclose the code into try/except/finally -- this is done by
    # the framework itself
    def runTest(self):
        # Test Parameters
        mac_da       = "00:11:11:11:11:11"


	print("Enabling ports (physical interface 1 and 2 as 40G)")
        ingress_port = 128
        egress_port  = 136
	speed40G = 4
	dev = self.dev
	channel = 0
	self.pltfm_pm.pltfm_pm_port_add(dev,ingress_port,speed40G,channel)
	self.pltfm_pm.pltfm_pm_port_add(dev,egress_port,speed40G,channel)
	self.pltfm_pm.pltfm_pm_port_enable(dev,ingress_port)
	self.pltfm_pm.pltfm_pm_port_enable(dev,egress_port)

	self.client.session_init_table_set_default_action_sendback_sa(self.sess_hdl,self.dev_tgt);
	self.client.session_complete_table_set_default_action_sendh2syn(self.sess_hdl,self.dev_tgt);
	self.client.relay_session_table_set_default_action_sendh2ack(self.sess_hdl,self.dev_tgt);
	self.client.inbound_tran_table_set_default_action_inbound_transformation(self.sess_hdl,self.dev_tgt);
	self.client.outbound_tran_table_set_default_action_outbound_transformation(self.sess_hdl,self.dev_tgt);

	self.client.session_check_set_default_action_lookup_session_map(self.sess_hdl,self.dev_tgt);
	self.client.session_check_reverse_set_default_action_lookup_session_map_reverse(self.sess_hdl,self.dev_tgt);
	self.client.set_heavy_hitter_count_table_1_set_default_action_set_heavy_hitter_count_1(self.sess_hdl,self.dev_tgt);
	self.client.set_heavy_hitter_count_table_2_set_default_action_set_heavy_hitter_count_2(self.sess_hdl,self.dev_tgt);

        self.conn_mgr.complete_operations(self.sess_hdl)
	self.client.hash_fields_register(self.sess_hdl,self.dev)
	while(True):
		digests = self.client.hash_fields_get_digest(self.sess_hdl)
		if len(digests.msg) == 0:
			continue	
		for digest_entry in digests.msg:
			print i32_to_ipv4Addr(digest_entry.ipv4_srcAddr)
		self.client.hash_fields_digest_notify_ack(self.sess_hdl,digests.msg_ptr)
			
	'''
        print("Sending packet with DST MAC=%s into port %d" %
              (mac_da, ingress_port))
        pkt = simple_tcp_packet(eth_dst=mac_da,
                                eth_src='00:55:55:55:55:55',
                                ip_dst='10.0.0.1',
                                ip_id=101,
                                ip_ttl=64,
                                ip_ihl=5)
        send_packet(self, ingress_port, pkt)
	time.sleep(1)
        print("Expecting packet on port %d" % egress_port)
        verify_packets(self, pkt, [egress_port])
	'''

    # Use this method to return the DUT to the initial state by cleaning
    # all the configuration and clearing up the connection
    def tearDown(self):
        try:
            print("Clearing table entries")
            for table in self.entries.keys():
                delete_func = "self.client." + table + "_table_delete"
                for entry in self.entries[table]:
                    exec delete_func + "(self.sess_hdl, self.dev, entry)"
        except:
            print("Error while cleaning up. ")
            print("You might need to restart the driver")
        finally:
            self.conn_mgr.complete_operations(self.sess_hdl)
            self.conn_mgr.client_cleanup(self.sess_hdl)
            print("Closed Session %d" % self.sess_hdl)
            pd_base_tests.ThriftInterfaceDataPlane.tearDown(self)
