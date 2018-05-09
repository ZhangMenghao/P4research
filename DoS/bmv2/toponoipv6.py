from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost, Controller, RemoteController, OVSSwitch, Ryu
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel,info
from mininet.cli import CLI
from functools import partial
from p4_mininet import P4Switch, P4Host

import argparse
import os
from time import sleep
import subprocess

_THIS_DIR = os.path.dirname(os.path.realpath(__file__))
_THRIFT_BASE_PORT = 22222

parser = argparse.ArgumentParser(description='Mininet demo')
parser.add_argument('--behavioral-exe', help='Path to behavioral executable',
                    type=str, action="store", required=True)
parser.add_argument('--json', help='Path to JSON config file',
                    type=str, action="store", required=True)
parser.add_argument('--cli', help='Path to BM CLI',
                    type=str, action="store", required=True)
parser.add_argument('--thrift-port', help='Thrift server port for table updates',
                            type=int, action="store", required=True)

args = parser.parse_args()

class MyTopo( Topo ):
    def __init__( self, sw_path, json_path, thrift_port, **opts):
      
        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        h1 = self.addHost('h1',
                          ip = "10.0.0.10",
                          mac = "00:04:00:00:00:10")
        h2 = self.addHost('h2',
          #                ip = "192.168.0.10",
                           ip = "10.0.0.20",
                           mac = "00:05:00:00:00:10")
        #middleHost = self.addSwitch( 'h3' )
        Switch = self.addSwitch( 's1' ,
                                sw_path = sw_path,
                                json_path = json_path,
                                thrift_port = thrift_port,
                                pcap_dump = True)

        # Add links
        self.addLink( h1, Switch )
        self.addLink( h2, Switch )

        

def main():
    topo = MyTopo(args.behavioral_exe,
                  args.json,
                  args.thrift_port)
    net = Mininet(topo = topo,
                    host = P4Host,
                    switch = P4Switch,
                    controller = None )
    h1 = net.get('h1')
    h2 = net.get('h2')
    s1 = net.get('s1')

#disable ipv6
    h1.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    h1.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    h1.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")
    h2.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    h2.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    h2.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")
      
    s1.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    s1.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    s1.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

    net.start()

    h1.setARP('10.0.0.20',"00:05:00:00:00:10")
    h2.setARP('10.0.0.10',"00:04:00:00:00:10")
    sleep(1)

    cmd = [args.cli,"--json",  args.json, "--thrift-port",str(args.thrift_port)]
    with open("commands.txt", "r") as f:
        print " ".join(cmd)
        try:
            output = subprocess.check_output(cmd, stdin = f)
            print output
        except subprocess.CalledProcessError as e:
            print e
            print e.output
    
    sleep(1)
    print "Ready !"
    
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    main()
