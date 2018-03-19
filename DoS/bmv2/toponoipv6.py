from mininet.topo import Topo
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost, Controller, RemoteController, OVSSwitch, Ryu
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel,info
from mininet.cli import CLI
from functools import partial
class MyTopo( Topo ):
    def __init__( self ):
      
        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        leftHost = self.addHost( 'h1' )
        rightHost = self.addHost( 'h2' )
        #middleHost = self.addSwitch( 'h3' )
        Switch = self.addSwitch( 's1' )

        # Add links
        self.addLink( leftHost, Switch )
        self.addLink( Switch, rightHost )
        #self.addLink( middleHost, Switch )
        

def main():
    topo = MyTopo()
    net = Mininet(topo = topo )
    h1 = net.get('h1')
    h2 = net.get('h2')
    s1 = net.get('s1')

    
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
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    main()
