"""Custom topology example

Two directly connected switches plus a host for each switch:

host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.

start OVS Test Controller as:
sudo ovs-controller --max-idle=500 ptcp:6633:127.0.0.2

To add delay and redirect traffic, follow instructiosn from link:
https://mailman.stanford.edu/pipermail/mininet-discuss/2014-January/003882.html

"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.node import Controller, OVSSwitch
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel

def topology():
    net = Mininet(controller=RemoteController)
    h1  = net.addHost('h1', mac='0a:55:76:65:cd:f0')
    h2  = net.addHost('h2', mac='0a:55:76:65:cd:f1')
    h3  = net.addHost('h3', mac='0a:55:76:65:cd:f2')
    h4  = net.addHost('h4', mac='0a:55:76:65:cd:f3')
    h5  = net.addHost('h5', mac='0a:55:76:65:cd:f4')
    h6  = net.addHost('h6', mac='0a:55:76:65:cd:f5')
    h7  = net.addHost('h7', mac='0a:55:76:65:cd:f6')
    h8  = net.addHost('h8', mac='0a:55:76:65:cd:f7')
    h9  = net.addHost('h9', mac='0a:55:76:65:cd:f8')
    h10 = net.addHost('h10', mac='0a:55:76:65:cd:f9')
    h11 = net.addHost('h11', mac='0a:55:76:65:cd:fa')
    h12 = net.addHost('h12', mac='0a:55:76:65:cd:fb')
    h13 = net.addHost('h13', mac='0a:55:76:65:cd:fc')
    h14 = net.addHost('h14', mac='0a:55:76:65:cd:fd')
    h15 = net.addHost('h15', mac='0a:55:76:65:cd:fe')
    h16 = net.addHost('h16', mac='0a:55:76:65:cd:ff')
    h17 = net.addHost('h17', mac='76:1c:a1:e2:1b:41')
    h18 = net.addHost('h18', mac='76:1c:a1:e2:1b:42')

    s1 = net.addSwitch('s1')
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.2', port=6633)

    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)
    net.addLink(h5, s1)
    net.addLink(h6, s1)
    net.addLink(h7, s1)
    net.addLink(h8, s1)
    net.addLink(h9, s1)
    net.addLink(h10, s1)
    net.addLink(h11, s1)
    net.addLink(h12, s1)
    net.addLink(h13, s1)
    net.addLink(h14, s1)
    net.addLink(h15, s1)
    net.addLink(h16, s1)
    net.addLink(h17, s1)
    net.addLink(h18, s1)

    net.build()

    c0.start()
    s1.start( [c0] )

    CLI(net)

if __name__ == '__main__':
    setLogLevel( 'info' )
    topology()
