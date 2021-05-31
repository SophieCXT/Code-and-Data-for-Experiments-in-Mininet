"""Custom topology example

Two directly connected switches plus a host for each switch:

host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import Controller, OVSSwitch

class MyTopo( Topo ):
    "Simple topology example."
    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        h1  = self.addHost('h1', mac='0a:55:76:65:cd:f0')
        h2  = self.addHost('h2', mac='0a:55:76:65:cd:f1')
        h3  = self.addHost('h3', mac='0a:55:76:65:cd:f2')
        h4  = self.addHost('h4', mac='0a:55:76:65:cd:f3')
        h5  = self.addHost('h5', mac='0a:55:76:65:cd:f4')
        h6  = self.addHost('h6', mac='0a:55:76:65:cd:f5')
        h7  = self.addHost('h7', mac='0a:55:76:65:cd:f6')
        h8  = self.addHost('h8', mac='0a:55:76:65:cd:f7')
        h9  = self.addHost('h9', mac='0a:55:76:65:cd:f8')
        h10 = self.addHost('h10', mac='0a:55:76:65:cd:f9')
        h11 = self.addHost('h11', mac='0a:55:76:65:cd:fa')
        h12 = self.addHost('h12', mac='0a:55:76:65:cd:fb')
        h13 = self.addHost('h13', mac='0a:55:76:65:cd:fc')
        h14 = self.addHost('h14', mac='0a:55:76:65:cd:fd')
        h15 = self.addHost('h15', mac='0a:55:76:65:cd:fe')
        h16 = self.addHost('h16', mac='0a:55:76:65:cd:ff')
        h17 = self.addHost('h17', mac='76:1c:a1:e2:1b:41')
        h18 = self.addHost('h18', mac='76:1c:a1:e2:1b:42')
        s1 = self.addSwitch('s1')
        #c0 = self.addController('c0')

        # Add links
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)
        self.addLink(h5, s1)
        self.addLink(h6, s1)
        self.addLink(h7, s1)
        self.addLink(h8, s1)
        self.addLink(h9, s1)
        self.addLink(h10, s1)
        self.addLink(h11, s1)
        self.addLink(h12, s1)
        self.addLink(h13, s1)
        self.addLink(h14, s1)
        self.addLink(h15, s1)
        self.addLink(h16, s1)
        self.addLink(h17, s1)
        self.addLink(h18, s1)
        #self.addLink(c0, s1)
	
topos = { 'mytopo': ( lambda: MyTopo() ) }
