from mininet.topo import Topo

class DiamondTopo(Topo):
    def build(self):
        h1, h2 = self.addHost('h1'), self.addHost('h2')
        s1, s2, s3, s4 = [self.addSwitch('s' + str(i)) for i in range(1, 5)]
        self.addLink(h1, s1)
        self.addLink(s1, s2)
        self.addLink(s1, s3)
        self.addLink(s2, s4)
        self.addLink(s3, s4)
        self.addLink(s4, h2)

class RingTopo(Topo):
    def build(self):
        # 5 Switches, 5 Hosts
        switches = [self.addSwitch('s' + str(i)) for i in range(1, 6)]
        hosts = [self.addHost('h' + str(i)) for i in range(1, 6)]
        
        # Connect 1 host to each switch
        for i in range(5):
            self.addLink(hosts[i], switches[i])
        
        # Connect switches in a circular ring
        for i in range(5):
            self.addLink(switches[i], switches[(i+1)%5])

class MeshTopo(Topo):
    def build(self):
        # 4 Switches, fully interconnected
        switches = [self.addSwitch('s' + str(i)) for i in range(1, 5)]
        hosts = [self.addHost('h' + str(i)) for i in range(1, 5)]
        
        # 2 hosts on Switch 1, 2 hosts on Switch 4
        self.addLink(hosts[0], switches[0])
        self.addLink(hosts[1], switches[0])
        self.addLink(hosts[2], switches[3])
        self.addLink(hosts[3], switches[3])
        
        # Connect every switch to every other switch
        for i in range(4):
            for j in range(i+1, 4):
                self.addLink(switches[i], switches[j])

topos = {
    'diamond': (lambda: DiamondTopo()),
    'ring': (lambda: RingTopo()),
    'mesh': (lambda: MeshTopo())
}