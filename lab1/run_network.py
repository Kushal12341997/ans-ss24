"""
 Copyright 2024 Computer Networks Group @ UPB

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 """

#!/bin/env python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.node import Host
from mininet.cli import CLI
from mininet.log import setLogLevel


class NetworkTopo(Topo):

    def __init__(self):

        Topo.__init__(self)

        # Build the specified network topology here
        # Defining Hosts
        h1 = self.addHost('h1', cls=Host, ip='10.0.1.2/24')
        h2 = self.addHost('h2', cls=Host, ip='10.0.1.3/24')
        ext = self.addHost('ext', cls=Host, ip='192.168.1.123/24')
        ser = self.addHost('ser', cls=Host, ip='10.0.2.2/24')
        
        # Defining Switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        
        # Defining the links
        self.addLink( h1, s1, cls=TCLink,bw=15, delay='10ms')
        self.addLink( h2, s1, cls=TCLink,bw=15, delay='10ms')
        self.addLink( s1, s3, cls=TCLink,bw=15, delay='10ms')
        self.addLink( s2, s3, cls=TCLink,bw=15, delay='10ms')
        self.addLink( ser, s2, cls=TCLink,bw=15, delay='10ms')
        self.addLink( ext, s3, cls=TCLink,bw=15, delay='10ms')

        

def run():
    topo = NetworkTopo()
    net = Mininet(topo=topo,
                  switch=OVSKernelSwitch,
                  link=TCLink,
                  controller=None)
    net.addController(
        'c1', 
        controller=RemoteController, 
        ip="127.0.0.1", 
        port=6653)
    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()