"""
Author:     Annabelle Richard <richanna@u.washington.edu>
Course:     CSEP 561 (Autumn, 2013)
Professor:  Arvind Krishnamurthy

Creates and runs a mininet topology containing a single switch with three hosts.  Also provides a set of utility methods for manipulating the topology from the mininet CLI via the `py` command.

Based on the SingleSwitchTopo example in the Mininet Python API documentation (https://github.com/mininet/mininet/wiki/Introduction-to-Mininet#wiki-creating).
"""

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo
from mininet.util import dumpNodeConnections

"""
Creates a single switch connected to n hosts.
"""
class SingleSwitchTopo(Topo):
  def __init__(self, host_count = 10, switch_name = 's1', host_name_prefix = 'h', **opts):
    Topo.__init__(self, **opts)
    switch = self.addSwitch(switch_name)
    for i in range(host_count):
      name = '{prefix}{index}'.format(prefix = host_name_prefix, index = i + 1)
      host = self.addHost(name)
      self.addLink(host, switch)

  def hello_world(self):
    print 'Hello, world!'


if __name__ == '__main__':
  setLogLevel('info')

  topo = SingleSwitchTopo()
  net = Mininet(topo = topo, controller = lambda name: RemoteController('c0'), autoSetMacs = True)
  net.start()

  print 'Listing host connections:'
  dumpNodeConnections(net.hosts)

  CLI(net)
  net.stop()
