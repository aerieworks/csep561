from pox.core import core
from pox.lib.revent import EventMixin

from ..lib.addresses import ArpTable


"""
Represents a network of switches.
"""
class Network(EventMixin):

  def __init__(self):
    self._nodes = {}
    self._arp_table = ArpTable()

    self.listenTo(core)
    self.listenTo(core.openflow)


  """
  Gets the node for the specified switch DPID.
  """
  def _get_switch(self, switch_dpid):
    return self._nodes.get(switch_dpid)


  """
  Creates a network node to handle a new connection.
  """
  def _create_node(self, connect_event):
    raise NotImplementedError()


  """
  Cleans up the specified node after removal from the network.
  """
  def _clean_up_node(self, node):
    pass


  """
  Creates a switch instance to manage the new switch connection.
  """
  def _handle_ConnectionUp(self, event):
    node = self._create_node(event)
    self._nodes[node.dpid] = node


  """
  Removes a disconnected switch from the network.
  """
  def _handle_ConnectionDown(self, event):
    node = self._nodes.pop(event.dpid, None)
    if node:
      self._clean_up_node(node)


  """
  Perform cleanup tasks when the controller is shut down.
  """
  def _handle_DownEvent(self, event):
    LoadBalancer.logger.debug('Performing final clean up.')
    for k in self._nodes.viewkeys():
      node = self._nodes.pop(k)
      self._clean_up_node(node)


"""
Invoked by POX when Network is specified as a module on the command line:
  $ ./pox csep561.net.network
"""
def launch(**params):
  network = SpanningTreeNetwork(params)
  core.register('spanning_tree_network', network)

