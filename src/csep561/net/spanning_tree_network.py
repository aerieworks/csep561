from pox.core import core

from ..device.lldp_switch import LldpSwitch
from ..graph.dijkstra import DijkstraNode, find_shortest_paths
from .network import Network


PARAM_UPLINKS = 'uplinks'


"""
A network of switches that routes traffic along a spanning tree.
"""
class SpanningTreeNetwork(Network):

  logger = core.getLogger()

  def __init__(self, params):
    self.root = None
    self._parse_config(params)
    super(SpanningTreeNetwork, self).__init__()


  def _create_node(self, connect_event):
    switch = LldpSwitch(connect_event, self._arp_table)
    switch.addListenerByName('LinkDiscoveryEvent', self._handle_switch_LinkDiscoveryEvent)
    switch.addListenerByName('UnknownPacketSourceEvent', self._handle_switch_UnknownPacketSourceEvent)
    return switch


  def _parse_config(self, params):
    uplink_str = params.get(PARAM_UPLINKS)
    if uplink_str:
      self._uplinks = [tuple(x.split(',')) for x in uplink_str.split(';')]
    else:
      self._uplinks = []


  def _rebuild_spanning_tree(self, start = None):
    if start is None:
      start = self.root

    # Build the list of switches for which to rebuild the spanning tree.
    switches = [ start ]
    added = set()
    i = 0
    while i < len(switches):
      switch = switches[i]
      added.add(switch)

      # Add all switches this node is linked to, except those that we have
      # initialized.
      links = filter(lambda x: (switch.dpid, x.port) not in self._uplinks and x.switch not in added, switch.links)
      switches.extend([ x.switch for x in links ])
      i += 1

    # Calculate shortest paths using Dijkstra's algorithm.
    nodes = { x.dpid: DijkstraNode(x.dpid) for x in switches }
    for switch in switches:
      node = nodes[switch.dpid]
      node.neighbors = [ nodes[x.switch.dpid] for x in switch.links ]

    paths = find_shortest_paths(nodes[start.dpid], set(nodes.values()))

    # Find which links need to be activated and which need to be deactivated.
    best_links = set()
    links_to_deactivate = set()
    for (node_name, best) in paths.viewitems():
      if best is None:
        continue
      # Find the link representing the best path for this node.
      for link in self._get_switch(node_name).links:
        reverse = link.get_reverse()
        if link.switch.dpid == best.name:
          # Activate both directions of the link.
          link.activate()
          reverse.activate()

          # Record that the link is a best path link.
          best_links.add(link)
          best_links.add(reverse)

          # Remove the link from the set of links to deactivate.
          links_to_deactivate.discard(link)
          links_to_deactivate.discard(reverse)

        elif link not in best_links and reverse not in best_links:
          # Add the link to the set of links to deactivate.
          links_to_deactivate.add(link)
          links_to_deactivate.add(reverse)

    # Deactivate any links that were not found to be best path links.
    for link in links_to_deactivate:
      link.deactivate()


  """
  Teach a switch where to find a MAC address, and propagate that along the
  switch's active links.
  """
  def _teach_mac_location(self, switch, mac, port):
    SpanningTreeNetwork.logger.debug('Teaching switch {} to find {} at port {}.'.format(switch.dpid, mac, port))
    switch.learn_mac_location(mac, port)

    # Teach that this MAC address can be reached through active links.
    for link in filter(lambda x: x.port != port and x.is_active(), switch.links):
      self._teach_mac_location(link.switch, mac, link.get_reverse().port)


  """
  Create Link instances for both directions of the link and update the spanning
  tree as necessary.
  """
  def _handle_switch_LinkDiscoveryEvent(self, event):
    local_switch = self._get_switch(event.local_switch.dpid)
    if not local_switch:
      raise Exception('Received link discovery event for unknown local switch: {}.'.format(event.local_switch.dpid))

    remote_switch = self._get_switch(event.remote_dpid)
    if not remote_switch:
      raise Exception('Received link discovery event for unknown remote switch: {}.'.format(event.remote_dpid))


    SpanningTreeNetwork.logger.debug('Discovered link from {}[{}] to {}[{}].'.format(local_switch.dpid, event.local_port, remote_switch.dpid, event.remote_port))
    local_switch.add_link(event.local_port, remote_switch, event.remote_port)

    # Set root to switch with the lowest DPID.
    if self.root is None or local_switch.dpid < self.root.dpid:
      self.root = local_switch
    if remote_switch.dpid < self.root.dpid:
      self.root = remote_switch

    # For simplicity, just calculate a full spanning tree for now, can probably optimize.
    SpanningTreeNetwork.logger.debug('New link added within the network; calculating full spanning tree.')
    self._rebuild_spanning_tree()


  """
  Handle unknown packet sources by learning their location on the switch.
  """
  def _handle_switch_UnknownPacketSourceEvent(self, event):
    in_port = event.event.ofp.in_port
    #if event.switch.is_link_port(in_port):
      # Do nothing, we will learn what to do from the origin switch.
      #return

    SpanningTreeNetwork.logger.info('Learned that {} can be found at switch {} port {}.'.format(event.packet.src, event.switch.dpid, in_port))
    self._teach_mac_location(event.switch, event.packet.src, in_port)


"""
Invoked by POX when SpanningTreeNetwork is specified as a module on the command line:
  $ ./pox csep561.net.spanning_tree_network
"""
def launch(**params):
  network = SpanningTreeNetwork(params)
  core.register('spanning_tree_network', network)

