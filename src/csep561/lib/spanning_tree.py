from pox.core import core

Infinity = float('inf')

"""
Constructs a spanning tree using Djikstra.
"""
class SpanningTree:

  logger = core.getLogger()

  """
  Creates a new spanning tree builder.  If uplink is specified,
  that link will be ignored.  This can be used to exclude a link
  that connects out of the local switch network, or one that connects
  to an already built tree (i.e. we're attaching a subtree).
  """
  def __init__(self, root, uplink = None):
    self.root = root
    self.uplink = uplink

  """
  Gets the list of links on the specified node that are traversable for the
  purposes of the spanning tree (i.e. not an uplink).
  """
  def _get_node_links(self, node):
    return filter(lambda x: x is not self.uplink, node.links)

  """
  Initializes all nodes in the network to the initial state for Djikstra.
  """
  def _initialize(self):
    nodes = [ self.root ]
    initialized_nodes = set()

    i = 0
    while i < len(nodes):
      node = nodes[i]
      node.distance = Infinity
      node.visited = False
      node.uplink = None
      initialized_nodes.add(node)

      # Add all switches this node is linked to, except those that we have
      # initialized.
      links = filter(lambda x: x.remote_switch not in initialized_nodes, self._get_node_links(node))
      nodes.extend([ x.remote_switch for x in links ])
      i += 1

    # The set of all initialized nodes is now our set of unvisited nodes.
    return initialized_nodes


  """
  Visit a node, according to Djikstra.
  """
  def _visit_node(self, node):
    if node.uplink:
      SpanningTree.logger.debug('Visiting switch {}. Uplink: [{}] => {}[{}] (distance = {})'.format(node.dpid, node.uplink.local_port, node.uplink.remote_switch.dpid, node.uplink.remote_port, node.distance))
    else:
      SpanningTree.logger.debug('Visiting switch {}. (distance = {})'.format(node.dpid, node.distance))

    distance = node.distance + 1

    for link in self._get_node_links(node):
      remote_node = link.remote_switch
      if remote_node.visited:
        continue

      # This link provides a shorter path to the node on the other end.
      if distance < remote_node.distance:
        SpanningTree.logger.debug('Updating distance for {} to {}.'.format(remote_node.dpid, distance))
        remote_node.distance = distance
        remote_node.uplink = link.reverse

    node.visited = True
    for link in node.links:
      if link is node.uplink:
        # If this link is what connects us to the rest of the tree, activate it.
        link.activate()
      elif link.is_active():
        # Otherwise, deactivate it (for now).
        link.deactivate()


  """
  Find the unvisited node with the lowest distance, to start the next round of
  Djikstra.
  """
  def _find_next_start(self, unvisited):
    next_start = None
    for node in unvisited:
      if next_start is None or node.distance < next_start.distance:
        next_start = node

    if next_start.distance == Infinity:
      # Should not happen - this means there are unconnected nodes in our node list.
      raise Exception('Unvisited node set contains only unlinked nodes.')
    return next_start


  """
  Build the spanning tree, updating link active status along the way.
  """
  def build(self):
    SpanningTree.logger.debug('Building spanning tree.')
    unvisited = self._initialize()
    visited = []
    SpanningTree.logger.debug('Unvisisted node list: {}'.format(', '.join([ str(x.dpid) for x in unvisited ])))

    if self.uplink:
      # If an uplink was specified, base the root's distance off the node on the
      # other end.  This happens when a segment of the network is first connected to
      # another segment that already has run the algorithm.
      self.root.uplink = self.uplink
      self.root.distance = self.uplink.remote_switch.distance + 1
    else:
      # Otherwise, just initialize the root node with distance 0.
      self.root.uplink = None
      self.root.distance = 0

    # Run Djikstra until all nodes have been visited.
    current = self.root
    while current is not None:
      self._visit_node(current)
      unvisited.remove(current)
      visited.append(current)
      if len(unvisited) == 0:
        current = None
      else:
        current = self._find_next_start(unvisited)
    SpanningTree.logger.debug('Finished building spanning tree.')
