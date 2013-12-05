from pox.core import core

Infinity = float('inf')

_logger = core.getLogger()


"""
A node in a graph, as required for Dijkstra's algorithm.
"""
class DijkstraNode:

  def __init__(self, name, neighbors = []):
    self.name = name
    self.distance = None
    self.visited = False

    self.best = None
    self.neighbors = set(neighbors)
    for node in neighbors:
      node.neighbors.add(self)


"""
Initializes all nodes in the graph set to the start state for Dijkstra's algorithm.
"""
def _initialize_graph_state(graph):
  for node in graph:
    node.distance = Infinity
    node.visited = False


"""
Find the unvisited node with the lowest distance, to start the next round of
Dijkstra's algorithm.
"""
def _find_next_start(unvisited):
  next_start = None
  for node in unvisited:
    if next_start is None or node.distance < next_start.distance:
      next_start = node

  if next_start.distance == Infinity:
    _logger.debug('No connected nodes left in unvisited set.')
    return None

  return next_start


"""
Visits a node, according to Dijkstra.
"""
def _visit_node(node):
  distance = node.distance + 1
  best_name = node.best.name if node.best else None
  _logger.debug('Visiting node {}. Distance = {} ({})'.format(node.name, node.distance, best_name))

  for neighbor in node.neighbors:
    if neighbor.visited:
      continue

    # This link provides a shorter path to the node on the other end.
    if distance < neighbor.distance:
      _logger.debug('Updating distance for {} to {}.'.format(neighbor.name, distance))
      neighbor.distance = distance
      neighbor.best = node

  node.visited = True


"""
Finds the shortest path from the specified root node to all nodes in the graph set.
"""
def find_shortest_paths(root, graph, root_distance = 0):
  _logger.debug('Finding shortest paths from {}.'.format(root.name))
  _initialize_graph_state(graph)
  unvisited = set(graph)
  visited = []
  _logger.debug('Unvisisted node list: {}'.format(', '.join([ str(x.name) for x in unvisited ])))

  root.distance = root_distance

  # Run Dijkstra until all nodes have been visited.
  current = root
  while current is not None:
    _visit_node(current)
    unvisited.remove(current)
    visited.append(current)
    if len(unvisited) == 0:
      _logger.debug('Out of unvisited nodes.')
      current = None
    else:
      current = _find_next_start(unvisited)
  _logger.debug('Finished finding shortest paths.')

  return { x.name: x.best for x in visited }


