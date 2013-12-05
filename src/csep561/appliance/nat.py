from pox.core import core

from ..device.lldp_switch import LldpSwitch
from ..net.spanning_tree_network import SpanningTreeNetwork


CONFIG_PARAM_UPLINK = 'uplink'

"""
A switch that acts as a NAT router.
"""
class NatRouter(LldpSwitch):

  def __init__(self, event, arp_table, uplink_port):
    self._uplink_port = uplink_port
    super(NatRouter, self).__init__(event, arp_table)


  def _get_discoverable_ports(self):
    return filter(lambda x: x.port_no != self._uplink_port, self.get_ports())


"""
A network appliance consisting of a spanning tree network with an uplink NAT router.
"""
class NatAppliance(SpanningTreeNetwork):

  logger = core.getLogger()

  def __init__(self, config):
    uplink = tuple(self._get_required_config(config, CONFIG_PARAM_UPLINK).split(','))
    self._uplink_switch = int(uplink[0])
    self._uplink_port = int(uplink[1])
    NatAppliance.logger.info('Uplink switch: {}; port: {}'.format(self._uplink_switch, self._uplink_port))
    super(NatAppliance, self).__init__()


  def _get_required_config(self, config, key):
    value = config.get(key)
    if value is None:
      raise Exception('Configuration parameter "{}" is required.'.format(key))
    return value


  def _create_node(self, connect_event):
    if connect_event.dpid == self._uplink_switch:
      return NatRouter(connect_event, self._arp_table, self._uplink_port)
    return super(NatAppliance, self)._create_node(connect_event)


"""
Invoked by POX when NatAppliance is specified as a module on the command line:
  $ ./pox csep561.appliance.nat
"""
def launch(**params):
  appliance = NatAppliance(params)
  core.register('nat', appliance)

