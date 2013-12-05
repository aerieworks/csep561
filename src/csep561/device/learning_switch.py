import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.addresses import EthAddr
from pox.lib.revent import Event, EventMixin

from ..lib.addresses import is_special_mac
from .switch import Switch


# Default priority to assign to new flows.
DEFAULT_FLOW_PRIORITY = 10


"""
Event raised when a switch encounters a packet whose source MAC address is not known
to the switch.
"""
class UnknownPacketSourceEvent(Event):

  def __init__(self, switch, event, packet):
    Event.__init__(self)
    self.switch = switch
    self.event = event
    self.packet = packet


"""
Switch that can learn how to route packets to specific ethernet MAC addresses.
"""
class LearningSwitch(Switch, EventMixin):

  logger = core.getLogger()

  _eventMixin_events = set([ UnknownPacketSourceEvent ])

  def __init__ (self, event, arp_table):
    self._port_for_mac = {}
    super(LearningSwitch, self).__init__(event, arp_table)


  """
  Handle all packets with known destination MAC addresses by forwarding them
  to the mapped port.
  """
  def _handle_default(self, event, ether_pkt):
    dst_port = self.get_port_for_mac(ether_pkt.dst)
    if dst_port:
      self._send_packet(event.ofp, dst_port)
      self._packet_logger.action('FORWARD', [ ('Out Port', dst_port) ])
    else:
      super(LearningSwitch, self)._handle_default(event, ether_pkt)


  """
  Check for unknown source MAC addresses in packets.
  """
  def _handle_packet(self, event, ether_pkt):
    mac = ether_pkt.src
    if not is_special_mac(mac) and self.get_port_for_mac(mac) is None:
      self.raiseEvent(UnknownPacketSourceEvent(self, event, ether_pkt))
    super(LearningSwitch, self)._handle_packet(event, ether_pkt)


  """
  Gets the switch port through which the specified MAC address can be reached,
  or None if the MAC address is unknown.
  """
  def get_port_for_mac(self, mac):
    return self._port_for_mac.get(str(mac))


  """
  Teaches the switch on which port to send traffic for the specified MAC address.
  """
  def learn_mac_location(self, mac, port_no, priority = DEFAULT_FLOW_PRIORITY):
    if is_special_mac(mac):
      # Do not learn locations for "special" MAC addresses (e.g. broadcast addresses).
      return

    # Make sure the port actually exists on the switch.
    port_mac = self._get_mac_for_port(port_no)
    if port_mac is None:
      raise Exception('Port {} does not exist on this switch ({}).'.format(port_no, self.dpid))

    old_port_no = self.get_port_for_mac(mac)
    if old_port_no == port_no:
      # We already know the location of this MAC address.
      return

    # Keep track of what we have learned.
    LearningSwitch.logger.info('switch-{}: MAC address {} can be found at port {}.'.format(self.dpid, mac, port_no))
    if old_port_no is not None:
      LearningSwitch.logger.info('Overwriting previous location at port {}.'.format(old_port_no))
    self._port_for_mac[str(mac)] = port_no

    # Teach it to the switch flow table.
    LearningSwitch.logger.info('switch-{}: Installing flow: Dest MAC {} => Output Port {} (priority = {}).'.format(self.dpid, mac, port_no, priority))
    msg = of.ofp_flow_mod(priority = priority)
    msg.match.dl_dst = EthAddr(mac)
    msg.actions.append(of.ofp_action_output(port = port_no))
    self.connection.send(msg)


