import pox.openflow.libopenflow_01 as of
from pox.core import core
import pox.lib.packet as pkt
from pox.lib.recoco import Timer
from pox.lib.revent import Event, EventMixin

from ..lib.addresses import SpecialMacs
from .learning_switch import LearningSwitch, UnknownPacketSourceEvent


# TTL to use for outbound LLDP packets.
LLDP_TTL = 120

# Time to wait before assuming that we have heard back from all LLDP receivers.
DISCOVERY_TIMEOUT_PERIOD = 2


"""
Event raised when a new link is discovered between two switches.
"""
class LinkDiscoveryEvent(Event):

  def __init__(self, local_switch, local_port, remote_dpid, remote_port):
    Event.__init__(self)
    self.local_switch = local_switch
    self.local_port = local_port
    self.remote_dpid = remote_dpid
    self.remote_port = remote_port


"""
Learning switch with topology discovery via LLDP.
O
Referred to the openflow/discovery.py and openflow/spanning_tree.py POX modules for reference on using LLDP and ofp_port_mod().
"""
class LldpSwitch(LearningSwitch, EventMixin):

  logger = core.getLogger()
  _eventMixin_events = set([ LinkDiscoveryEvent, UnknownPacketSourceEvent ])


  def _activate(self):
    super(LldpSwitch, self)._activate()

    # Disable flooding on all links, so we don't spam packets all over the network.
    # We will activate them as we learn about topology.
    for port in self.get_ports():
      self.set_flood_status(port.port_no, False)

    # Start learning about our neighbors.
    self._discover_neighbors()


  """
  Send an LLDP packet out each port.  If there is an LldpSwitch on the other end, we
  will receive the packet there and learn about the link.
  """
  def _discover_neighbors(self):
    LldpSwitch.logger.debug('Discovering neighbors on switch {}.'.format(self.dpid))

    # Send an LLDP packet to discover switch links.  LLDP lets us include the switch
    # and port identity on this side, so when we receive the packet on the other
    # side we know about both ends of the link.
    for port in self.get_ports():
      LldpSwitch.logger.debug('Discovering neighbors on switch {} port {}.'.format(self.dpid, port.port_no))
      lldp_pkt = pkt.lldp()
      lldp_pkt.add_tlv(pkt.chassis_id(subtype = pkt.chassis_id.SUB_MAC, id = port.hw_addr.toRaw()))
      lldp_pkt.add_tlv(pkt.port_id(subtype = pkt.port_id.SUB_PORT, id = str(port.port_no)))
      lldp_pkt.add_tlv(pkt.ttl(ttl = LLDP_TTL))
      lldp_pkt.add_tlv(pkt.system_description(payload = bytes(self.dpid)))
      lldp_pkt.add_tlv(pkt.end_tlv())
      ether_wrapper = pkt.ethernet(type = pkt.ethernet.LLDP_TYPE, src = port.hw_addr,
        dst = SpecialMacs.LLDP_BROADCAST, payload = lldp_pkt)
      self._send_packet(ether_wrapper, port.port_no)

    Timer(DISCOVERY_TIMEOUT_PERIOD, self._activate_host_ports)


  """
  Activates flooding on ports that do NOT have links, since they might have hosts.
  """
  def _activate_host_ports(self):
    for port in filter(lambda x: not self.is_link_port(x.port_no), self.get_ports()):
      self.set_flood_status(port.port_no, True)

  """
  LLDP packets teach us about our neighboring switches, so we can dynamically learn the topology.
  """
  def _handle_lldp(self, event, ether_pkt, lldp_pkt):
    if len(lldp_pkt.tlvs) >= 4 and lldp_pkt.tlvs[1].tlv_type == pkt.lldp.PORT_ID_TLV and lldp_pkt.tlvs[1].subtype == pkt.port_id.SUB_PORT and lldp_pkt.tlvs[3].tlv_type == pkt.lldp.SYSTEM_DESC_TLV:
      local_port = event.ofp.in_port
      remote_port = int(lldp_pkt.tlvs[1].id)
      remote_dpid = int(lldp_pkt.tlvs[3].payload)
      self._packet_logger.action('LinkDiscoveryEvent', [
        ('Local Switch', self.dpid),
        ('Local Port', local_port),
        ('Remote Switch', remote_dpid),
        ('Remote Port', remote_port)
      ])
      self.raiseEvent(LinkDiscoveryEvent, self, local_port, remote_dpid, remote_port)
      return True

    return super(LldpSwitch, self)._handle_lldp(event, ether_pkt, lldp_pkt)


