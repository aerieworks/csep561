import weakref
from traceback import format_exc

import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.packet import arp, ethernet
from pox.lib.recoco import Timer
from pox.lib.revent import Event, EventMixin

from ..lib.addresses import SpecialIps, SpecialMacs
from ..lib.packet_logger import PacketLogger


# Default format to use for packet log file.
DEFAULT_PACKET_LOG_FILE_PATH_FORMAT = 'packet.log.{dpid}'


# How long to wait in seconds before refreshing switch features after port
# modifications.
FEATURE_REFRESH_PERIOD = 2


"""
Event raised when a link is activated.
"""
class LinkActivatedEvent(Event):

  def __init__(self, link):
    super(LinkActivatedEvent, self).__init__()
    self.link = link


"""
Event raised when a link is deactivated.
"""
class LinkDeactivatedEvent(Event):

  def __init__(self, link):
    super(LinkDeactivatedEvent, self).__init__()
    self.link = link


"""
Represents a link between two switches.
"""
class Link(EventMixin):

  _eventMixin_events = set([ LinkActivatedEvent, LinkDeactivatedEvent ])

  def __init__(self, port, switch):
    self.port = port
    self.switch = switch
    self._is_active = True
    self._reverse = None

  def get_reverse(self):
    return self._reverse()

  def set_reverse(self, reverse):
    self._reverse = weakref.ref(reverse)
    reverse._reverse = weakref.ref(self)

  def is_active(self):
    return self._is_active

  def activate(self):
    self._is_active = True
    self.raiseEvent(LinkActivatedEvent, self)
    reverse = self.get_reverse()
    if reverse and not reverse.is_active():
      reverse.activate()

  def deactivate(self):
    self._is_active = False
    self.raiseEvent(LinkDeactivatedEvent, self)
    reverse = self.get_reverse()
    if reverse and reverse.is_active():
      reverse.deactivate()


"""
Basic switch that hardly deserves the name.  This should be extended by a class
that implements more intelligent behavior.
"""
class Switch():

  logger = core.getLogger()

  def __init__ (self, event, arp_table):
    self._arp_table = arp_table
    self._packet_logger = PacketLogger(DEFAULT_PACKET_LOG_FILE_PATH_FORMAT.format(dpid = event.dpid))
    self._link_ports = set()
    self._feature_refresh_timer = None

    self.links = []
    self.dpid = event.dpid
    self.event = event
    self.connection = event.connection

    self._activate()


  def _activate(self):
    self.listenTo(self.connection)

    # Install a rule routing all ARP requests through the controller.
    msg = of.ofp_flow_mod(priority = 100)
    msg.match = of.ofp_match(dl_type = ethernet.ARP_TYPE)
    msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
    self.connection.send(msg)


  def __del__(self):
    Switch.logger.debug('Destroying instance for switch {}.'.format(self.dpid))
    try:
      self._packet_logger.close()
    except:
      Switch.logger.warn('Unable to close packet logger for {}: {}'.format(self.dpid, format_exc()))


  """
  Sends the specified packet out on the specified port on the switch.
  """
  def _send_packet(self, packet_in, out_port):
    msg = of.ofp_packet_out(data = packet_in)
    msg.actions.append(of.ofp_action_output(port = out_port))
    self.connection.send(msg)


  """
  Drops the packet.
  """
  def _drop_packet(self, event, reason):
    self._packet_logger.action('DROP', reason)
    # Send a command without an action.  This causes the switch to drop the packet.
    msg = of.ofp_packet_out()
    msg.buffer_id = event.ofp.buffer_id
    msg.in_port = event.port
    self.connection.send(msg)


  def _refresh_features(self):
    # Not sure if this is strictly necessary; pulled from openflow/spanning_tree.py
    # We do this after we adjust link state via ofp_port_mod commands.
    Switch.logger.info('switch-{}: Refreshing features.'.format(self.dpid))
    self.connection.send(of.ofp_barrier_request())
    self.connection.send(of.ofp_features_request())


  def _schedule_feature_refresh(self):
    if self._feature_refresh_timer is not None:
      # Already have a refresh scheduled.
      return
    self._feature_refresh_timer = Timer(FEATURE_REFRESH_PERIOD, self._refresh_features)


  """
  Gets the MAC address of the specified port on the switch.
  """
  def _get_mac_for_port(self, port_no):
    return self.connection.ports[port_no].hw_addr


  def _handle_LinkActivatedEvent(self, event):
    # Turn on flooding on the activated link.
    self.set_flood_status(event.link.port, True)


  def _handle_LinkDeactivatedEvent(self, event):
    # Turn off flooding on the deactivated link.
    self.set_flood_status(event.link.port, False)

    # Remove any flow table rules that sent packets across the deactivated link.
    msg = of.ofp_flow_mod(command = of.OFPFC_DELETE, out_port = event.link.port)
    self.connection.send(msg)


  """
  Attempt to short-circuit ARP requests using the switch's ARP table.
  """
  def _handle_arp(self, event, ether_pkt, arp_pkt):
    src_ip = arp_pkt.protosrc
    src_mac = ether_pkt.src
    # Update the ARP table with the info for the sender.
    self._arp_table.add(src_ip, src_mac)

    if arp_pkt.opcode == arp.REQUEST:
      # Try to find a known MAC address for the requested IP address and send a reply ourselves.
      requested_ip = arp_pkt.protodst
      requested_mac = self._arp_table.lookup(requested_ip)
      self._packet_logger.metric('ARP Target', [ ('IP', requested_ip), ('MAC', requested_mac) ])
      if requested_mac:
        self._packet_logger.action('ARP Reply', [ ('Requested MAC', requested_mac) ])
        arp_reply = arp(hwsrc = requested_mac, hwdst = src_mac, opcode = arp.REPLY, protosrc = requested_ip, protodst = src_ip)
        ether = ethernet(type = ethernet.ARP_TYPE, dst = src_mac, src = requested_mac, payload = arp_reply)
        self._send_packet(ether, event.ofp.in_port)
        return True


  """
  Update our ARP table based on the IP packet.
  """
  def _handle_ip(self, event, ether_pkt, ip_pkt):
    self._arp_table.add(ip_pkt.srcip, ether_pkt.src)

    # If this packet was sent to the controller, that means the switch doesn't have a rule for the destination MAC address.
    dst_arp_entry = self._arp_table.lookup(ip_pkt.dstip)
    if dst_arp_entry is None:
      # Our ARP table doesn't contain the destination MAC address, but the sender knows about it.
      Switch.logger.info('switch-{}: No ARP table entry for {}. Packet says it is {}.  Sending ARP request.'.format(self.dpid, ip_pkt.dstip, ether_pkt.dst))

      # Flood an ARP request for the destination IP.  The reply will let us update our ARP table and MAC-to-port table.
      # But, only do it if this came from a host; this packet will be flooded through the network, and we don't need every switch to send an ARP probe.
      if event.ofp.in_port not in [ x.local_port for x in self.links ]:
        self._packet_logger.action('ARP Probe', [ ('Target IP', ip_pkt.dstip), ('Expected MAC', ether_pkt.dst) ])

        src_mac = self._get_mac_for_port(event.ofp.in_port)
        arp_probe = arp(
          opcode = arp.REQUEST,
          hwsrc = src_mac,
          hwdst = SpecialMacs.ARP_REQUEST_TARGET,
          protosrc = SpecialIps.ARP_PROBE_SENDER,
          protodst = ip_pkt.dstip)
        ether = ethernet(type = ethernet.ARP_TYPE, dst = SpecialMacs.ARP_REQUEST_TARGET, src = src_mac, payload = arp_probe)
        self._send_packet(ether, of.OFPP_FLOOD)


  """
  Drops LLDP packets.
  """
  def _handle_lldp(self, event, ether_pkt, lldp_pkt):
    self._drop_packet(event, 'LLDP packets should not be forwarded by the switch.')
    return True


  """
  Handle all otherwise unhandled packets by flooding them.
  """
  def _handle_default(self, event, ether_pkt):
    dst_port = of.OFPP_FLOOD
    self._packet_logger.action('FLOOD', 'Unknown destination MAC address')
    self._send_packet(event.ofp, dst_port)


  """
  Handle ethernet packets.
  """
  def _handle_packet(self, event, ether_pkt):
    handled = False
    if ether_pkt.type == ethernet.ARP_TYPE:
      handled = self._handle_arp(event, ether_pkt, ether_pkt.payload)
    elif ether_pkt.type == ethernet.LLDP_TYPE:
      handled = self._handle_lldp(event, ether_pkt, ether_pkt.payload)
    elif ether_pkt.type == ethernet.IP_TYPE:
      handled = self._handle_ip(event, ether_pkt, ether_pkt.payload)

    if not handled:
      self._handle_default(event, ether_pkt)


  """
  Event handler triggered when the switch sends us a packet it does not know how to handle.
  """
  def _handle_PacketIn(self, event):
    ether_pkt = event.parse()

    self._packet_logger.new_packet(self.dpid, event.ofp.in_port, ether_pkt)
    try:
      self._handle_packet(event, ether_pkt)
    except Exception as ex:
      Switch.logger.error(format_exc())
      self._packet_logger.metric('Error', [ ('Type', type(ex).__name__), ('Message', ex.message) ])


  """
  Gets an iterable list of ports on the switch.
  """
  def get_ports(self):
    ports = self.connection.ports.itervalues()
    return filter(lambda x: x.port_no <= of.OFPP_MAX, ports)


  """
  Gets whether or not the specified port is a link to another switch.
  """
  def is_link_port(self, port_no):
    return port_no in self._link_ports


  """
  Adds a link to the switch.
  """
  def add_link(self, port, switch, remote_port):
    # Make sure the local and remote ports are not already in use.
    for link in self.links:
      if link.port == port:
        if link.switch is not switch or link.get_reverse().port != remote_port:
          # This local port is in use, and used to link to another switch or port.
          raise Exception('Found link on already linked local port: {}[{}] => {}[{}]'.format(self.dpid, port, switch.dpid, remote_port))
        # We already know about this link.
        return

    for reverse in switch.links:
      if reverse.port == remote_port:
        if reverse.switch is not self or reverse.get_reverse().port != port:
          # The remote port is in use, and does not link to this switch and port.
          raise Exception('Found link on already linked remote port: {}[{}] => {}[{}]'.format(self.dpid, port, switch.dpid, remote_port))


    link = Link(port, switch)
    reverse = Link(remote_port, self)
    link.set_reverse(reverse)
    self.links.append(link)
    self._link_ports.add(link.port)
    link.addListeners(self)
    switch.links.append(reverse)
    switch._link_ports.add(reverse.port)
    reverse.addListeners(switch)


  """
  Sets the whether or not packets should be flooded out the specified port.
  """
  def set_flood_status(self, port_no, should_flood):
    # Make sure the port actually exists on the switch.
    hw_addr = self._get_mac_for_port(port_no)
    if hw_addr is None:
      raise Exception('Port {} does not exist on this switch ({}).'.format(port_no, self.dpid))

    if should_flood:
      config_flags = 0
      message = 'Enabling'
    else:
      config_flags = of.OFPPC_NO_FLOOD
      message = 'Disabling'

    Switch.logger.info('{} flooding on switch {} port {}.'.format(message, self.dpid, port_no))
    port_mod = of.ofp_port_mod(
      port_no = port_no,
      hw_addr = hw_addr,
      config = config_flags,
      mask = of.OFPPC_NO_FLOOD)
    self.connection.send(port_mod)

    # Update our connection's view of switch port statuses.
    self._schedule_feature_refresh()


