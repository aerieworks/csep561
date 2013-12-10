"""
Author:     Annabelle Richard <richanna@u.washington.edu>
Course:     CSEP 561 (Autumn, 2013)
Professor:  Arvind Krishnamurthy

Learning switch implemented using the POX SDN library.
"""

from traceback import format_exc

import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.addresses import EthAddr
from pox.lib.packet import arp, ethernet
from pox.lib.revent import EventMixin
from pox.lib.util import dpid_to_str

from ..lib.addresses import ArpTable, is_special_mac, SpecialIps, SpecialMacs
from ..lib.packet_logger import PacketLogger


# Default priority to assign to new flows.
DEFAULT_FLOW_PRIORITY = 10


"""
Switch that can learn how to route packets to specific ethernet MAC addresses.
"""
class LearningSwitch(EventMixin):

  logger = core.getLogger()

  def __init__ (self, event):
    self.dpid = dpid_to_str(event.dpid)
    self._arp_table = ArpTable(self.dpid)
    self._packet_logger = PacketLogger('packet.log.{dpid}'.format(dpid = self.dpid))
    self._port_for_mac = {}
    self.event = event
    self.connection = event.connection
    self._initialize()


  def __del__(self):
    LearningSwitch.logger.debug('Destroying instance for switch {}.'.format(self.dpid))
    try:
      self._packet_logger.close()
    except:
      LearningSwitch.logger.warn('Unable to close packet logger for {}: {}'.format(self.dpid, format_exc()))


  def _initialize(self):
    self._initialize_flow_table()
    self.listenTo(self.connection)


  """
  Installs initial flow table rules.
  """
  def _initialize_flow_table(self):
    # Install a rule routing all ARP requests through the controller.
    msg = of.ofp_flow_mod(priority = 100)
    msg.match = of.ofp_match(dl_type = ethernet.ARP_TYPE)
    msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
    self.connection.send(msg)


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
  def _drop_packet(self, event, reason = None):
    if reason is not None:
      self._packet_logger.action('DROP', reason)
    # Send a command without an action.  This causes the switch to drop the packet.
    msg = of.ofp_packet_out()
    msg.buffer_id = event.ofp.buffer_id
    msg.in_port = event.port
    self.connection.send(msg)


  """
  Gets the MAC address of the specified port on the switch.
  """
  def _get_mac_for_port(self, port_no):
    return self.connection.ports[port_no].hw_addr


  """
  Install a rule in the switch flow table to send traffic for the given MAC out on
  the given port.
  """
  def _install_mac_rule(self, mac, port_no):
    pass


  """
  Attempt to short-circuit ARP requests using the switch's ARP table.
  """
  def _handle_arp(self, event, ether_pkt, arp_pkt):
    # Update the ARP table with the info for the sender.
    self._packet_logger.action('Add ARP Entry', [
      ('IP Address', arp_pkt.protosrc), ('MAC Address', arp_pkt.hwsrc)
    ])
    self._arp_table.add(arp_pkt.protosrc, arp_pkt.hwsrc)
    if not is_special_mac(arp_pkt.hwdst):
      # If the hardware destination is a normal MAC address, add it to the ARP table.
      self._packet_logger.action('Add ARP Entry', [
        ('IP Address', arp_pkt.protodst), ('MAC Address', arp_pkt.hwdst)
      ])
      self._arp_table.add(arp_pkt.protodst, arp_pkt.hwdst)

    if arp_pkt.opcode == arp.REQUEST:
      # Try to find a known MAC address for the requested IP address and send a reply ourselves.
      requested_ip = arp_pkt.protodst
      requested_mac = self._arp_table.lookup(requested_ip)
      self._packet_logger.metric('ARP Target', [ ('IP', requested_ip), ('MAC', requested_mac) ])
      if requested_mac:
        self._packet_logger.action('ARP Reply', [
          ('Requested MAC', requested_mac),
          ('Out Port', event.ofp.in_port)
        ])
        arp_reply = arp(hwsrc = requested_mac, hwdst = arp_pkt.hwsrc, opcode = arp.REPLY, protosrc = requested_ip, protodst = arp_pkt.protosrc)
        ether = ethernet(type = ethernet.ARP_TYPE, dst = arp_pkt.hwsrc, src = requested_mac, payload = arp_reply)
        self._send_packet(ether, event.ofp.in_port)
        return True


  """
  Update our ARP table based on the IP packet.
  """
  def _handle_ip(self, event, ether_pkt, ip_pkt):
    self._arp_table.add(ip_pkt.srcip, ether_pkt.src)


  """
  Handle all packets with known destination MAC addresses by forwarding them
  to the mapped port.
  """
  def _handle_default(self, event, ether_pkt):
    dst_port = self.get_port_for_mac(ether_pkt.dst)
    if dst_port:
      self._packet_logger.action('FORWARD', [ ('Out Port', dst_port) ])
    else:
      dst_port = of.OFPP_FLOOD
      self._packet_logger.action('FLOOD', 'Unknown destination MAC address')

    self._send_packet(event.ofp, dst_port)


  """
  Check for unknown source MAC addresses in packets.
  """
  def _handle_packet(self, event, ether_pkt):
    self.learn_mac_location(ether_pkt.src, event.ofp.in_port)

    handled = False
    if ether_pkt.type == ethernet.ARP_TYPE:
      handled = self._handle_arp(event, ether_pkt, ether_pkt.payload)
    elif ether_pkt.type == ethernet.IP_TYPE:
      handled = self._handle_ip(event, ether_pkt, ether_pkt.payload)

    if not handled:
      self._handle_default(event, ether_pkt)


  """
  Event handler triggered when the switch sends us a packet it does not know how to handle.
  """
  def _handle_PacketIn(self, event):
    ether_pkt = event.parse()
    try:
      self._packet_logger.new_packet(self.dpid, event.ofp, ether_pkt)
    except:
      LearningSwitch.logger.error('Exception opening packet log entry: {}'.format(format_exc()))

    try:
      self._handle_packet(event, ether_pkt)
    except Exception as ex:
      LearningSwitch.logger.error(format_exc())
      try:
        self._packet_logger.metric('Error', [ ('Type', type(ex).__name__), ('Message', ex.message) ])
      except:
        LearningSwitch.logger.error('Exception logging error to packet log: {}'.format(format_exc()))

    try:
      self._packet_logger.end_packet()
    except:
      LearningSwitch.logger.error('Exception closing packet log entry: {}'.format(format_exc()))



  """
  Gets the switch port through which the specified MAC address can be reached,
  or None if the MAC address is unknown.
  """
  def get_port_for_mac(self, mac):
    return self._port_for_mac.get(str(mac))


  """
  Teaches the switch on which port to send traffic for the specified MAC address.
  """
  def learn_mac_location(self, mac, port_no):
    if is_special_mac(mac) or port_no > of.OFPP_MAX:
      # Do not learn locations for "special" MAC addresses (e.g. broadcast
      # addresses) or ports (e.g. FLOOD).
      return

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
    msg = of.ofp_flow_mod(priority = DEFAULT_FLOW_PRIORITY)
    msg.match.dl_dst = EthAddr(mac)
    msg.actions.append(of.ofp_action_output(port = port_no))
    self.connection.send(msg)

