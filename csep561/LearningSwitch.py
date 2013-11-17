"""
Author:     Annabelle Richard <richanna@u.washington.edu>
Course:     CSEP 561 (Autumn, 2013)
Professor:  Arvind Krishnamurthy

A basic learning switch that learns which port a MAC address is reachable on, and pushes forwarding rules based on that information.  When the controller receives a packet, it stores the packet's source MAC address and switch port in a mapping table.  If the mapping table contains an entry for the destination MAC address, the controller pushes a forwarding rule to the switch, instructing it to foward all packets with the packet's destination MAC address to the switch port in the mapping table.  If the port for the destination MAC address is not known, the controller instructs the switch to flood the packet.

Based on the L2 learning switch skeleton by Junaid Khalid (http://courses.cs.washington.edu/courses/csep561/13au/projects/LearningSwitch.txt) and the misc.Tutorial module distributed with POX.
"""

from datetime import datetime
import logging

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *


"""
Switch logic that learns which port each MAC address is reachable on and installs fowarding rules based on that knowledge.
"""
class LearningSwitch (EventMixin):

  logger = core.getLogger()

  def __init__ (self, connection):
    # The MAC address-to-port mapping table.  Keys are MAC addresses, values are the switch port on which that MAC address can be reached.
    self.mac_to_port = {}

    # The ARP table to use to optimize ARP replies on the network (IPv4 only).  Keys are IPv4 addresses, values are MAC addresses.
    self.arp_table = {}

    self.connection = connection
    self.listenTo(connection)

    self.info('connected')


  """
  Sends the specified packet out on the specified port on the switch.
  """
  def _send_packet(self, packet_in, out_port):
    msg = of.ofp_packet_out(data = packet_in)
    msg.actions.append(of.ofp_action_output(port = out_port))
    self.connection.send(msg)


  """
  Updates the MAC address => switch port mapping table based on the packet's source data.
  """
  def _update_mac_to_port_mapping(self, packet, ofp):
    src_mac = str(packet.src)
    src_switch_port = ofp.in_port

    # Make sure our mapping for the source MAC address is accurate.
    prev_src_mapping = self.mac_to_port.get(src_mac)
    if prev_src_mapping != src_switch_port:
      if prev_src_mapping == None:
        # We haven't seen the sender before.
        self.info('mapping', src_mac = src_mac, src_port = src_switch_port)
      else:
        # The sender may have moved to a different location on the network.
        self.info('updating', src_mac = src_mac, old_port = prev_src_mapping, new_port = src_switch_port)
      self.mac_to_port[src_mac] = src_switch_port


  """
  Teaches the switch where to forward packets with the given packet's destination, if the port mapping is known.  If not, floods the packet.
  """
  def handle_default_packet(self, packet, ofp):
    dst_mac = str(packet.dst)
    dst_mapping = self.mac_to_port.get(dst_mac)
    if dst_mapping != None:
      # We know how to reach this destination.  Teach it to the switch.
      self.info('installing flow', dst_mac = dst_mac, dst_port = dst_mapping)
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match(dl_dst = packet.dst)
      msg.actions.append(of.ofp_action_output(port = dst_mapping))
      self.connection.send(msg)

      # Send this packet out on the correct port.
      self.debug('resending', src_mac = packet.src, src_port = ofp.in_port, dst_mac = dst_mac, dst_port = dst_mapping)
      self._send_packet(ofp, dst_mapping)
    else:
      # Since we don't know where the destination MAC address can be reached, flood the packet.  If the destination exists on the network, it should receive the packet.
      self.debug('flooding', src_mac = packet.src, src_port = ofp.in_port, dst_mac = dst_mac)
      self._send_packet(ofp, of.OFPP_FLOOD)


  """
  Drops LLDP packets, since we don't need to forward them beyond the switch.
  """
  def handle_lldp_packet(self, packet, ofp):
    # LLDP packets do not need to be forwarded.
    # Send a command without an action.  This causes the switch to drop it.
    msg = of.ofp_packet_out()
    msg.buffer_id = event.ofp.buffer_id
    msg.in_port = event.port
    self.connection.send(msg)


  """
  Event handler triggered when the switch sends us a packet it does not know how to handle.
  """
  def _handle_PacketIn(self, event):
    packet = event.parse()

    self.debug('received', type = packet.getNameForType(packet.type), src_mac = packet.src, src_port = event.ofp.in_port, dst_mac = packet.dst)
    self._update_mac_to_port_mapping(packet, event.ofp)

    if packet.type == packet.LLDP_TYPE:
      self.handle_lldp_packet(packet, event.ofp)
    else:
      self.handle_default_packet(packet, event.ofp)


  """
  Logs a debug message with a timestamp and switch name.
  """
  def debug(self, message, **properties):
    self.log(logging.DEBUG, message, **properties)


  """
  Logs an info message with a timestamp and switch name.
  """
  def info(self, message, **properties):
    self.log(logging.INFO, message, **properties)


  """
  Logs a message with a timestamp and switch name at the specified log level.
  """
  def log(self, level, message, **properties):
    prefix = ' - '.join([
      datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f'),
      str(self.connection),
      message
    ])
    prop_keys = sorted(properties.keys(), cmp = compare_log_properties)
    parts = ["{}: {}".format(k, properties[k]) for k in prop_keys]
    parts.insert(0, prefix)

    LearningSwitch.logger.log(level, '; '.join(parts))


"""
Creates a new LearningSwitch instance when a switch connects to the controller.
"""
class LearningSwitchManager(EventMixin):

  def __init__(self):
    self.listenTo(core.openflow)

  def _handle_ConnectionUp (self, event):
    LearningSwitch(event.connection)


"""
Invoked by POX when learning_switch is specified as a module on the command line:
  $ ./pox LearningSwitch
"""
def launch():
  core.registerNew(LearningSwitchManager)


log_property_order = {
    'type': 1,
    'src_mac': 2,
    'src_port': 3,
    'dst_mac': 4,
    'dst_port': 5
}

"""
Compares two properties for ordering in log messages, based on a predefined sort order for known properties.
"""
def compare_log_properties(a, b):
  # Sort recognized properties according to their defined order.
  if a in log_property_order:
    if b in log_property_order:
      return cmp(log_property_order[a], log_property_order[b])
    return -1
  elif b in log_property_order:
    return 1

  # Sort other properties alphabetically.
  return cmp(a, b)


