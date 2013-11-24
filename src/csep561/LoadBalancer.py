"""
Author:     Annabelle Richard <richanna@u.washington.edu>
Course:     CSEP 561 (Autumn, 2013)
Professor:  Arvind Krishnamurthy

Load balancer network appliance implemented using the POX SDN library.
"""

import struct
from time import time
from traceback import format_exc

import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet import arp, echo, ethernet, icmp, ipv4, lldp, chassis_id, port_id, ttl, end_tlv, system_description, TYPE_ECHO_REPLY, TYPE_ECHO_REQUEST
from pox.lib.recoco import Timer
from pox.lib.revent import *

from lib.addresses import ArpTable, SpecialIps, SpecialMacs, is_special_mac
from lib.packet_logger import PacketLogger
from lib.spanning_tree import Infinity, SpanningTree


def get_time_in_ms():
  return long(time() * 1000)


"""
Represents a host in the load balancer fleet.
"""
class Host:
  def __init__(self, ip_address):
    self.ip_address = IPAddr(ip_address)
    self.is_healthy = False
    self.last_check_reply = 0


"""
Represents a link between two switches.
"""
class Link:
  def __init__(self, local_port, remote_switch, remote_port):
    self.local_port = local_port
    self.remote_switch = remote_switch
    self.remote_port = remote_port
    self._is_active = True
    self.reverse = None

  def is_active(self):
    return self._is_active

  def activate(self):
    self._is_active = True
    if self.reverse and not self.reverse.is_active():
      self.reverse.activate()

  def deactivate(self):
    self._is_active = False
    if self.reverse and self.reverse.is_active():
      self.reverse.deactivate()


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
Switch with topology discovery via LLDP and routing via spanning tree.

Referred to the openflow/discovery.py and openflow/spanning_tree.py POX modules for reference on using LLDP and ofp_port_mod().
"""
class SpanningTreeSwitch(EventMixin):

  # Default priority to assign to new flows.
  DEFAULT_FLOW_PRIORITY = 10

  # How long to wait for LLDP responses before assuming we've heard from all neighboring switches.
  # During this delay, the switch will not respond to any packets, to prevent mucking up the existing tree.
  LLDP_LISTEN_DELAY = 2
  LLDP_TTL = 120

  # How long to wait before refreshing switch features after port modifications.
  FEATURE_REFRESH_PERIOD = 2

  logger = core.getLogger()

  _eventMixin_events = set([ LinkDiscoveryEvent ])

  def __init__ (self, event, arp_table, packet_logger):
    # For Djikstra, used to calculate spanning tree.
    self.distance = None
    self.visited = False

    self.dpid = event.dpid
    self.is_active = False
    self.connection = event.connection
    self.packet_logger = packet_logger
    self._arp_table = arp_table
    self.mac_to_port = {}
    self.links = []
    self.uplink = None
    self.feature_refresh_timer = None
    self.listenTo(event.connection)
    self._discover_neighbors()


  def _refresh_features(self):
    # Not sure if this is strictly necessary; pulled from openflow/spanning_tree.py
    # We do this after we adjust link state via ofp_port_mod commands.
    SpanningTreeSwitch.logger.info('switch-{}: Refreshing features.'.format(self.dpid))
    self.connection.send(of.ofp_barrier_request())
    self.connection.send(of.ofp_features_request())


  def _schedule_feature_refresh(self):
    if self.feature_refresh_timer is not None:
      # Already have a refresh scheduled.
      return
    self.feature_refresh_timer = Timer(SpanningTreeSwitch.FEATURE_REFRESH_PERIOD, self._refresh_features)


  """
  Sends the specified packet out on the specified port on the switch.
  """
  def _send_packet(self, packet_in, out_port):
    msg = of.ofp_packet_out(data = packet_in)
    msg.actions.append(of.ofp_action_output(port = out_port))
    self.connection.send(msg)


  """
  Tells the switch to drop the packet.
  """
  def _drop_packet(self, event, reason):
    self.packet_logger.action('DROP', reason)
    # Send a command without an action.  This causes the switch to drop the packet.
    msg = of.ofp_packet_out()
    msg.buffer_id = event.ofp.buffer_id
    msg.in_port = event.port
    self.connection.send(msg)


  """
  Send an LLDP packet out each port.  If there is a switch on the other end, it will send
  the packet to the controller, and we will learn about the link.
  """
  def _discover_neighbors(self):
    # Send an LLDP packet to discover switch links.  LLDP lets us include the switch and port identity on this side,
    # so when we receive the packet on the other side we know about both ends of the link.
    ports = filter(lambda x: x.port_no <= of.OFPP_MAX, self.connection.ports.itervalues())
    for port in ports:
      lldp_pkt = lldp()
      lldp_pkt.add_tlv(chassis_id(subtype = chassis_id.SUB_MAC, id = port.hw_addr.toRaw()))
      lldp_pkt.add_tlv(port_id(subtype = port_id.SUB_PORT, id = str(port.port_no)))
      lldp_pkt.add_tlv(ttl(ttl = SpanningTreeSwitch.LLDP_TTL))
      lldp_pkt.add_tlv(system_description(payload = bytes(self.dpid)))
      lldp_pkt.add_tlv(end_tlv())
      ether_wrapper = ethernet(type = ethernet.LLDP_TYPE, src = port.hw_addr, dst = SpecialMacs.LLDP_BROADCAST, payload = lldp_pkt)
      self._send_packet(ether_wrapper, port.port_no)
    Timer(SpanningTreeSwitch.LLDP_LISTEN_DELAY, self._activate)


  """
  Performs final initialization necessary before we are ready to handle packets.
  """
  def _activate(self):
    self.is_active = True
    self._update_active_links()

    # Install a rule routing all ARP requests through the controller.
    msg = of.ofp_flow_mod(priority = 100)
    msg.match.dl_type = 0x806
    msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
    self.connection.send(msg)


  """
  Activate/deactivate links on the switch, based on the results of the spanning tree algorithm.
  """
  def _update_active_links(self):
    for link in self.links:
      port_no = link.local_port
      hw_addr = self._get_mac_for_port(port_no)

      # Enable flooding on active links; disable on inactive links.
      if link.is_active():
        config_flags = 0
        message = 'Enabling'
      else:
        config_flags = of.OFPPC_NO_FLOOD
        message = 'Disabling'

      SpanningTreeSwitch.logger.info('{} flooding on switch {} port {}.'.format(message, self.dpid, port_no))
      port_mod = of.ofp_port_mod(
        port_no = port_no,
        hw_addr = hw_addr,
        config = config_flags,
        mask = of.OFPPC_NO_FLOOD)
      self.connection.send(port_mod)

    self._schedule_feature_refresh()


  """
  Gets the MAC address of the specified port on the switch.
  """
  def _get_mac_for_port(self, port_no):
    return self.connection.ports[port_no].hw_addr


  """
  Gets the switch port through which the specified MAC address can be reached,
  or None if the MAC address is unknown.
  """
  def _get_port_for_mac(self, mac):
    return self.mac_to_port.get(str(mac))


  """
  Attempt to short-circuit ARP requests using the switch's ARP table.
  """
  def _handle_arp(self, ether_pkt, arp_pkt, event):
    self.packet_logger.metric('Handler', 'ARP')

    src_ip = arp_pkt.protosrc
    src_mac = ether_pkt.src
    # Update the ARP table with the info for the sender.
    self._arp_table.add(src_ip, src_mac)

    if arp_pkt.opcode == arp.REQUEST:
      # Try to find a known MAC address for the requested IP address and send a reply ourselves.
      requested_ip = arp_pkt.protodst
      requested_mac = self._arp_table.lookup(requested_ip)
      self.packet_logger.metric('ARP Target', [ ('IP', requested_ip), ('MAC', requested_mac) ])
      if requested_mac:
        self.packet_logger.action('ARP Reply', [ ('Requested MAC', requested_mac) ])
        arp_reply = arp(hwsrc = requested_mac, hwdst = src_mac, opcode = arp.REPLY, protosrc = requested_ip, protodst = src_ip)
        ether = ethernet(type = ethernet.ARP_TYPE, dst = src_mac, src = requested_mac, payload = arp_reply)
        self._send_packet(ether, event.ofp.in_port)
        return True


  """
  Update our ARP table based on the IP packet.
  """
  def _handle_ip(self, ether_pkt, ip_pkt, event):
    self._arp_table.add(ip_pkt.srcip, ether_pkt.src)

    # If this packet was sent to the controller, that means the switch doesn't have a rule for the destination MAC address.
    dst_arp_entry = self._arp_table.lookup(ip_pkt.dstip)
    if dst_arp_entry is None:
      # Our ARP table doesn't contain the destination MAC address, but the sender knows about it.
      SpanningTreeSwitch.logger.info('switch-{}: No ARP table entry for {}. Packet says it is {}.  Sending ARP request.'.format(self.dpid, ip_pkt.dstip, ether_pkt.dst))

      # Flood an ARP request for the destination IP.  The reply will let us update our ARP table and MAC-to-port table.
      # But, only do it if this came from a host; this packet will be flooded through the network, and we don't need every switch to send an ARP probe.
      if event.ofp.in_port not in [ x.local_port for x in self.links ]:
        self.packet_logger.action('ARP Probe', [ ('Target IP', ip_pkt.dstip), ('Expected MAC', ether_pkt.dst) ])

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
  LLDP packets teach us about our neighboring switches, so we can dynamically learn the topology.
  """
  def _handle_lldp(self, ether_pkt, lldp_pkt, event):
    if len(lldp_pkt.tlvs) >= 4 and lldp_pkt.tlvs[1].tlv_type == lldp.PORT_ID_TLV and lldp_pkt.tlvs[1].subtype == port_id.SUB_PORT and lldp_pkt.tlvs[3].tlv_type == lldp.SYSTEM_DESC_TLV:
      local_port = event.ofp.in_port
      remote_port = int(lldp_pkt.tlvs[1].id)
      remote_dpid = int(lldp_pkt.tlvs[3].payload)
      self.packet_logger.action('LinkDiscoveryEvent', [
        ('Local Switch', self.dpid),
        ('Local Port', local_port),
        ('Remote Switch', remote_dpid),
        ('Remote Port', remote_port)
      ])
      self.raiseEvent(LinkDiscoveryEvent, self, local_port, remote_dpid, remote_port)
    else:
      self._drop_packet(event, 'Unknown LLDP packet.')
    return True


  """
  Handle all other packet types by forwarding or flooding them.
  """
  def _handle_default(self, ether_pkt, event):
    dst_port = self._get_port_for_mac(ether_pkt.dst)
    if dst_port:
      self.packet_logger.action('FORWARD', [ ('Out Port', dst_port) ])
    else:
      dst_port = of.OFPP_FLOOD
      self.packet_logger.action('FLOOD', 'Unknown destination MAC address')

    self._send_packet(event.ofp, dst_port)


  """
  Handle ethernet packets.
  """
  def _handle_packet(self, ether_pkt, event):
    handled = False
    if ether_pkt.type == ethernet.IP_TYPE:
      handled = self._handle_ip(ether_pkt, ether_pkt.payload, event)
    elif ether_pkt.type == ethernet.ARP_TYPE:
      handled = self._handle_arp(ether_pkt, ether_pkt.payload, event)

    if not handled:
      self._handle_default(ether_pkt, event)


  """
  Event handler triggered when the switch sends us a packet it does not know how to handle.
  """
  def _handle_PacketIn(self, event):
    ether_pkt = event.parse()
    if ether_pkt.type == ethernet.IPV6_TYPE:
      # POX doesn't seem to do IPV6, but the mininet hosts generate packets on startup (duplicate address detection?),
      # which is really noisy and they seem to generate OpenFlow errors from POX.
      # For now, we just won't support IPV6, just like the rest of the Internet. :P
      return

    self.packet_logger.new_packet(self.dpid, event.ofp.in_port, ether_pkt)
    try:
      if ether_pkt.type == ethernet.LLDP_TYPE:
        # LLDP packets are the only thing we handle while inactive.
        self._handle_lldp(ether_pkt, ether_pkt.payload, event)
      elif not self.is_active:
        # If the switch has not activated yet, only handle LLDP packets.
        # Once the switch has (most likely) heard from all of its neighbors,
        # then it will start handling traffic.
        self._drop_packet(event, 'Not active yet.')
      else:
        # Don't start learning MAC locations until we're active...shouldn't matter, but seems like a sane precaution.
        self._learn_mac_location(ether_pkt.src, event.ofp.in_port)

        # Handle the packet.
        self._handle_packet(ether_pkt, event)
    except Exception as ex:
      SpanningTreeSwitch.logger.error(format_exc())
      self.packet_logger.metric('Error', [ ('Type', type(ex).__name__), ('Message', ex.message) ])


  """
  Teaches the switch that the specified MAC address can be reached through the specified port.
  """
  def _learn_mac_location(self, mac, port):
    if is_special_mac(mac):
      # Do not learn locations for "special" MAC addresses (e.g. broadcast addresses).
      return

    # Make sure the port actually exists on the switch.
    port_mac = self._get_mac_for_port(port)
    if port_mac is None:
      raise Exception('Port {} does not exist on this switch ({}).'.format(port, self.dpid))

    old_port = self._get_port_for_mac(mac)
    if old_port == port:
      # We already know the location of this MAC address.
      return

    # Keep track of what we have learned in the controller.
    SpanningTreeSwitch.logger.info('switch-{}: MAC address {} can be found at port {}.'.format(self.dpid, mac, port))
    if old_port is not None:
      SpanningTreeSwitch.logger.info('Overwriting previous location at port {}.'.format(old_port))
    self.mac_to_port[str(mac)] = port

    # Teach it to the switch flow table.
    priority = SpanningTreeSwitch.DEFAULT_FLOW_PRIORITY
    SpanningTreeSwitch.logger.info('switch-{}: Installing flow: Dest MAC {} => Output Port {} (priority = {}).'.format(self.dpid, mac, port, priority))
    msg = of.ofp_flow_mod(priority = priority)
    msg.match.dl_dst = EthAddr(mac)
    msg.actions.append(of.ofp_action_output(port = port))
    self.connection.send(msg)

    # Teach others that this MAC address can be reached through us.
    for link in self.links:
      # Only teach it to our spanning tree neighbors, and don't teach it to the switch we are sending to.
      if link.is_active() and link.local_port != port:
        link.remote_switch._learn_mac_location(mac, link.remote_port)


"""
Switch that takes in traffic from outside the load balancer fleet.
"""
class LoadBalancingSwitch(SpanningTreeSwitch):

  # Seconds to wait between sending health check PINGs to hosts.
  DEFAULT_HEALTH_CHECK_INTERVAL = 10
  # Time out old health checks (both host status and replies) after two health check intervals.
  MAX_HEALTH_CHECK_AGE = DEFAULT_HEALTH_CHECK_INTERVAL * 2 * 1000 # Converting from seconds to milliseconds.

  # Delay before starting health checks (to give switches time to finish activating links, etc.).
  FIRST_HEALTH_CHECK_DELAY = 5

  def __init__(self, event, arp_table, packet_log, ingress_port, vip, host_pool):
    SpanningTreeSwitch.__init__(self, event, arp_table, packet_log)
    # Ingress switch is always the root of the spanning tree.
    self.distance = 0

    self._ingress_port = ingress_port
    self._vip = vip
    self._vip_mac = self._get_mac_for_port(self._ingress_port)
    self._host_pool = host_pool
    self._next_host = 0
    self._health_check_seq = 0

    # Add the VIP to the ARP table right away.
    self._arp_table.add(self._vip, self._vip_mac)


  def _activate(self):
    super(LoadBalancingSwitch, self)._activate()
    Timer(LoadBalancingSwitch.FIRST_HEALTH_CHECK_DELAY, self._do_health_check)


  """
  Sends periodic health check packets to each host in the pool.  These are ICMP ECHO REQUESTs if we know the
  host's MAC address, ARP requests if we do not.
  """
  def _do_health_check(self):
    now = get_time_in_ms()
    health_changed = False

    LoadBalancingSwitch.logger.debug('Performing health check.')
    for host in self._host_pool:
      if host.is_healthy and now - host.last_check_reply >= LoadBalancingSwitch.MAX_HEALTH_CHECK_AGE:
        # Haven't gotten a health check response in one health check interval.  Mark as unhealthy.
        host.is_healthy = False
        LoadBalancingSwitch.logger.warn('Host {} did not respond to health check, marking unhealthy.'.format(host.ip_address))
        health_changed = True

      host_mac = self._arp_table.lookup(host.ip_address)
      if host_mac is None:
        # Host is not in ARP table; send an ARP health check.
        host_port = of.OFPP_FLOOD
        arp_probe = arp(
          opcode = arp.REQUEST,
          hwsrc = self._vip_mac,
          hwdst = SpecialMacs.ARP_REQUEST_TARGET,
          protosrc = self._vip,
          protodst = host.ip_address)
        ether_wrapper = ethernet(type = ethernet.ARP_TYPE, src = self._vip_mac, dst = SpecialMacs.ARP_REQUEST_TARGET, payload = arp_probe)
      else:
        # Send ICMP ECHO REQUEST health check.
        host_port = self._get_port_for_mac(host_mac)
        if host_port is None:
          # If the host is in the ARP table, we should know which port to send to, but if not we can fall back to flooding.
          host_port = of.OFPP_FLOOD

        # Health check pings contain the timestamp for the health check, so we can ignore responses from stale checks.
        icmp_echo_req = icmp(type = TYPE_ECHO_REQUEST, payload = struct.pack('!IQ', self._health_check_seq, now))
        ipv4_wrapper = ipv4(protocol = ipv4.ICMP_PROTOCOL, srcip = self._vip, dstip = host.ip_address, payload = icmp_echo_req)
        ether_wrapper = ethernet(type = ethernet.IP_TYPE, src = self._vip_mac, dst = host_mac, payload = ipv4_wrapper)

      self._send_packet(ether_wrapper, host_port)

    if health_changed:
      self._report_healthy_hosts()

    # Schedule the next health check.
    Timer(LoadBalancingSwitch.DEFAULT_HEALTH_CHECK_INTERVAL, self._do_health_check)


  """
  Output the list of healthy hosts to the log.
  """
  def _report_healthy_hosts(self):
    healthy_hosts = filter(lambda x: x.is_healthy, self._host_pool)
    LoadBalancingSwitch.logger.info('Healthy hosts: {}'.format(', '.join([ str(x.ip_address) for x in healthy_hosts ])))


  """
  Gets the next host to send a connection to, or None if there are no active hosts in the pool.
  """
  def _get_next_host(self):
    host_count = len(self._host_pool)
    if host_count == 0:
      # No hosts in the pool!
      return None

    # Step through the host pool, starting at next_host, looking for the next healthy host.
    starting_next = self._next_host
    for i in xrange(host_count):
      host = self._host_pool[self._next_host]
      self._next_host = (self._next_host + 1) % host_count
      if host.is_healthy:
        return host

    # Could not find any healthy hosts!
    return None


  """
  Updates the host health check status.
  """
  def _mark_host_healthy(self, host):
    host.last_check_reply = get_time_in_ms()
    if not host.is_healthy:
      host.is_healthy = True
      LoadBalancingSwitch.logger.info('Received health check for unhealthy host {}; marking healthy.'.format(host.ip_address))
      self._report_healthy_hosts()

  """
  Attempts to process an ARP packet as a health check reply.
  """
  def _handle_arp_health_check_reply(self, ether_pkt, arp_pkt, event):
    if arp_pkt.opcode == arp.REPLY and ether_pkt.dst == self._vip_mac and arp_pkt.protodst == self._vip:
      src_ip = arp_pkt.protosrc
      self._arp_table.add(src_ip, ether_pkt.src)
      self.packet_logger.metric('Health Check', [ ('Host', src_ip), ('Type', 'ARP') ])
      for host in self._host_pool:
        if host.ip_address == src_ip:
          self._mark_host_healthy(host)
          self.packet_logger.action('Health Check Reply', [ ('Type', 'ARP'), ('Host', src_ip) ])
          return True
      self.packet_logger.action('Health Check Ignore', 'Reply too old.')


  """
  Attempts to process an ICMP packet as a health check reply.
  """
  def _handle_icmp_health_check_reply(self, ether_pkt, ip_pkt, icmp_pkt, event):
    if icmp_pkt.type == TYPE_ECHO_REPLY and ether_pkt.dst == self._vip_mac and ip_pkt.dstip == self._vip:
      # Only respect health check replies that are less than one health check interval old.
      (timestamp,) = struct.unpack('!Q', icmp_pkt.payload.payload)
      age = get_time_in_ms() - timestamp

      self.packet_logger.metric('Health Check', [ ('Host', ip_pkt.srcip), ('Type', 'ICMP'), ('Timestamp', timestamp), ('Age', age) ])
      if age < LoadBalancingSwitch.MAX_HEALTH_CHECK_AGE:
        for host in self._host_pool:
          if host.ip_address == ip_pkt.srcip:
            self._mark_host_healthy(host)
            self.packet_logger.action('Health Check Reply', 'Valid reply.')
            return True
        self.packet_logger.action('Health Check Ignore', 'Host not in fleet.')
      else:
        self.packet_logger.action('Health Check Ignore', 'Reply too old.')


  def _handle_vip_arp(self, ether_pkt, arp_pkt, event):
    if arp_pkt.opcode == arp.REQUEST and arp_pkt.protodst == self._vip:
      self._arp_table.add(arp_pkt.protosrc, ether_pkt.src)

      self.packet_logger.action('ARP VIP Reply', [ ('Target IP', arp_pkt.protodst), ('Target MAC', self._vip_mac) ])
      arp_reply = arp(hwsrc = self._vip_mac, hwdst = ether_pkt.src, opcode = arp.REPLY, protosrc = arp_pkt.protodst, protodst = arp_pkt.protosrc)
      ether = ethernet(type = ethernet.ARP_TYPE, dst = ether_pkt.src, src = self._vip_mac, payload = arp_reply)
      self._send_packet(ether, event.ofp.in_port)
    else:
      self._drop_packet(event, 'Inbound ARP not REQUEST targeted at load balancer VIP.')
    return True


  def _handle_packet(self, ether_pkt, event):
    dst_ip = None
    if ether_pkt.type == ethernet.ARP_TYPE:
      dst_ip = ether_pkt.payload.protodst
    elif ether_pkt.type == ethernet.IP_TYPE:
      dst_ip = ether_pkt.payload.dstip

    handled = False
    if event.ofp.in_port == self._ingress_port:
      # The ingress port only accepts ARPs, ICMP ECHO REQUESTs, and TCP connections, and only for the VIP.
      if ether_pkt.type == ethernet.ARP_TYPE:
        handled = self._handle_vip_arp(ether_pkt, ether_pkt.payload, event)
      elif ether_pkt.type == ethernet.IP_TYPE:
        ip_pkt = ether_pkt.payload
        self._arp_table.add(ip_pkt.srcip, ether_pkt.src)
        if ip_pkt.protocol == ipv4.ICMP_PROTOCOL:
          handled = self._handle_vip_icmp(ether_pkt, ip_pkt, ip_pkt.payload, event)
        elif ether_pkt.payload.protocol == ipv4.TCP_PROTOCOL:
          handled = self._handle_vip_tcp(ether_pkt, ip_pkt, ip_pkt.payload, event)

      if not handled:
        self._drop_packet(event, 'Ingress packet not targeted at load balanced service.')
    elif ether_pkt.dst == self._vip_mac or dst_ip == self._vip:
      # The only things we should see from inside the load balancer targeted at the VIP or its MAC are health check replies.
      if ether_pkt.type == ethernet.ARP_TYPE:
        # Try to handle the packet as an ARP health check.
        handled = self._handle_arp_health_check_reply(ether_pkt, ether_pkt.payload, event)
      elif ether_pkt.type == ethernet.IP_TYPE and ether_pkt.payload.protocol == ipv4.ICMP_PROTOCOL:
        # Try to handle the packet as an ICMP health check.
        handled = self._handle_icmp_health_check_reply(ether_pkt, ether_pkt.payload, ether_pkt.payload.payload, event)

      if not handled:
        # Drop anything else from inside the load balancer if it is targeted at the VIP or its MAC.
        self._drop_packet(event, 'Unrecognized packet from inside load balancer destined for VIP or VIP MAC address.')

    if not handled:
      super(LoadBalancingSwitch, self)._handle_packet(ether_pkt, event)


  def _handle_vip_icmp(self, ether_pkt, ip_pkt, icmp_pkt, event):
    if icmp_pkt.type == TYPE_ECHO_REQUEST and ip_pkt.dstip == self._vip:
      # Always respond to echo requests to the VIP.
      vip_mac = self._get_mac_for_port(event.ofp.in_port)
      self.packet_logger.action('VIP ECHO REPLY', [ ('From MAC', vip_mac) ])
      icmp_reply = icmp(type = TYPE_ECHO_REPLY, payload = icmp_pkt.payload)
      ipv4_wrapper = ipv4(protocol = ipv4.ICMP_PROTOCOL, srcip = self._vip, dstip = ip_pkt.srcip, payload = icmp_reply)
      ether_wrapper = ethernet(type = ethernet.IP_TYPE, src = vip_mac, dst = ether_pkt.src, payload = ipv4_wrapper)
      self._send_packet(ether_wrapper, event.ofp.in_port)
      return True
    return super(LoadBalancingSwitch, self).handle_icmp(ether_pkt, ip_pkt, icmp_pkt, event)


  """
  Handle TCP packets by routing to a load balanced host.
  """
  def _handle_vip_tcp(self, ether_pkt, ip_pkt, tcp_pkt, event):
    # Load balance traffic to the virtual IP across the host pool.
    host = self._get_next_host()
    if host is None:
      self.packet_logger.metric('Host', 'No healthy host')
      return False

    host_mac = self._arp_table.lookup(host.ip_address)
    output_port = self._get_port_for_mac(host_mac)
    self.packet_logger.action('Load Balance', [ ('Host IP', host.ip_address), ('Host MAC', host_mac), ('Host Port', output_port) ])
    if output_port is None:
      return False

    # Add a rule to rewrite the destination to point to load balanced host.
    self.packet_logger.metric('Flow Mod', [
      ('Ethernet Type', 'IP'),
      ('IP Protocol', 'TCP'),
      ('Source', '{}:{}'.format(ip_pkt.srcip, tcp_pkt.srcport)),
      ('Dest', '{}:{}'.format(self._vip, tcp_pkt.dstport)),
      ('Output Port', output_port)
    ])
    src_to_vip_flow = of.ofp_flow_mod(idle_timeout = 3600)
    src_to_vip_flow.match = of.ofp_match(dl_type = 0x800, nw_src = ip_pkt.srcip, nw_proto = 6, tp_src = tcp_pkt.srcport, nw_dst = self._vip, tp_dst = tcp_pkt.dstport)
    src_to_vip_flow.actions.append(of.ofp_action_dl_addr.set_dst(host_mac))
    src_to_vip_flow.actions.append(of.ofp_action_nw_addr.set_dst(host.ip_address))
    src_to_vip_flow.actions.append(of.ofp_action_output(port = output_port))
    self.connection.send(src_to_vip_flow)

    # Rewrite packet coming back.
    src_to_vip_flow = of.ofp_flow_mod(idle_timeout = 3600)
    src_to_vip_flow.match = of.ofp_match(dl_type = 0x800, nw_src = host.ip_address, nw_proto = 6, tp_src = tcp_pkt.dstport, nw_dst = ip_pkt.srcip, tp_dst = tcp_pkt.srcport)
    src_to_vip_flow.actions.append(of.ofp_action_dl_addr.set_src(self._vip_mac))
    src_to_vip_flow.actions.append(of.ofp_action_nw_addr.set_src(self._vip))
    src_to_vip_flow.actions.append(of.ofp_action_output(port = self._ingress_port))
    self.connection.send(src_to_vip_flow)

    # Send the packet.
    self.packet_logger.action('FORWARD', 'Sending based on new flow table rules.')
    self._send_packet(event.ofp, of.OFPP_TABLE)
    return True


"""
Creates a load balancing network appliance consisting of a LoadBalancingSwitch and
a network of SpanningTreeSwitches.
"""
class LoadBalancer(EventMixin):
  CONFIG_VIP = 'vip'
  CONFIG_PACKET_LOG = 'packet_log'
  CONFIG_INGRESS_SWITCH = 'ingress_switch'
  CONFIG_INGRESS_PORT = 'ingress_port'
  CONFIG_HOST_IPS = 'hosts'

  DEFAULT_PACKET_LOG_FORMAT = 'packet.log.{switch}'

  logger = core.getLogger()


  def _get_required_config(self, config, key):
    value = config.get(key)
    if value is None:
      raise Exception('Configuration parameter "{}" is required.'.format(key))
    return value


  def _load_config(self, config):
    self._vip = IPAddr(self._get_required_config(config, LoadBalancer.CONFIG_VIP))
    LoadBalancer.logger.info('Load balancer virtual IP: {}'.format(str(self._vip)))
    self._ingress_switch_dpid = int(self._get_required_config(config, LoadBalancer.CONFIG_INGRESS_SWITCH))
    LoadBalancer.logger.info('Load balancer ingress switch: {}'.format(self._ingress_switch_dpid))
    self._ingress_port = int(self._get_required_config(config, LoadBalancer.CONFIG_INGRESS_PORT))
    LoadBalancer.logger.info('Load balancer ingress port: {}'.format(self._ingress_port))

    host_ip_arg = self._get_required_config(config, LoadBalancer.CONFIG_HOST_IPS)
    self._host_pool = [ Host(x) for x in host_ip_arg.split(',') ]
    LoadBalancer.logger.info('Fleet host IP addresses: {}'.format(host_ip_arg))


  def __init__(self, params):
    self._ingress_switch_dpid = None
    self._ingress_switch = None
    self._ingress_port = None
    self._host_pool = []
    self._arp_table = ArpTable()
    self._switches = {}
    self._packet_loggers = {}

    self._load_config(params)

    self.listenTo(core)
    self.listenTo(core.openflow)


  """
  Create Link instances for both directions of the link and update the spanning
  tree as necessary.
  """
  def _handle_switch_LinkDiscoveryEvent(self, event):
    local_switch = event.local_switch
    remote_switch = self._switches[event.remote_dpid]

    for link in local_switch.links:
      if link.local_port == event.local_port and link.remote_port == event.remote_port:
        # This link is already known; we probably already handled the event for the other side.
        return

    LoadBalancer.logger.debug('Discovered link from {} to {}.'.format(local_switch.dpid, remote_switch.dpid))
    local_link = Link(event.local_port, remote_switch, event.remote_port)
    local_switch.links.append(local_link)

    remote_link = Link(event.remote_port, local_switch, event.local_port)
    remote_switch.links.append(remote_link)
    local_link.reverse = remote_link
    remote_link.reverse = local_link

    if local_switch.distance is None:
      if remote_switch.distance is None:
        # Not linked to the root yet, so can't calculate a spanning tree.
        LoadBalancer.logger.debug('Link added between two switches outside the tree; no spanning tree calculated.')
      else:
        # The local switch (and any connected to it) just got linked to the root.
        # Time to generate a spanning tree, but just for the local subtree.
        LoadBalancer.logger.debug('Subtree (local) added to tree; calculating partial spanning tree.')
        SpanningTree(local_switch, uplink = local_link).build()
    elif remote_switch.distance is None:
      # The remote switch (and any connected to it) just got linked to the root.
      # Time to generate a spanning tree, but just for the remote subtree.
      LoadBalancer.logger.debug('Subtree (local) added to tree; calculating partial spanning tree.')
      SpanningTree(remote_switch, uplink = remote_link).build()
    else:
      # Added a new link between two switches already in the tree.
      # For simplicity, just calculate a full spanning tree for now, can probably optimize.
      LoadBalancer.logger.debug('New link added within the tree; calculating full spanning tree.')
      SpanningTree(self._ingress_switch).build()


  """
  Creates a switch instance to manage the new switch connection.
  """
  def _handle_ConnectionUp(self, event):
    # Each switch gets a separate packet logger instance, so we can easily log to different files.
    packet_logger = PacketLogger(LoadBalancer.DEFAULT_PACKET_LOG_FORMAT.format(switch = event.dpid))
    self._packet_loggers[event.dpid] = packet_logger

    # Create a new switch controller instance.
    if event.dpid == self._ingress_switch_dpid:
      # This is the switch that connects to the outside world.  It handles the job of balancing inbound connections across the fleet.
      switch = LoadBalancingSwitch(event, self._arp_table, packet_logger, self._ingress_port, self._vip, self._host_pool)
      self._ingress_switch = switch
      LoadBalancer.logger.debug('Ingress switch connected: {}'.format(switch.dpid))
    else:
      # This is just another switch in the load balancer's internal topology.
      switch = SpanningTreeSwitch(event, self._arp_table, packet_logger)
      LoadBalancer.logger.debug('Internal switch connected: {}'.format(event.dpid))

    # Listen to link discovery events so we can learn the network topology and build a spanning tree to route traffic along.
    switch.addListenerByName('LinkDiscoveryEvent', self._handle_switch_LinkDiscoveryEvent)
    self._switches[event.dpid] = switch


  """
  Perform cleanup tasks when the controller is shut down.
  """
  def _handle_DownEvent(self, event):
    LoadBalancer.logger.debug('Performing final clean up.')
    # Close the packet log files.  Failures are logged, not reraised.
    for dpid in self._packet_loggers.keys():
      packet_logger = self._packet_loggers.pop(dpid, None)
      if packet_logger:
        LoadBalancer.logger.info('Closing packet logger for switch {}.'.format(dpid))
        try:
          packet_logger.close()
        except:
          LoadBalancer.logger.warn('Unable to close packet logger for {}: {}'.format(dpid, format_exc()))


"""
Invoked by POX when LoadBalancer is specified as a module on the command line:
  $ ./pox csep561.LoadBalancer
"""
def launch(**params):
  load_balancer = LoadBalancer(params)
  core.register('loadbalancer', load_balancer)

