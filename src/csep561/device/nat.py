from random import randint
from time import time

import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet import arp, ethernet, ipv4
from pox.lib.recoco import Timer

from .learning_switch import LearningSwitch
from ..lib.addresses import SpecialMacs
from ..lib.packet_logger import PacketLogger


# How long a NAT connection must be idle before it can be cleaned up.
NAT_ESTABLISHED_IDLE_TIMEOUT = 7440 # seconds; 2 hours and 4 minutes
NAT_TRANSIENT_IDLE_TIMEOUT = 300 # seconds; 5 minutes

# How long to wait between sweeps of the NAT table for transient idle connections.
NAT_TABLE_TRANSIENT_SWEEP_PERIOD = 10 # seconds

# Cookie values to set on NAT rules (values chosen arbitrarily).
NAT_INBOUND_RULE_COOKIE = 437
NAT_OUTBOUND_RULE_COOKIE = 438

CONFIG_KEY_GATEWAY = 'gateway'
CONFIG_KEY_NETMASK = 'netmask'
CONFIG_KEY_IP = 'ip'
CONFIG_KEY_UPLINK = 'uplink'
CONFIG_KEY_PORT_MAP = 'port_map'
CONFIG_KEY_PORT_MAP_IP = 'ip'
CONFIG_KEY_PORT_MAP_PORT = 'port'
CONFIG_KEY_PORT_MAP_NAT_PORT = 'nat_port'


def ip_to_network(ip, netmask):
  return IPAddr(ip.toUnsigned() & netmask.toUnsigned())


def _make_nat_key(ip, port):
  return (str(ip), port)


class NatTable():

  logger = core.getLogger()

  def __init__(self, packet_logger, min_port = 1024, max_port = 65535, port_map = None):
    self._packet_logger = packet_logger
    self._min_port = min_port
    self._max_port = max_port
    self._available_ports = range(min_port, max_port + 1)
    self._port_mapping = {}
    self._local_mapping = {}
    self._connections = {}

    if port_map:
      for mapping in port_map:
        self.add_port_mapping(mapping[CONFIG_KEY_PORT_MAP_IP], mapping[CONFIG_KEY_PORT_MAP_PORT], nat_port = mapping[CONFIG_KEY_PORT_MAP_NAT_PORT])

    Timer(NAT_TABLE_TRANSIENT_SWEEP_PERIOD, self._sweep_for_transients, recurring = True)

  def _sweep_for_transients(self):
    NatTable.logger.debug('Sweeping NAT table for idle transient connections.')
    for mapping in self._port_mapping.values():
      remaining_conns = mapping.clean_up_idle_transients()
      if remaining_conns == 0:
        self._clean_up_mapping(mapping)

  def _clean_up_mapping(self, mapping):
    if not mapping.is_dynamic:
      NatTable.logger.info('Not cleaning up static mapping: {}:{} => {}.'.format(mapping.local_ip, mapping.local_port, mapping.nat_port))
      return
    self._port_mapping.pop(mapping.nat_port)
    self._local_mapping.pop(_make_nat_key(mapping.local_ip, mapping.local_port))
    self._available_ports.append(mapping.nat_port)
    NatTable.logger.info('Cleaned up mapping: {}:{} => {}'.format(mapping.local_ip, mapping.local_port, mapping.nat_port))

  """
  Registers a NAT mapping between the specified local IP address and TCP port and
  the specified NAT TCP port.  If the specified NAT TCP port is None, the next
  available port will be used.
  """
  def add_port_mapping(self, local_ip, local_port, nat_port = None):
    is_dynamic = False
    if nat_port is None:
      # Dynamically select an unmapped port and assign it to this mapping.

      # Make sure we have an unmapped port available.
      available_port_count = len(self._available_ports)
      if available_port_count == 0:
        raise Exception('Cannot map dynamic port: no unmapped ports available.')

      # Select a random port.
      port_index = randint(0, available_port_count - 1)
      nat_port = self._available_ports.pop(port_index)
      is_dynamic = True
    elif nat_port in self._port_mapping:
      # The specified NAT TCP port is already mapped.
      raise Exception('NAT port {} already mapped.'.format(nat_port))
    elif nat_port >= self._min_port and nat_port <= self._max_port:
      # Remove the specified port from the list of available ports.
      self._available_ports.remove(nat_port)

    self._packet_logger.action('Map NAT Port', [
      ('Local IP', local_ip), ('Local Port', local_port),
      ('NAT Port', nat_port), ('Dynamic', is_dynamic)
    ])
    mapping = NatMapping(self._packet_logger, local_ip, local_port, nat_port, is_dynamic)
    self._port_mapping[nat_port] = mapping
    self._local_mapping[_make_nat_key(local_ip, local_port)] = mapping
    return mapping

  """
  Gets the NAT connection associated with either the specified:
   - local IP address, local TCP port, remote IP address, and remote TCP port
   - remote IP address, remote TCP port, and NAT TCP port
  """
  def get_connection(self, *params):
    if len(params) == 3:
      (remote_ip, remote_port, nat_port) = params
      mapping = self._port_mapping.get(nat_port)
      if mapping is None:
        # No port mapping, and we cannot create one from the remote side.
        return None
      self._packet_logger.metric('NAT Port Mapping', [
        ('Local IP', mapping.local_ip), ('Local Port', mapping.local_port), ('NAT Port', mapping.nat_port)
      ])
    elif len(params) == 4:
      local_ip, local_port, remote_ip, remote_port = params
      mapping = self._local_mapping.get(_make_nat_key(local_ip, local_port))
      if mapping is None:
        # No port mapping, so create one.
        mapping = self.add_port_mapping(local_ip, local_port)
      else:
        self._packet_logger.metric('NAT Port Mapping', [
          ('Local IP', mapping.local_ip), ('Local Port', mapping.local_port), ('NAT Port', mapping.nat_port)
        ])
    else:
      raise Exception('NatTable.get_connection() requires either 3 or 4 parameters ({} provided).'.format(len(params)))

    # Get the connection for this remote address/port.
    return mapping.get_connection(remote_ip, remote_port)

  """
  Cleans up the NAT table and releases any resources related to a now closed connection, also releasing
  the NAT port mapping if it was dynamically assigned and has no further active connections.
  """
  def clean_up_connection(self, *params):
    if len(params) == 3:
      (remote_ip, remote_port, nat_port) = params
      mapping = self._port_mapping.get(nat_port)
    elif len(params) == 4:
      local_ip, local_port, remote_ip, remote_port = params
      mapping = self._local_mapping.get(_make_nat_key(local_ip, local_port))
    else:
      raise Exception('NatTable.clean_up_connection() requires either 3 or 4 parameters ({} provided).'.format(len(params)))

    if mapping is None:
      return
    conn_count = mapping.clean_up_connection(remote_ip, remote_port)
    if conn_count == 0:
      self._clean_up_mapping(mapping)


"""
Represents a NAT port to local IP and TCP port mapping, and the remote connections
associated with it.
"""
class NatMapping:

  logger = core.getLogger()

  def __init__(self, packet_logger, local_ip, local_port, nat_port, is_dynamic):
    self._packet_logger = packet_logger
    self.local_ip = local_ip
    self.local_port = local_port
    self.nat_port = nat_port
    self.is_dynamic = is_dynamic
    self._connections = {}

  """
  Gets the NAT connection associated with the remote IP address and TCP port.
  """
  def get_connection(self, remote_ip, remote_port):
    # Get the connection for this remote address/port.
    conn_key = _make_nat_key(remote_ip, remote_port)
    conn = self._connections.get(conn_key)
    if conn is None:
      # No connection yet; create one.
      self._packet_logger.action('New NAT Connection', [
        ('Remote IP', remote_ip), ('Remote Port', remote_port),
        ('NAT Port', self.nat_port)
      ])
      conn = NatConnection(self._packet_logger, self.local_ip, self.local_port, remote_ip, remote_port, self.nat_port)
      self._connections[conn_key] = conn
    else:
      self._packet_logger.metric('NAT Connection', [
        ('Remote IP', conn.remote_ip), ('Remote TCP Port', conn.remote_port),
        ('NAT TCP Port', conn.nat_port), ('Established', conn.is_established())
      ])
    return conn

  """
  Checks for idle transient connections and removes them.
  """
  def clean_up_idle_transients(self):
    now = time()
    for conn in self._connections.values():
      if not conn.is_established() and now - conn.start_time >= NAT_TRANSIENT_IDLE_TIMEOUT:
        self.clean_up_connection(conn.remote_ip, conn.remote_port)
    return len(self._connections)

  """
  Cleans up the NAT mapping and releases any resources related to a now closed connection.
  Returns the number of active connections on the mapping.
  """
  def clean_up_connection(self, remote_ip, remote_port):
    conn = self._connections.pop(_make_nat_key(remote_ip, remote_port), None)
    if conn:
      NatMapping.logger.info('Cleaned up connection: {}:{} => {} => {}:{}'.format(conn.local_ip, conn.local_port, conn.nat_port, conn.remote_ip, conn.remote_port))
    return len(self._connections)


class NatConnection:

  def __init__(self, packet_logger, local_ip, local_port, remote_ip, remote_port, nat_port):
    self._packet_logger = packet_logger
    self.start_time = time()
    self.local_ip = IPAddr(local_ip)
    self.local_port = local_port
    self.remote_ip = IPAddr(remote_ip)
    self.remote_port = remote_port
    self.nat_port = nat_port
    self._reset()

  def _reset(self):
    self._expected_syn_ack = { 'local': None, 'remote': None }
    self._received_syn_ack = { 'local': False, 'remote': False }
    self._is_established = False
    self.is_installed = False

  def _identify_src_and_dest(self, ip_pkt):
    if ip_pkt.srcip == self.local_ip:
      # Packet source is the local NATed host, destination is the remote host.
      return ('local', 'remote')
    else:
      # Packet source is the remote host, destination is the local NATed host.
      return ('remote', 'local')

  def update(self, ether_pkt, ip_pkt, tcp_pkt):
    if self.is_installed:
      # If the rules have already been installed, do nothing - not even reset. If
      # we are still seeing packets, it is because they were already sent to us
      # before the rule was installed on the switch. (race condition, but no ill
      # effects)
      return
    if tcp_pkt.RST:
      # TCP reset; throw out all of our expectations and start over.
      self._packet_logger.action('Reset NAT connection')
      self._reset()
      return
    elif self._is_established:
      # Already established.  If we're still getting packets, it means we didn't
      # know which port to use for the NAT host (weird!).  Don't bother to update;
      # once the controller knows the port, it will install rules.
      return

    src, dst = self._identify_src_and_dest(ip_pkt)
    action = None
    if tcp_pkt.SYN:
      if tcp_pkt.ACK:
        if tcp_pkt.ack == self._expected_syn_ack[dst]:
          # This is a SYN+ACK for the last SYN received from the destination.
          # Update destination state to indicate that its SYN has been ACKed.
          self._received_syn_ack[dst] = True
          action = 'Marked {} SYN+ACK as "received"'.format(dst)
          if self._received_syn_ack[src] and self._received_syn_ack[dst]:
            # Both sides have sent SYN+ACKs for the other side's SYN.
            # Simultaneous open.
            action = 'Established due to simultaneous open'
            self._is_established = True
      else:
        # Just a SYN; update source state with the expected ACK.
        self._expected_syn_ack[src] = tcp_pkt.seq + 1
        self._received_syn_ack[src] = False
        action = 'Set {} state from new SYN'.format(src)
    elif tcp_pkt.ACK:
      # ACKs that arn't SYN+ACKs only happen when moving to ESTABLISHED, or within
      # later states.  We won't know if/when an established connection is closed or
      # reset anyway, we may as well aggressively consider connections established.
      action = 'Established due to ACK.'
      self._is_established = True

    if action:
      self._packet_logger.action(action, [
        ('Packet Source', src),
        ('Local Exp. SYN+ACK', self._expected_syn_ack['local']),
        ('Local Recvd SYN+ACK', self._received_syn_ack['local']),
        ('Remote Exp. SYN+ACK', self._expected_syn_ack['remote']),
        ('Remote Recvd SYN+ACK', self._received_syn_ack['remote'])
      ])


  def is_established(self):
    return self._is_established


"""
A switch that acts as a NAT router.
"""
class NatRouter(LearningSwitch):

  logger = core.getLogger()

  def __init__(self, event, config):
    self._uplink_port = config[CONFIG_KEY_UPLINK]
    self._nat_ip = IPAddr(config[CONFIG_KEY_IP])
    self._gateway_ip = IPAddr(config[CONFIG_KEY_GATEWAY])
    self._netmask = IPAddr(config[CONFIG_KEY_NETMASK])
    self._network = ip_to_network(self._gateway_ip, self._netmask)
    self._network_filter = '{}/{}'.format(self._network, self._netmask)
    self._config = config

    # A map of packets that are awaiting ARP replies; keys are destination IP
    # addresses, values are lists of queued packet events.
    # When the NAT box receives a packet from an internal host destined for an
    # external host, it may not know the MAC address for the destination yet.
    # In this case, we need to send an ARP request for the destination IP, and
    # queue this packet locally until we get a reply.
    self._pending_packets = {}

    super(NatRouter, self).__init__(event)



  def _initialize(self):
    # The NAT mapping tables.
    self._nat_table = NatTable(self._packet_logger, port_map = self._config[CONFIG_KEY_PORT_MAP])

    # Use a single MAC address for the NAT box.  We arbitrarily choose to use the
    # uplink port's address.
    uplink_mac = self._get_mac_for_port(self._uplink_port)
    self._gateway_mac = EthAddr(uplink_mac)
    NatRouter.logger.info('Gateway MAC address: {}'.format(str(self._gateway_mac)))

    # Add entries to the ARP table mapping both the gateway and external NAT IP addresses to the gateway MAC address.
    self._arp_table.add(self._gateway_ip, self._gateway_mac)
    self._arp_table.add(self._nat_ip, self._gateway_mac)

    # Disable flooding on the uplink port.
    self.connection.send(of.ofp_port_mod(
      port_no = self._uplink_port,
      hw_addr = uplink_mac,
      config = of.OFPPC_NO_FLOOD,
      mask = of.OFPPC_NO_FLOOD))

    # Start listening to ARP add events, so we know when to process queued packets.
    self._arp_table.addListenerByName('ArpEntryAddedEvent', self._handle_arp_table_ArpEntryAddedEvent)

    super(NatRouter, self)._initialize()


  def _initialize_flow_table(self):
    # Filter out all ARP packets to start with.
    self.connection.send(of.ofp_flow_mod(priority = 100,
      match = of.ofp_match(dl_type = ethernet.ARP_TYPE)))

    # Filter out all packets destined for the gateway MAC address.
    self.connection.send(of.ofp_flow_mod(priority = 100,
      match = of.ofp_match(dl_dst = self._gateway_mac)))

    # Send ARP packets from network addresses to network addresses to the
    # controller.  This allows traffic from the uplink port, but the next rule
    # blocks it.
    self.connection.send(of.ofp_flow_mod(priority = 110,
      match = of.ofp_match(
        dl_type = ethernet.ARP_TYPE,
        nw_src = self._network_filter,
        nw_dst = self._network_filter),
      action = of.ofp_action_output(port = of.OFPP_CONTROLLER)))

    # Filter out everything coming in the uplink port by default; we will install
    # higher priority rules to let in only what we want.
    self.connection.send(of.ofp_flow_mod(priority = 120,
      match = of.ofp_match(in_port = self._uplink_port)))

    # Send ARP requests from the network for the NAT IP address to the controller,
    # regardless of what port they come from.  A later rule will block packets on
    # the upink port that claim to be from the network.
    self.connection.send(of.ofp_flow_mod(priority = 130,
      match = of.ofp_match(
        dl_type = ethernet.ARP_TYPE,
        dl_dst = SpecialMacs.BROADCAST,
        nw_proto = arp.REQUEST,
        nw_src = self._network_filter,
        nw_dst = self._nat_ip),
      action = of.ofp_action_output(port = of.OFPP_CONTROLLER)))

    # Send uplink ARP requests for the NAT IP address to the controller.
    self.connection.send(of.ofp_flow_mod(priority = 130,
      match = of.ofp_match(
        in_port = self._uplink_port,
        dl_type = ethernet.ARP_TYPE,
        dl_dst = SpecialMacs.BROADCAST,
        nw_proto = arp.REQUEST,
        nw_dst = self._nat_ip),
      action = of.ofp_action_output(port = of.OFPP_CONTROLLER)))

    # Send uplink ARP replies for requests sent by the controller to the controller.
    self.connection.send(of.ofp_flow_mod(priority = 130,
      match = of.ofp_match(
        in_port = self._uplink_port,
        dl_type = ethernet.ARP_TYPE,
        dl_dst = self._gateway_mac,
        nw_proto = arp.REPLY,
        nw_dst = self._nat_ip),
      action = of.ofp_action_output(port = of.OFPP_CONTROLLER)))

    # Send TCP packets from the network destined for the gateway MAC to the
    # controller.
    self.connection.send(of.ofp_flow_mod(priority = 130,
      match = of.ofp_match(
        dl_type = ethernet.IP_TYPE,
        dl_dst = self._gateway_mac,
        nw_proto = ipv4.TCP_PROTOCOL,
        nw_src = self._network_filter),
      action = of.ofp_action_output(port = of.OFPP_CONTROLLER)))

    # Send uplink TCP packets destined for the NAT IP to the controller.
    self.connection.send(of.ofp_flow_mod(priority = 130,
      match = of.ofp_match(
        in_port = self._uplink_port,
        dl_type = ethernet.IP_TYPE,
        dl_dst = self._gateway_mac,
        nw_proto = ipv4.TCP_PROTOCOL,
        nw_dst = self._nat_ip),
      action = of.ofp_action_output(port = of.OFPP_CONTROLLER)))

    # Reject any uplink ARPs packets claiming to be from the network.
    self.connection.send(of.ofp_flow_mod(priority = 140,
      match = of.ofp_match(
        in_port = self._uplink_port,
        dl_type = ethernet.ARP_TYPE,
        nw_src = self._network_filter)))

    # Reject any uplink IP packets claiming to be from the network.
    self.connection.send(of.ofp_flow_mod(priority = 140,
      match = of.ofp_match(
        in_port = self._uplink_port,
        dl_type = ethernet.IP_TYPE,
        nw_src = self._network_filter)))


  """
  Sends an ARP request on behalf of the NAT box.
  """
  def _send_arp_request(self, nw_dst):
    # If the ARP is for an IP on the internal network, use the internal gateway IP
    # address as the source and flood it.
    if IPAddr(nw_dst).in_network(self._network, netmask = self._netmask):
      proto_src = self._gateway_ip
      out_port = of.OFPP_FLOOD
    else:
      # Otherwise, use the external NAT IP address and send it out the uplink.
      proto_src = self._nat_ip
      out_port = self._uplink_port

    self._packet_logger.action('Send ARP Request', [
      ('Source MAC', self._gateway_mac),
      ('Dest MAC', SpecialMacs.ARP_REQUEST_DESTINATION),
      ('Source IP', proto_src),
      ('Dest IP', nw_dst)
    ])
    arp_request = arp(
        hwsrc = self._gateway_mac,
        hwdst = SpecialMacs.ARP_REQUEST_DESTINATION,
        opcode = arp.REQUEST,
        protosrc = proto_src,
        protodst = nw_dst)
    ether = ethernet(type = ethernet.ARP_TYPE, src = self._gateway_mac, dst = SpecialMacs.BROADCAST, payload = arp_request)
    self._send_packet(ether, out_port)


  """
  Sends packets that have been queued for the specified destination IP address.
  """
  def _send_queued_packets(self, dst_ip):
    NatRouter.logger.info('Sending queued packets for IP {}'.format(dst_ip))
    packet_queue = self._pending_packets.get(dst_ip)
    if packet_queue:
      NatRouter.logger.info('Sending {} queued packets for IP {}'.format(len(packet_queue), dst_ip))
      while len(packet_queue) > 0:
        # Replay the packet through the controller.  This makes sure we get all of
        # our logging and other incidental logic.
        self._handle_PacketIn(packet_queue.pop(0))


  """
  Sends an ARP request for the IP packet's destination, and queues the packet
  for processing when the ARP reply arrives.
  """
  def _queue_and_arp(self, event, arp_dst_ip):
    # Queue the packet.
    self._packet_logger.action('Queue', ('Awaiting IP', arp_dst_ip))
    pending_key = str(arp_dst_ip)
    pending_list = self._pending_packets.get(pending_key)
    if pending_list is None:
      pending_list = []
      self._pending_packets[pending_key] = pending_list
    pending_list.append(event)

    # Send the ARP request.
    self._send_arp_request(arp_dst_ip)


  def _handle_outbound_nat(self, event, ether_pkt, ip_pkt, tcp_pkt, remote_mac):
    nat_conn = self._nat_table.get_connection(ip_pkt.srcip, tcp_pkt.srcport, ip_pkt.dstip, tcp_pkt.dstport)

    # Update the NAT connection state from the outbound packet.
    nat_conn.update(ether_pkt, ip_pkt, tcp_pkt)

    msg = of.ofp_packet_out(data = event.ofp)
    if nat_conn.is_established():
      if not nat_conn.is_installed:
        # The connection is now ESTABLISHED, so hand control over to flow table rules.
        self._install_nat_rules(nat_conn, event.ofp.in_port, ether_pkt.src, remote_mac)
        nat_conn.is_installed = True

      # Send the current packet according to the new flow table rules.
      msg.actions.append(of.ofp_action_output(port = of.OFPP_TABLE))
      self._packet_logger.action('Apply Flow Table')
    else:
      # Translate and send the current packet.
      msg.actions = self._get_outbound_nat_actions(nat_conn, remote_mac)
      self._packet_logger.action('Translate and Forward', [
        ('Out Port', self._uplink_port)
      ])

    self.connection.send(msg)


  def _handle_inbound_nat(self, event, ether_pkt, ip_pkt, tcp_pkt):
    nat_conn = self._nat_table.get_connection(ip_pkt.srcip, tcp_pkt.srcport, tcp_pkt.dstport)
    if nat_conn is None:
      self._drop_packet(event, 'Inbound TCP packet for unmapped port')
      return

    local_mac = self._arp_table.lookup(nat_conn.local_ip)
    if local_mac is None:
      self._queue_and_arp(event, nat_conn.local_ip)
      return

    # Update the NAT connection state from the outbound packet.
    nat_conn.update(ether_pkt, ip_pkt, tcp_pkt)

    msg = of.ofp_packet_out(data = event.ofp)
    out_port = self.get_port_for_mac(local_mac)
    if nat_conn.is_established() and out_port is not None:
      # The connection is now ESTABLISHED and we know where to find the
      # destination NAT host, so hand control over to flow table rules.
      self._install_nat_rules(nat_conn, out_port, local_mac, ether_pkt.src)

      # Send the current packet according to the new flow table rules.
      msg.actions.append(of.ofp_action_output(port = of.OFPP_TABLE))
      self._packet_logger.action('Apply Flow Table')
      return
    elif out_port is None:
      out_port = of.OFPP_FLOOD

    self._packet_logger.action('Translate and Forward', [ ('Out Port', out_port) ])
    msg = of.ofp_packet_out(data = event.ofp)
    msg.actions = self._get_inbound_nat_actions(nat_conn, local_mac, out_port)
    self.connection.send(msg)


  def _install_nat_rules(self, nat_conn, switch_port, local_mac, remote_mac):
    self._packet_logger.action('NAT Rule', [
      ('Network Switch Port', switch_port),
      ('Local MAC', local_mac), ('Local IP', nat_conn.local_ip), ('Local TCP Port', nat_conn.local_port),
      ('Remote MAC', remote_mac), ('Remote IP', nat_conn.remote_ip), ('Remote TCP Port', nat_conn.remote_port),
      ('NAT TCP Port', nat_conn.nat_port)
    ])

    # Install a rule to route and translate inbound packets for this NATed connection.
    msg = of.ofp_flow_mod(priority = 200,
      cookie = NAT_INBOUND_RULE_COOKIE,
      flags = of.OFPFF_SEND_FLOW_REM,
      idle_timeout = NAT_ESTABLISHED_IDLE_TIMEOUT,
      match = of.ofp_match(
        in_port = self._uplink_port,
        dl_type = ethernet.IP_TYPE,
        dl_src = remote_mac,
        dl_dst = self._gateway_mac,
        nw_proto = ipv4.TCP_PROTOCOL,
        nw_src = nat_conn.remote_ip,
        nw_dst = self._nat_ip,
        tp_src = nat_conn.remote_port,
        tp_dst = nat_conn.nat_port))
    msg.actions = self._get_inbound_nat_actions(nat_conn, local_mac, switch_port)
    self.connection.send(msg)

    # Install a rule to route and translate outbound packets for this NATed connection.
    msg = of.ofp_flow_mod(priority = 200,
      cookie = NAT_OUTBOUND_RULE_COOKIE,
      flags = of.OFPFF_SEND_FLOW_REM,
      idle_timeout = NAT_ESTABLISHED_IDLE_TIMEOUT,
      match = of.ofp_match(
        in_port = switch_port,
        dl_type = ethernet.IP_TYPE,
        dl_src = local_mac,
        dl_dst = self._gateway_mac,
        nw_proto = ipv4.TCP_PROTOCOL,
        nw_src = nat_conn.local_ip,
        nw_dst = nat_conn.remote_ip,
        tp_src = nat_conn.local_port,
        tp_dst = nat_conn.remote_port))
    msg.actions = self._get_outbound_nat_actions(nat_conn, remote_mac)
    self.connection.send(msg)


  def _get_inbound_nat_actions(self, nat_conn, local_mac, switch_port):
    return [
      of.ofp_action_dl_addr.set_src(self._gateway_mac),
      of.ofp_action_dl_addr.set_dst(local_mac),
      of.ofp_action_nw_addr.set_dst(nat_conn.local_ip),
      of.ofp_action_tp_port.set_dst(nat_conn.local_port),
      of.ofp_action_output(port = switch_port)
    ]


  def _get_outbound_nat_actions(self, nat_conn, remote_mac):
    return [
      of.ofp_action_dl_addr.set_src(self._gateway_mac),
      of.ofp_action_dl_addr.set_dst(remote_mac),
      of.ofp_action_nw_addr.set_src(self._nat_ip),
      of.ofp_action_tp_port.set_src(nat_conn.nat_port),
      of.ofp_action_output(port = self._uplink_port)
    ]


  """
  Handle IP packets that require routing to the correct hardward address.
  """
  def _handle_ip(self, event, ether_pkt, ip_pkt):
    if ether_pkt.dst == self._gateway_mac:
      if event.ofp.in_port == self._uplink_port:
        self._handle_inbound_nat(event, ether_pkt, ip_pkt, ip_pkt.payload)
      else:
        # Find the actual MAC address for the destination.
        hw_dst = self._arp_table.lookup(ip_pkt.dstip)
        if hw_dst == None:
          # We don't know the MAC for this destination IP, so we need to send an ARP
          # request for it and queue this packet locally until we get a reply.
          self._queue_and_arp(event, ip_pkt.dstip)
        else:
          self._handle_outbound_nat(event, ether_pkt, ip_pkt, ip_pkt.payload, hw_dst)
      return True
    return super(NatRouter, self)._handle_ip(event, ether_pkt, ip_pkt)


  def _handle_default(self, event, ether_pkt):
    if ether_pkt.dst == self._gateway_mac:
      self._drop_packet(event, 'Packet intended for controller, no need to forward.')
    else:
      super(NatRouter, self)._handle_default(event, ether_pkt)


  def _handle_FlowRemoved(self, event):
    if event.idleTimeout:
      reason = 'idle timeout'
    elif event.hardTimeout:
      reason = 'hard timeout'
    elif event.deleted:
      reason = 'deleted'
    else:
      reason = 'unknown'

    NatRouter.logger.info('{}: Flow removed; Reason = {}; Cookie = {}; in_port = {}; nw_src = {}; nw_dst = {}; tp_src = {}; tp_dst = {};'.format(self.dpid, reason, event.ofp.cookie, event.ofp.match.in_port, event.ofp.match.nw_src, event.ofp.match.nw_dst, event.ofp.match.tp_src, event.ofp.match.tp_dst))
    if event.ofp.cookie == NAT_INBOUND_RULE_COOKIE:
      # Remove connection associated with this inbound NAT rule; identify connection by remote IP/port and NAT port.
      self._nat_table.clean_up_connection(event.ofp.match.nw_src, event.ofp.match.tp_src, event.ofp.match.tp_dst)
    elif event.ofp.cookie == NAT_OUTBOUND_RULE_COOKIE:
      # Remove connection associated with this outbound NAT rule; identify connection by local IP/port and remote IP/port.
      self._nat_table.clean_up_connection(event.ofp.match.nw_src, event.ofp.match.tp_src, event.ofp.match.nw_dst, event.ofp.match.tp_dst)


  def _handle_arp_table_ArpEntryAddedEvent(self, event):
    # Send any queued packets destined for the added address.
    ip = str(event.ip)
    packet_queue = self._pending_packets.get(ip)
    if packet_queue and len(packet_queue) > 0:
      NatRouter.logger.info('Scheduling queued packet processing for IP {}'.format(ip))
      core.callDelayed(0, self._send_queued_packets, ip)
      NatRouter.logger.info('Queued packet processing for IP {} scheduled.'.format(ip))


  def learn_mac_location(self, mac, port_no):
    if port_no != self._uplink_port and mac != self._gateway_mac:
      # Only learn locations of MACs on the internal network.
      super(NatRouter, self).learn_mac_location(mac, port_no)


