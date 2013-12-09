from time import time

import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet import arp, ethernet, ipv4

from .learning_switch import LearningSwitch
from ..lib.addresses import SpecialMacs
from ..lib.packet_logger import PacketLogger


# How long a NAT flow table rule must go idle before it times out.
NAT_RULE_IDLE_TIMEOUT = 7440

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


class NatMappingTable():

  def __init__(start_port = 1024):
    self._start_port = start_port
    self._next_port = self._start_port
    self._outbound = {}
    self._inbound = {}


  """
  Gets the NAT mapping associated with the specified key.  Key may be either an
  (<local IP address>, <local TCP port>) tuple for the mapping, or the NAT TCP
  port assigned to the mapping.
  """
  def get(self, key):
    if isinstance(key, tuple):
      mapping = self._outbound.get(key)
      if mapping is None:
        mapping = NatMapping(local_ip, local_port, self._next_port)
        self._inbound[key] = mapping
        self._outbound[self._next_port] = mapping
        self._next_port += 1
    else:
      mapping = self._inbound.get(key)
    return mapping


class NatConnection():

  def __init__(self, dst_ip, dst_port):
    self.dst_ip = dst_ip
    self.dst_port = dst_port


  def inbound_advance(self, ip_pkt, tcp_pkt):
    if tcp_pkt.RST:
      self._ib_syn_ack_seq = None
    elif tcp_pkt.ACK and tcp_pkt.SYN:
        self._ib_syn_ack_seq = tcp_pkt.seq
    return False


  def outbound_advance(self, ip_pkt, tcp_pkt):
    if tcp_pkt.ACK and not tcp_pkt.SYN and tcp_pkt.ack == self._ib_syn_ack_seq + 1:
      return True
    return False


class NatMapping():

  def __init__(self, local_ip, local_port, nat_port):
    self.start_time = time()
    self.local_ip = local_ip
    self.local_port = local_port
    self.nat_port = nat_port
    self._connections = {}


  def _get_conn(self, dst_ip, dst_port):
    conn_key = (dst_ip, dst_port)
    conn = self._connections.get(conn_key)
    if conn == None:
      conn = NatConnection(dst_ip, dst_port)
      self._connections[conn_key] = conn
    return conn


  """
  Advances the mapping to the next appropriate state (based on TCP state transitions), based on
  the specified outbound IP packet.
  Note that we only care about transitions between states up to and including ESTABLISHED.
  Once the connection is established, we will install flow table rules for it and stop seeing
  packets for tuple until it times out due to idleness.
  """
  def outbound_advance(self, ip_pkt):
    tcp_pkt = ip_pkt.payload
    conn = self._get_conn(ip_pkt.dstip, tcp_pkt.dstport)


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

    # The NAT mapping tables.
    # Outbound:
    #  - Keys are (<IP Address>, <TCP Port>) tuples.
    #  - Values are TCP port numbers as integers.
    self._outbound_nat_map = {}
    # Inbound:
    #  - Keys are TCP port numbers as integers.
    #  - Values are (<IP Address>, <TCP Port>) tuples.
    self._inbound_nat_map = {}
    # The next TCP port available for NAT mapping.
    self._next_nat_tcp_port = 2000

    # A map of packets that are awaiting ARP replies; keys are destination IP
    # addresses, values are lists of queued packet events.
    # When the NAT box receives a packet from an internal host destined for an
    # external host, it may not know the MAC address for the destination yet.
    # In this case, we need to send an ARP request for the destination IP, and
    # queue this packet locally until we get a reply.
    self._pending_packets = {}

    super(NatRouter, self).__init__(event)
    self._initialize_nat_mappings(config[CONFIG_KEY_PORT_MAP])


  def _initialize(self):
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


  def _initialize_nat_mappings(self, config):
    if config:
      for mapping in config:
        self._create_nat_mapping(mapping[CONFIG_KEY_PORT_MAP_IP], mapping[CONFIG_KEY_PORT_MAP_PORT], nat_tcp_port = mapping[CONFIG_KEY_PORT_MAP_NAT_PORT])


  """
  Gets the NAT TCP port assignment for a local IP address and TCP port.
  """
  def _get_outbound_nat_mapping(self, ip, tcp_port):
    return self._outbound_nat_map.get((str(ip), tcp_port))


  """
  Gets the local IP address and TCP port for a NAT mapped TCP port.
  """
  def _get_inbound_nat_mapping(self, nat_tcp_port):
    return self._inbound_nat_map.get(nat_tcp_port)


  """
  Create a NAT mapping for the specified IP address and TCP port.
  """
  def _create_nat_mapping(self, ip, tcp_port, nat_tcp_port = None):
    if nat_tcp_port is None:
      nat_tcp_port = self._next_nat_tcp_port
      self._next_nat_tcp_port += 1
    elif nat_tcp_port in self._inbound_nat_map:
      raise Exception('NAT port {} already mapped.'.format(nat_tcp_port))
    elif nat_tcp_port == self._next_nat_tcp_port:
      self._next_nat_tcp_port += 1

    mapping = (str(ip), tcp_port)
    self._outbound_nat_map[mapping] = nat_tcp_port
    self._inbound_nat_map[nat_tcp_port] = mapping
    self._packet_logger.action('NAT Mapping', [
      ('Local IP', ip), ('Local TCP Port', tcp_port), ('NAT TCP Port', nat_tcp_port)
    ])
    return nat_tcp_port


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
    nat_tcp_port = self._get_outbound_nat_mapping(ip_pkt.srcip, tcp_pkt.srcport)
    if nat_tcp_port is None:
      # Create NAT mapping.
      nat_tcp_port = self._create_nat_mapping(ip_pkt.srcip, tcp_pkt.srcport)
    else:
      self._packet_logger.metric('NAT Mapping', [
        ('Local IP', ip_pkt.srcip),
        ('Local TCP Port', tcp_pkt.srcport),
        ('NAT TCP Port', nat_tcp_port)
      ])

    msg = of.ofp_packet_out(data = event.ofp)
    if tcp_pkt.ACK and not tcp_pkt.SYN:
      self._install_nat_rules(event.ofp.in_port, ether_pkt.src, ip_pkt.srcip, tcp_pkt.srcport, remote_mac, ip_pkt.dstip, tcp_pkt.dstport, nat_tcp_port)

      # Send the current packet according to the new flow table rules.
      msg.actions.append(of.ofp_action_output(port = of.OFPP_TABLE))
      self._packet_logger.action('Apply Flow Table')
    else:
      # Translate and send the current packet.
      msg.actions = self._get_outbound_nat_actions(remote_mac, nat_tcp_port)
      self._packet_logger.action('Translate and Forward', [
        ('Out Port', self._uplink_port)
      ])

    self.connection.send(msg)


  def _handle_inbound_nat(self, event, ether_pkt, ip_pkt, tcp_pkt):
    mapping = self._get_inbound_nat_mapping(tcp_pkt.dstport)
    if mapping is None:
      self._drop_packet(event, 'Inbound TCP packet for unmapped port')
      return

    local_ip, local_port = mapping
    self._packet_logger.metric('NAT Mapping', [
      ('Local IP', local_ip),
      ('Local TCP Port', local_port),
      ('NAT TCP Port', tcp_pkt.dstport)
    ])

    local_mac = self._arp_table.lookup(local_ip)
    if local_mac is None:
      self._queue_and_arp(event, local_ip)
      return

    out_port = self.get_port_for_mac(local_mac) or of.OFPP_FLOOD
    self._packet_logger.action('Translate and Forward', [ ('Out Port', out_port) ])
    msg = of.ofp_packet_out(data = event.ofp)
    msg.actions = self._get_inbound_nat_actions(local_mac, local_ip, local_port, out_port)
    self.connection.send(msg)


  def _install_nat_rules(self, switch_port, local_mac, local_ip, local_tcp_port, remote_mac, remote_ip, remote_tcp_port, nat_tcp_port):
    self._packet_logger.action('NAT Rule', [
      ('Network Switch Port', switch_port),
      ('Local MAC', local_mac), ('Local IP', local_ip), ('Local TCP Port', local_tcp_port),
      ('Remote MAC', remote_mac), ('Remote IP', remote_ip), ('Remote TCP Port', remote_tcp_port),
      ('NAT TCP Port', nat_tcp_port)
    ])

    # Install a rule to route and translate inbound packets for this NATed connection.
    msg = of.ofp_flow_mod(priority = 200,
      idle_timeout = NAT_RULE_IDLE_TIMEOUT,
      match = of.ofp_match(
        in_port = self._uplink_port,
        dl_type = ethernet.IP_TYPE,
        dl_src = remote_mac,
        dl_dst = self._gateway_mac,
        nw_proto = ipv4.TCP_PROTOCOL,
        nw_src = remote_ip,
        nw_dst = self._nat_ip,
        tp_src = remote_tcp_port,
        tp_dst = nat_tcp_port))
    msg.actions = self._get_inbound_nat_actions(local_mac, local_ip, local_tcp_port, switch_port)
    self.connection.send(msg)

    # Install a rule to route and translate outbound packets for this NATed connection.
    msg = of.ofp_flow_mod(priority = 200,
      idle_timeout = NAT_RULE_IDLE_TIMEOUT,
      match = of.ofp_match(
        in_port = switch_port,
        dl_type = ethernet.IP_TYPE,
        dl_src = local_mac,
        dl_dst = self._gateway_mac,
        nw_proto = ipv4.TCP_PROTOCOL,
        nw_src = local_ip,
        nw_dst = remote_ip,
        tp_src = local_tcp_port))
    msg.actions = self._get_outbound_nat_actions(remote_mac, nat_tcp_port)
    self.connection.send(msg)


  def _get_inbound_nat_actions(self, local_mac, local_ip, local_tcp_port, switch_port):
    return [
      of.ofp_action_dl_addr.set_src(self._gateway_mac),
      of.ofp_action_dl_addr.set_dst(local_mac),
      of.ofp_action_nw_addr.set_dst(local_ip),
      of.ofp_action_tp_port.set_dst(local_tcp_port),
      of.ofp_action_output(port = switch_port)
    ]


  def _get_outbound_nat_actions(self, remote_mac, nat_tcp_port):
    return [
      of.ofp_action_dl_addr.set_src(self._gateway_mac),
      of.ofp_action_dl_addr.set_dst(remote_mac),
      of.ofp_action_nw_addr.set_src(self._nat_ip),
      of.ofp_action_tp_port.set_src(nat_tcp_port),
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


