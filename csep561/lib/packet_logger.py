from datetime import datetime

from pox.lib.packet import arp, chassis_id, ethernet, ipv4, lldp, port_id

class PacketLogger:

  _arp_opcode_to_name = {
    arp.REQUEST: 'REQUEST',
    arp.REPLY: 'REPLY'
  }

  _ip_protocol_to_name = {
    ipv4.ICMP_PROTOCOL: 'ICMP',
    ipv4.IGMP_PROTOCOL: 'IGMP',
    ipv4.TCP_PROTOCOL: 'TCP',
    ipv4.UDP_PROTOCOL: 'UDP'
  }

  def __init__(self, file_name):
    self._is_open = False
    self._out = open(file_name, 'a')
    self._is_open = True

    self._ether_handlers = {
      ethernet.ARP_TYPE: self._handle_arp,
      ethernet.IP_TYPE: self._handle_ip,
      ethernet.LLDP_TYPE: self._handle_lldp
    }

    self._ip_handlers = {
      ipv4.ICMP_PROTOCOL: self._handle_icmp,
      ipv4.TCP_PROTOCOL: self._handle_tcp
    }


  def _handle_arp(self, arp_pkt):
    self.metric('ARP', [
      ('Opcode', PacketLogger._arp_opcode_to_name[arp_pkt.opcode]),
      ('Protocol Source', arp_pkt.protosrc),
      ('Protocol Dest.', arp_pkt.protodst)
    ])


  def _handle_icmp(self, icmp_pkt):
    self.metric('ICMP', [
      ('Type', icmp_pkt.type),
      ('Details', str(icmp_pkt))
    ])


  def _handle_ip(self, ip_pkt):
    self.metric('IPV4', [
      ('Source', ip_pkt.srcip),
      ('Dest', ip_pkt.dstip),
      ('Protocol', PacketLogger._ip_protocol_to_name[ip_pkt.protocol])
    ])

    handler = self._ip_handlers.get(ip_pkt.protocol)
    if handler:
      handler(ip_pkt.payload)


  def _handle_lldp(self, lldp_pkt):
    tlv_count = len(lldp_pkt.tlvs)
    chassis_id_value = ' '.join([ str(ord(x)) for x in lldp_pkt.tlvs[0].id ])
    metric_values = [
      ('TLV Count', tlv_count),
      ('Chassis ID', '{} [{}]'.format(chassis_id_value, chassis_id.subtype_to_str[lldp_pkt.tlvs[0].subtype])),
      ('Port ID', '{} [{}]'.format(lldp_pkt.tlvs[1].id, port_id.subtype_to_str[lldp_pkt.tlvs[1].subtype])),
      ('TTL', lldp_pkt.tlvs[2].ttl)
    ]
    if tlv_count > 3 and lldp_pkt.tlvs[3].tlv_type == lldp.SYSTEM_DESC_TLV:
      metric_values.append(('Sys Desc', lldp_pkt.tlvs[3].payload))

    self.metric('LLDP', metric_values)


  def _handle_tcp(self, tcp_pkt):
    self.metric('TCP', [
      ('Source Port', tcp_pkt.srcport),
      ('Dest Port', tcp_pkt.dstport)
    ])


  """
  Starts a new packet entry in the log and records packet attributes.
  """
  def new_packet(self, dpid, in_port, ether_pkt):
    if not self._is_open:
      raise Exception('Packet logger is closed.')

    self._out.write('-' * 20)
    self._out.write('\n')
    self.metric('Timestamp', datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f'))
    self.metric('Hardware', [
      ('Switch', dpid),
      ('In Port', in_port)
    ])
    self.metric('Ethernet', [
      ('Source MAC', ether_pkt.src),
      ('Dest MAC', ether_pkt.dst),
      ('Type', ethernet.getNameForType(ether_pkt.type))
    ])

    handler = self._ether_handlers.get(ether_pkt.type)
    if handler:
      handler(ether_pkt.payload)


  """
  Logs packet attributes.
  """
  def metric(self, name, value):
    if not self._is_open:
      raise Exception('Packet logger is closed.')

    self._out.write('{:<20}'.format(name + ':'))
    if isinstance(value, list):
      for kv in value:
        if kv[0] is None:
          self._out.write(kv[1] + '; ')
        else:
          self._out.write('{} = {}; '.format(kv[0], str(kv[1])))
      self._out.write('\n')
    else:
      self._out.write('{}\n'.format(value))
    self._out.flush()


  """
  Logs an action being taken on a packet, and a description/reason.
  """
  def action(self, action, description):
    if not self._is_open:
      raise Exception('Packet logger is closed.')

    values = [ (None, action) ]
    if isinstance(description, list):
      values.extend(description)
    else:
      values.append(('Description', description))

    self.metric('Action', values)


  """
  Closes the packet logger.
  """
  def close(self):
    if self._is_open:
      try:
        self._out.close()
      finally:
        self._is_open = False
