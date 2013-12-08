from datetime import datetime
from time import time

from pox.lib.packet import arp, chassis_id, ethernet, ipv4, lldp, port_id

def _format_metric_name(name):
  return '{:<20}'.format(name + ':')


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
    self._start_time = time()
    self._metrics = {}
    self._metrics_order = []
    self._is_in_packet = False
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


    self.metric('Logger Start', self._start_time)
    self._out.write(_format_metric_name('Logger Start'))
    self._out.write('{}\n'.format(self._start_time))
    self._write_entry_end()


  def _handle_arp(self, arp_pkt):
    self.metric('ARP', [
      ('Opcode', PacketLogger._arp_opcode_to_name[arp_pkt.opcode]),
      ('Hardware Source', arp_pkt.hwsrc),
      ('Protocol Source', arp_pkt.protosrc),
      ('Hardware Dest.', arp_pkt.hwdst),
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


  def _raise_exception(self, ex):
    self._out.write('{}{}\n'.format(_format_metric_name('Exception'), ex.message))
    self._out.flush()
    raise ex


  def _write_packet(self):
    self.metric('EOP', ('Implicit', self._is_in_packet))

    for name in self._metrics_order:
      fields = self._metrics[name]
      self._out.write(_format_metric_name(name))
      for field, value in fields:
        if field is None:
          self._out.write(str(value) + '; ')
        else:
          self._out.write('{} = {}; '.format(field, str(value)))
      self._out.write('\n')
    self._write_entry_end()


  def _write_entry_end(self):
    self._out.write('-' * 20)
    self._out.write('\n')
    self._out.flush()


  """
  Starts a new packet entry in the log and records packet attributes.
  """
  def new_packet(self, dpid, of_packet_in, ether_pkt):
    if not self._is_open:
      self._raise_exception(Exception('Packet logger is closed.'))

    if self._is_in_packet:
      self._write_packet()
    self._is_in_packet = True

    self._metrics.clear()
    self._metrics_order = []

    self.metric('Timestamp', datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f'))
    self.metric('Start Time', time() - self._start_time)
    self.metric('Hardware', [
      ('Switch', dpid),
      ('In Port', of_packet_in.in_port),
      ('Buffer ID', of_packet_in.buffer_id)
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
      self._raise_exception(Exception('Packet logger is closed.'))

    fields = self._metrics.get(name)
    if fields is None:
      fields = []
      self._metrics[name] = fields
      self._metrics_order.append(name)

    if isinstance(value, list):
      fields.extend(value)
    elif isinstance(value, tuple):
      fields.append(value)
    else:
      fields.append((None, value))


  """
  Logs an action being taken on a packet, and a description/reason.
  """
  def action(self, action, description):
    if not self._is_open:
      self._raise_exception(Exception('Packet logger is closed.'))

    values = [ (None, action) ]
    if isinstance(description, list):
      values.extend(description)
    else:
      values.append(('Description', description))

    self.metric('Action', values)


  """
  Logs the end of the processing of a packet.
  """
  def end_packet(self):
    if self._is_in_packet:
      self._is_in_packet = False
      self._write_packet()


  """
  Closes the packet logger.
  """
  def close(self):
    if self._is_open:
      try:
        if self._is_in_packet:
          self.end_packet()

        self._out.close()
      finally:
        self._is_open = False
