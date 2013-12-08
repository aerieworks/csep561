from pox.core import core
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.revent import Event, EventMixin


"""
Event raised when an address is added to the ARP table.
"""
class ArpEntryAddedEvent(Event):

  def __init__(self, ip, mac):
    super(ArpEntryAddedEvent, self).__init__()
    self.ip = ip
    self.mac = mac


"""
An ARP table cache, mapping IP addresses to Ethernet MAC addresses.
"""
class ArpTable(EventMixin):

  logger = core.getLogger()
  _eventMixin_events = set([ ArpEntryAddedEvent ])

  def __init__(self, name):
    self.name = name
    self._ip_to_mac = {}

  def add(self, ip, mac):
    if is_special_ip(ip) or is_special_mac(mac):
      # Do not put "special" IP or MAC addresses in the ARP table.
      return

    ip_key = str(ip)
    mac_value = EthAddr(mac)
    old_mac = self._ip_to_mac.get(ip_key)
    if old_mac != mac_value:
      self._ip_to_mac[ip_key] = mac_value
      ArpTable.logger.debug('{}: Added entry {} => {}'.format(self.name, ip_key, str(mac)))
      self.raiseEvent(ArpEntryAddedEvent, IPAddr(ip), mac_value)


  def lookup(self, ip):
    return self._ip_to_mac.get(str(ip))


  def __str__(self):
    return str(self._ip_to_mac)


"""
IP addresses with special meanings and/or purposes.
"""
class SpecialIps:
  # Sender IP address to use when sending an ARP probe.
  ARP_PROBE_SENDER = IPAddr('0.0.0.0')

  all = set([ ARP_PROBE_SENDER ])

def is_special_ip(ip):
  for special_ip in SpecialIps.all:
    if ip == special_ip:
      return True
  return False


"""
MAC addresses with special meanings and/or purposes.
"""
class SpecialMacs:
  # Broadcast MAC address instructing switches not to forward (see IEEE 802.1AB-2009).
  LLDP_BROADCAST = EthAddr('01:80:c2:00:00:0e')

  # Hardware destination for ARP requests.
  ARP_REQUEST_DESTINATION = EthAddr('00:00:00:00:00:00')

  # Target MAC address to use when sending an ARP request.
  BROADCAST = EthAddr('ff:ff:ff:ff:ff:ff')

  all = set([ LLDP_BROADCAST, ARP_REQUEST_DESTINATION, BROADCAST ])

def is_special_mac(mac):
  for special_mac in SpecialMacs.all:
    if mac == special_mac:
      return True
  return False


