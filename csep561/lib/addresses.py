from pox.lib.addresses import EthAddr, IPAddr


"""
An ARP table cache, mapping IP addresses to Ethernet MAC addresses.
"""
class ArpTable:

  def __init__(self):
    self._ip_to_mac = {}

  def add(self, ip, mac):
    if is_special_ip(ip) or is_special_mac(mac):
      # Do not put "special" IP or MAC addresses in the ARP table.
      return

    self._ip_to_mac[str(ip)] = EthAddr(mac)


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

  # Target MAC address to use when sending an ARP request.
  ARP_REQUEST_TARGET = EthAddr('ff:ff:ff:ff:ff:ff')

  all = set([ LLDP_BROADCAST, ARP_REQUEST_TARGET ])

def is_special_mac(mac):
  for special_mac in SpecialMacs.all:
    if mac == special_mac:
      return True
  return False


