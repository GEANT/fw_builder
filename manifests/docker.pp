# == Class: fw_builder::docker
#
# Pre IPtables allows several icmp type, loopback connection
# either on IPv6 and IPv4
#
# This class opens the firewall to Geant specific servers
#
# === Parameters
#
# === Requires
#
# === Examples
#
# === ToDo
#
# ADD SUPPORT FOR IPv6
#
class fw_builder::docker {
  assert_private()

  firewallchain { ['INPUT:filter:IPv4', 'OUTPUT:filter:IPv4']:
    purge  => true,
    ignore => ['docker', 'br-', 'cali-', 'KUBE'],
  }

  firewallchain { 'FORWARD:filter:IPv4':
    purge  => true,
    ignore => ['docker', 'br-', 'cali-', 'KUBE'],
  }

  firewallchain { ['DOCKER:nat:IPv4', 'DOCKER:filter:IPv4']:
    purge  => false,
  }

  firewallchain { 'POSTROUTING:nat:IPv4':
    purge  => false,
  }

  firewallchain {
    [
      'INPUT:nat:IPv4', 'PREROUTING:nat:IPv4',
      'OUTPUT:nat:IPv4', 'PREROUTING:mangle:IPv4',
      'POSTROUTING:mangle:IPv4', 'INPUT:mangle:IPv4',
      'FORWARD:mangle:IPv4', 'OUTPUT:mangle:IPv4',
      'OUTPUT:raw:IPv4', 'PREROUTING:raw:IPv4',
    ]:
      purge  => true,
      ignore => ['DOCKER', 'cali-', 'KUBE'],
  }

  # this is is for kube / cali
  firewallchain {
    [
      'cali-PREROUTING:mangle:IPv4', 'cali-failsafe-in:mangle:IPv4',
      'cali-from-host-endpoint:mangle:IPv4', 'cali-failsafe-in:raw:IPv4',
      'cali-failsafe-out:raw:IPv4', 'cali-from-host-endpoint:raw:IPv4',
      'cali-to-host-endpoint:raw:IPv4', 'KUBE-SERVICES:filter:IPv4',
    ]:
      purge  => false,
  }
}
# vim:ts=2:sw=2
