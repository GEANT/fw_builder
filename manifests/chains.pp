# == Class: fw_builder::chains
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
class fw_builder::chains (
  $ipv4_enable,
  $ipv6_enable
) {

  assert_private()

  if ($ipv4_enable) {
    ['udp', 'tcp', 'trust', 'public'].each | $chain | {
      firewallchain { "INPUT_${chain}:filter:IPv4":
        ensure  => present;
      }
    }
    firewall {
      default:
        chain    => 'INPUT',
        action   => accept,
        provider => 'iptables';
      '010 accept all icmp for provider iptables':
        proto    => 'icmp';
      '003 accept inbound related established rules for provider iptables':
        proto => all,
        state => ['RELATED', 'ESTABLISHED'];
    }
    firewall {
      default:
        chain    => 'INPUT',
        jump     => 'INPUT_public',
        state    => ['NEW'],
        provider => 'ip6tables';
      '090 IPv4 UDP INPUT_public for all public services':
        proto    => 'udp';
      '090 IPv4 TCP INPUT_public for all public services':
        proto    => 'tcp';
    }
    firewall { '095 IPv4 INPUT_trust this is for all ip ranges (mostly internal)':
      chain    => 'INPUT',
      proto    => all,
      state    => ['NEW'],
      jump     => 'INPUT_trust',
      ipset    => 'trusted_networks_v4 src',
      provider => 'iptables';
    }
    firewall { '001 IPv4 accept all inbound to localhost':
      chain    => 'INPUT',
      proto    => all,
      iniface  => 'lo',
      action   => accept,
      provider => 'iptables';
    }
  }

  if ($ipv6_enable) {
    ['udp', 'tcp', 'trust', 'public'].each | $chain | {
      firewallchain { "INPUT_${chain}:filter:IPv6":
        ensure  => present,
      }
    }
    firewall {
      default:
        chain    => 'INPUT',
        action   => accept,
        provider => 'ip6tables';
      '010 accept all icmp for provider ip6tables':
        proto    => 'ipv6-icmp';
      '003 accept inbound related established rules for provider ip6tables':
        proto => all,
        state => ['RELATED', 'ESTABLISHED'];
    }
    firewall {
      default:
        chain    => 'INPUT',
        jump     => 'INPUT_public',
        state    => ['NEW'],
        provider => 'ip6tables';
      '090 IPv6 UDP INPUT_public for all public services':
        proto    => 'udp';
      '090 IPv6 TCP INPUT_public for all public services':
        proto    => 'tcp';
    }
    firewall { '095 IPv6 INPUT_trust this is for all ip ranges (mostly internal)':
      chain    => 'INPUT',
      proto    => all,
      state    => ['NEW'],
      jump     => 'INPUT_trust',
      ipset    => 'trusted_networks_v6 src',
      provider => 'ip6tables';
    }
    firewall { '001 IPv6 accept all inbound to localhost6':
      chain    => 'INPUT',
      proto    => all,
      iniface  => 'lo',
      action   => accept,
      provider => 'ip6tables';
    }
  }

}
# vim:ts=2:sw=2
