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
  $ipv4_enable = $fw_builder::params::ipv4_enable,
  $ipv6_enable = $fw_builder::params::ipv6_enable
) {

  assert_private()

  $test = $fw_builder::ip_proto_array

  echo { "test ${test}":; }

  $fw_builder::ip_proto_array.each | String $provider | {
    $trusted_net = $provider ? {
      'iptables' => 'trusted_networks_v4',
      'ip6tables' => 'trusted_networks_v6',
    }
    $icmp_proto = $provider ? {
      'iptables' => 'icmp',
      'ip6tables' => 'ipv6-icmp',
    }
    firewall { "001 accept all inbound to localhost for ${provider}":
      chain    => 'INPUT',
      proto    => all,
      iniface  => 'lo',
      action   => accept,
      provider => $provider;
    }
    firewall {
      default:
        chain    => 'INPUT',
        action   => accept,
        provider => 'iptables';
      "010 accept all icmp for ${provider}":
        proto    => $icmp_proto;
      "003 accept inbound related established rules for ${provider}":
        proto => all,
        state => ['RELATED', 'ESTABLISHED'];
    }

    firewall {
      default:
        chain    => 'INPUT',
        jump     => 'INPUT_public',
        state    => ['NEW'],
        provider => $provider;
      "090 UDP INPUT_public for all public services for ${provider}":
        proto    => 'udp';
      "090 TCP INPUT_public for all public services for ${provider}":
        proto    => 'tcp';
    }
    firewall { "095 INPUT_trust this is for all ip ranges (mostly internal) for ${provider}":
      chain    => 'INPUT',
      proto    => all,
      state    => ['NEW'],
      jump     => 'INPUT_trust',
      ipset    => "${trusted_net} src",
      provider => $provider;
    }

  }

  if ($ipv4_enable) {
    ['udp', 'tcp', 'trust', 'public'].each | $chain | {
      firewallchain { "INPUT_${chain}:filter:IPv4":
        ensure  => present;
      }
    }
  }

  if ($ipv6_enable) {
    ['udp', 'tcp', 'trust', 'public'].each | $chain | {
      firewallchain { "INPUT_${chain}:filter:IPv6":
        ensure  => present,
      }
    }
  }

}
# vim:ts=2:sw=2
