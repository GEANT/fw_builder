# == Class: fw_builder
#
# == Authors:
#
#   Pete Pedersen<pete.pedersen@geant.org>
#   Massimiliano Adamo<massimiliano.adamo@geant.org>
#
class fw_builder (
  Fw_builder::Iplist $trusted_networks,
  Boolean $manage_docker     = false,
  Boolean $ipv4_enable       = true,
  Boolean $ipv6_enable       = true,
  Boolean $logging           = true,
  Boolean $purge_rules       = true,
  Integer $log_rotation_days = '7',
  $ipset_package_ensure      = 'present',
  $limit                     = '1000/sec'
) {

  if ! ($purge_rules) and ($manage_docker) {
    fail('cannot set purge_rules to false and manage_docker to true')
  }

  if ! ($ipv4_enable) and ! ($ipv6_enable) {
    fail('you cannot disable ipv4 and ipv6 at the same time')
  }

  if ($ipv4_enable) and ($ipv6_enable) {
    $ip_proto_array = ['ip6tables', 'iptables']
  } elsif ($ipv4_enable) and ! ($ipv6_enable) {
    $ip_proto_array = ['iptables']
  } elsif ! ($ipv4_enable) and ($ipv6_enable) {
    $ip_proto_array = ['iptables']
  }


  anchor { 'fw_builder::begin': }
  -> class {
    'firewall':;
  }
  -> class { 'fw_builder::ipset':
    ipset_package_ensure => $ipset_package_ensure,
    trusted_networks     => $trusted_networks,
    ipv4_enable          => $ipv4_enable,
    ipv6_enable          => $ipv6_enable,
    require              => Class['firewall'];
  }
  -> class { 'fw_builder::chains':
    ipv4_enable => $ipv4_enable,
    ipv6_enable => $ipv6_enable,
    require     => Class['fw_builder::ipset'];
  }
  -> class { 'fw_builder::post':
    ipv4_enable => $ipv4_enable,
    ipv6_enable => $ipv6_enable,
    limit       => $limit;
  }
  -> anchor { 'fw_builder::end': }

  class { 'fw_builder::logrotate':
    logging           => $logging,
    log_rotation_days => $log_rotation_days,
  }

  if ($purge_rules) {
    if ($facts['fw_builder_is_docker']) and ($manage_docker) {
      echo { 'Docker detected':
        message => 'not purging iptables rules set by docker';
      }
      resources { 'firewallchain':
        purge => false;
      }
      class { 'fw_builder::docker':
        ipv4_enable => $ipv4_enable,
        ipv6_enable => $ipv6_enable,
        before      => Class['fw_builder::post'],
        require     => Class['fw_builder::ipset'];
      }
    } else {
      if ($ipv4_enable) {
        firewallchain { 'FORWARD:filter:IPv4':
          ensure => present,
          policy => drop,
          purge  => true;
        }
      }
      if ($ipv6_enable) {
        firewallchain { 'FORWARD:filter:IPv6':
          ensure => present,
          policy => drop,
          purge  => true;
        }
      }
      resources { 'firewall':
        purge => true;
      }
    }
  }

}
