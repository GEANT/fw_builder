# == Class: fw_builder
#
# == Parameters
#
# [*trusted_networks*] Fw_builder::Iplist
# Array of ipv4/ipv6 CIDR/Address
#
# [*purge_rules*] Boolean
# Purge rules not defined via Puppet
#
# [*manage_docker*] Boolean
# If purge rules is set to true, avoid purging rules set by Docker
#
# [*ipv4_enable*] Boolean
# enable iptables provider
#
# [*ipv6_enable*] Boolean
# enable ip6tables provider
#
# [*logging*] Boolean
# enable logging
#
# [*log_rotation_days*] Integer
# define log retention in days
#
# [*ipset_package_ensure*] String
# ipset version
#
# [*limit*] Variant[Undef, String]
# define limit for RST and Dropped connection on post.pp
#
# === Requires
#
# === Examples
#
# == Authors:
#
#   Pete Pedersen<pete.pedersen@geant.org>
#   Massimiliano Adamo<massimiliano.adamo@geant.org>
#
class fw_builder (
  Fw_builder::Iplist $trusted_networks,
  Boolean $manage_docker       = $fw_builder::params::manage_docker,
  Boolean $ipv4_enable         = $fw_builder::params::ipv4_enable,
  Boolean $ipv6_enable         = $fw_builder::params::ipv6_enable,
  Boolean $logging             = $fw_builder::params::logging,
  Boolean $purge_rules         = $fw_builder::params::purge_rules,
  Integer $log_rotation_days   = $fw_builder::params::log_rotation_days,
  Optional[String] $limit      = $fw_builder::params::limit,
  String $ipset_package_ensure = $fw_builder::params::ipset_package_ensure
) inherits fw_builder::params {
  if ! ($purge_rules) and ($manage_docker) {
    fail('cannot set purge_rules to false and manage_docker to true')
  } elsif ! ($ipv4_enable) and ! ($ipv6_enable) {
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
  -> class { 'firewall':; }
  -> class { 'fw_builder::ipset':; }
  -> class { 'fw_builder::chains':; }
  -> class { 'fw_builder::post':; }
  -> anchor { 'fw_builder::end': }

  include fw_builder::logrotate

  if ($purge_rules) {
    if ($facts['fw_builder_is_docker']) and ($manage_docker) {
      echo { 'Docker detected':
        message => 'not purging iptables rules set by docker';
      }
      resources { 'firewallchain':
        purge => false;
      }
      class { 'fw_builder::docker':
        before  => Class['fw_builder::post'],
        require => Class['fw_builder::ipset'];
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
