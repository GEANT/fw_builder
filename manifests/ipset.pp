# Class: fw_builder::ipset
#
#
class fw_builder::ipset (
  $ipv4_enable = $fw_builder::params::ipv4_enable,
  $ipv6_enable = $fw_builder::params::ipv6_enable
) {

  assert_private()

  $trusted_net = $fw_builder::trusted_networks

  $firewall_service = $facts['os']['family'] ? {
    'Debian' => 'netfilter-persistent.service',
    default => undef
  }

  $packages = "${facts['os']['family']}_${facts['os']['release']['major']}" ? {
    'RedHat_6' => ['ipset'],
    default => undef
  }

  class { 'ipset':
    packages         => $packages,
    package_ensure   => $fw_builder::ipset_package_ensure,
    firewall_service => $firewall_service
  }

  if ($ipv4_enable) {
    $trusted_networks_v4 = $trusted_net.filter |$ip_range| { $ip_range =~ Stdlib::IP::Address::V4 }
    ipset::set { 'trusted_networks_v4':
      ensure => 'present',
      type   => 'hash:net',
      set    => $trusted_networks_v4;
    }
  }

  if ($ipv6_enable) {
    $trusted_networks_v6 = $trusted_net.filter |$ip_range| { $ip_range =~ Stdlib::IP::Address::V6 }
    ipset::set { 'trusted_networks_v6':
      ensure  => 'present',
      type    => 'hash:net',
      set     => $trusted_networks_v6,
      options => {'family' => 'inet6'}
    }
  }

}
# vim:ts=2:sw=2
