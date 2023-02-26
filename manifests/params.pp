# == Class: fw_builder
#
# == Authors:
#
#   Pete Pedersen<pete.pedersen@geant.org>
#   Massimiliano Adamo<massimiliano.adamo@geant.org>
#
class fw_builder::params {
  # whether to purge rule not defined in puppet
  $purge_rules = true

  # avoid that docker rules are being overwritten if purge is set to true
  $manage_docker = false

  # enable iptables provider
  $ipv4_enable = true

  # enable ip6tables provider
  $ipv6_enable = true

  # enable logging
  $logging = true

  # define log retention daysn
  $log_rotation_days = 7

  # ipset package version
  $ipset_package_ensure = 'present'

  # whether to limit RST and dropped connections on post.pp
  $limit = '1000/sec'
}
