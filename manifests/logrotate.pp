# == Class: fw_builder
#
# == Parameter
#
# [*logging*] Boolean
# enable logging
#
# [*log_rotation_days*] Integer
# define log retention in days
#
# === Requires
#
# === Examples
#
class fw_builder::logrotate (
  Boolean $logging           = $fw_builder::params::logging,
  Integer $log_rotation_days = $fw_builder::params::log_rotation_days
) {
  assert_private()

  file { ['/var/log/iptables.log', '/var/log/ip6tables.log']: ensure => file; }

  if ($fw_builder::logging) {
    logrotate::rule { 'iptables':
      rotate       => $log_rotation_days,
      dateext      => true,
      copytruncate => true,
      missingok    => true,
      compress     => true,
      ifempty      => false,
      path         => '/var/log/ip*tables.log';
    }
  }
}
