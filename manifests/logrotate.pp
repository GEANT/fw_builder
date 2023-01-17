# == Class: fw_builder
#
# == Authors:
#
#   Pete Pedersen<pete.pedersen@geant.org>
#   Massimiliano Adamo<massimiliano.adamo@geant.org>
#
class fw_builder::logrotate (
  $logging,
  $log_rotation_days,
) {

  assert_private()

  file { ['/var/log/iptables.log', '/var/log/ip6tables.log']: ensure => file; }

  if ($logging) {
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
