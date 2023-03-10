# == Class: fw_builder::post
#
# == Parameter
#
# [*logging*] Boolean
# enable logging
#
# === Requires
#
# === Examples
#
class fw_builder::post (
  Boolean $logging = $fw_builder::params::logging
) {
  assert_private()

  if ($logging) {
    $fw_builder::ip_proto_array.each | String $provider | {
      firewall {
        default:
          chain     => 'INPUT',
          provider  => $provider,
          jump      => 'LOG',
          limit     => $fw_builder::limit,
          log_level => '4';
        "889 log RST dropped inbound chain for provider ${provider}":
          log_prefix => "[${provider.upcase()} RST RST] dropped";
        "900 log dropped inbound chain for provider ${provider}":
          proto      => all,
          log_prefix => "[${provider.upcase()} INPUT] dropped ",
      }
    }
  }

  $fw_builder::ip_proto_array.each | String $provider | {
    firewall {
      default:
        chain    => 'INPUT',
        provider => $provider;
      "910 deny all other inbound requests for provider ${provider}":
        before => undef,
        proto  => all,
        action => 'drop';
      "890 drop RST RST connections for provider ${provider}":
        tcp_flags => 'RST RST',
        action    => 'drop';
    }
  }
}
# vim:ts=2:sw=2
