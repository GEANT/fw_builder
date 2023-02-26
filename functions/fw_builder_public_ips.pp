# == Function: fw_builder::fw_builder_public_ips
#
# create an array of IPs listed in the public section
# of the firewall builder.
#
# === Parameters
#
# [*facts_fw_conf*]
#   custom fact: fw builder configuration, including the public IPs
#
# [*facts_ipsets*]
#   custom fact: ipsets pushed by fw builder
#
# === Variables
#
# [*public_ips*]
#   IPs without subnet
#
# [*public_cidr*]
#   IPs with subnet
#
function fw_builder::fw_builder_public_ips(
  Variant[String, Hash, Undef] $facts_fw_conf,
  Optional[Array] $facts_ipsets
) >> Array {
  #
  # when puppet runs for the first time these facts are not available
  if $facts_fw_conf =~ Undef or $facts_ipsets =~ Undef {
    $public_ipsets = []
    # if public is empty it's seen as empty string
  } elsif $facts_fw_conf['public'] =~ String or  $facts_fw_conf['public'] =~ Undef {
    $public_ipsets = []
  } else {
    # if public is present and contains some value
    if 'public' in $facts_fw_conf {
      $facts_fw_conf_public = $facts_fw_conf['public']

      # create a list of lists with all the ipsets in public
      $unflattened_public_ipsets = $facts_fw_conf_public.map |$app_key, $app_value| {
        if 'ipset' in keys($facts_fw_conf_public[$app_key]) {
          $facts_fw_conf_public[$app_key]['ipset']
        }
      }

      # flatten the list of list into a list with unique elements, and remove any Undef
      $public_ipsets_with_undef = unique(flatten($unflattened_public_ipsets))
      $public_ipsets = $public_ipsets_with_undef.filter |$item| { $item !~ Undef }
    } else {
      $public_ipsets = []
    }
  }

  # if we got ipsets in public, we parse them, we collect the corresponding IPs
  # and we add them to "public_cidr" list
  #
  if $public_ipsets.length > 0 {
    # create a list of lists with all the IPs associated with the ipsets in public
    $unflattened_public_ips = $facts_ipsets.map |$index, $value| {
      if keys($facts_ipsets[$index])[0] in $public_ipsets {
        $key_name = keys($facts_ipsets[$index])[0]
        $facts_ipsets[$index][$key_name]
      }
    }

    # flatten the list of list into a list with unique elements, and remove any Undef
    $public_ips_with_undef = unique(flatten($unflattened_public_ips))
    $public_ips = $public_ips_with_undef.filter | $item | { $item !~ Undef }

    # add /32 to IPv4, add /128 to IPv6, add nothing to CIDR
    $public_cidr = $public_ips.map |$ip| {
      if $ip =~ Stdlib::IP::Address::V4::Nosubnet {
        "${ip}/32"
      } elsif $ip =~ Stdlib::IP::Address::V6::Nosubnet {
        "${ip}/128"
      } elsif $ip =~ Stdlib::IP::Address::V4::CIDR or $ip =~ Stdlib::IP::Address::V6::CIDR {
        $ip
      }
    }
  } else {
    # there are no ipsets in public: we don't need to change fail2ban
    $public_cidr = []
  }

  $public_cidr
}
