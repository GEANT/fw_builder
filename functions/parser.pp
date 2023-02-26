# == Function: fw_builder::parser
#
# parse elements and add subnet if necessary
# it does not work quite well with IPv4 and ipset but it doesn't cause any issue
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
function fw_builder::parser(Array $ip_array) >> Array {
  if $ip_array.length > 0 {
    $unflattened_cidr_array = $ip_array.map |$ip| {
      if $ip =~ Stdlib::IP::Address::V4::Nosubnet {
        "${ip}/32"
      } elsif $ip =~ Stdlib::IP::Address::V6::Nosubnet {
        "${ip}/128"
      } elsif $ip =~ Stdlib::IP::Address::V4::CIDR or $ip =~ Stdlib::IP::Address::V6::CIDR {
        $ip
      } elsif $ip =~ Stdlib::Fqdn {
        $ipv4 = dns_a($ip)[0]
        $ipv6 = dns_aaaa($ip)[0]
        if ($ipv4) {
          $ipv4_subnetted = "${ipv4}/32"
        } else {
          $ipv4_subnetted = undef
        }
        if ($ipv6) {
          $ipv6_subnetted = downcase("${ipv6}/128")
        } else {
          $ipv6_subnetted = undef
        }
        # if we cannot resolve either ipv4 and ipv6 we fail here
        if $ipv4 == undef and $ipv6 == undef { fail("${ip} does not have a DNS entry. Please amend the configuration") }
        [$ipv4_subnetted, $ipv6_subnetted]
      }
    }
    $cidr_array_with_undef = unique(flatten($unflattened_cidr_array))
    $cidr_array = $cidr_array_with_undef.filter | $item | { $item !~ Undef }
  } else {
    $cidr_array = []
  }

  $cidr_array
}
