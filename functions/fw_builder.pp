# == Function: fw_builder::fw_builder
#
# tries to build the ipset and firewall rule set comming from hieradata 
# this function only affects the host firewall not the VMware crap
#
# == Example
#
# Please check the main README: ../README.md
#
function fw_builder::fw_builder() {
  # time to retrieve hieradata for the firewall 
  #
  $fw_conf = lookup('firewall', Hash, 'deep')
  $fw_conf_hash = { fw_conf => $fw_conf }

  file {
    ['/etc/facter/', '/etc/facter/facts.d/']:
      ensure => 'directory';
    '/etc/facter/facts.d/fw_conf.yaml':
      content => to_yaml($fw_conf_hash),
  }

  # first define if we need to generate all the custom ipset lists that have been
  # define, for latter use 
  #
  if ($fw_conf['custom_ipset']) {

    $ipsets = $fw_conf['custom_ipset'].keys().map |$name| {

      # check if key names are valid
      #
      $ipset_keys = keys($fw_conf['custom_ipset'][$name])
      $ipset_keys.each |$key| {
        unless $key in ['list', 'hieradata', 'puppetdb'] {
          fail("${key} is not a valid key. Valid keys are: 'list', 'hieradata', and 'puppetdb'")
        }
      }

      # ipset name is limited to 26 characters: 7 characters are surrounding the string as follows: "fwb_${name}_v4"
      if $name.length() > 19 { fail("ipset name ${name} cannot exceed 19 characters") }

      # getting list of IPs, Networks, and/or FQDNs
      #
      if ($fw_conf['custom_ipset'][$name]['list']) {
        $_list = $fw_conf['custom_ipset'][$name]['list']
        if $_list !~ Fw_builder::List { fail("${_list} types are not IPs, Networks or FQDNs") }
        $list = fw_builder::parser($_list)
      }

      # getting IPs or FQDNs from 'hieradata' lookup, if 'hieradata' is defined
      #
      if ($fw_conf['custom_ipset'][$name]['hieradata']) {
        $_hieradata = flatten($fw_conf['custom_ipset'][$name]['hieradata'].map |$hash_name| {
          lookup($hash_name, Array, 'deep')
        })
        if $_hieradata !~ Fw_builder::List { fail("${_hieradata} types are not IPs, Networks or FQDNs") }
        $hieradata = fw_builder::parser($_hieradata)
      }

      # querying 'puppetDB', if 'puppetdb' is defined
      #
      if ($fw_conf['custom_ipset'][$name]['puppetdb']) {
        # check if "env" was defined and it contains proper values
        $pdb_filter = join(
          $fw_conf['custom_ipset'][$name]['puppetdb'].map |$hash| {
            if $hash['env'] {
              # wrong setting for "env" creates an empty fact and breaks puppet on the host
              if $hash['env'] !~ Fw_builder::Puppet_environment {
                fail("${hash['env']} is an unacceptable value for 'env'. Valid values are 'test', 'uat', or 'production'")
              } else {
                if $hash['env'] =~ String {
                  $env_string = "= '${hash['env']}'"
                } elsif $hash['env'] =~ Array {
                  # if we use something like [%{::environment}, 'test'] we need unique
                  $_env_string = join(unique($hash['env']), '|')
                  $env_string = "~ '(${_env_string})'"
                }
              }
            } else {
              # we use the same environment of the agent
              $env_string = "= '${::environment}'"
            }
            "facts.fqdn ~ '${hash[name]}' and facts.agent_specified_environment ${env_string}"
          },
          ') or ('
        )
        # $pdb_filter example: 
        # facts.fqdn ~ 'nomad\d+\.geant\.org' and facts.agent_specified_environment = 'test') or (facts.fqdn ~ ... 
        $query = "inventory[facts.hostname, facts.ipaddress, facts.ipaddress6, facts.fqdn] { (${pdb_filter}) order by certname }"
        $full_list = puppetdb_query($query)
        $searchlist = $full_list.map |$hash| { $hash['facts.ipaddress']} + $full_list.map |$hash| { $hash['facts.ipaddress6'] }
        # an empty list creates an empty fact, it means that the regex is not working
        # and the firewall setting is ineffective. We better fail here
        if $searchlist !~ Fw_builder::Iplist {
          fail('PuppetDB query for Firewall Builder did not match any host. You may want to review you regex')
        }
      }

      # create a list with all the ip's 
      #
      $full_ip_list = flatten([$list, $fqdnlist, $searchlist, $hieradata]).filter |$val| { $val =~ NotUndef }

      # if we have a non zero list then let's create / update it 
      #
      if $full_ip_list.length() > 0 {
        $full_ip_list_sorted = sort($full_ip_list)
        # time to create the ipset with all the data/ip's .... 
        ipset::set {
          default:
            type   => 'hash:net',
            ensure => 'present';
          "fwb_${name}_v4":
            set  => $full_ip_list_sorted.filter |$ip| { $ip =~ Stdlib::IP::Address::V4 };
          "fwb_${name}_v6":
            set     => $full_ip_list_sorted.filter |$ip| { $ip =~ Stdlib::IP::Address::V6 },
            options => {
              'family' => 'inet6'
            }
        };
        { $name => $full_ip_list }
      }
    }
  } else {
    $ipsets = []
  }

  file { '/etc/facter/facts.d/fw_ipsets.yaml':
    content => to_yaml({fw_ipsets => $ipsets});
  }

  # emit warning if the key is deinfed and it's empty
  #
  ['public', 'trust'].each() |$zone| {
    if $zone in $fw_conf and empty($fw_conf[$zone]) {
      echo { "WARNING FW Builder zone ${zone}":
        message => "key '${zone}' is defined but it\'s empty";
      }
    }
  }

  # this section will setup / create all the fwb rules
  #
  ['public', 'trust'].each() |$zone| {
    if $fw_conf[$zone] {
      $fw_conf[$zone].each |$name , $conf| {
        $ports_spaces = $conf['port'] ? {
          Array => join($conf['port'], ' '),
          String => $conf['port'],
          Integer => $conf['port'],
          default => fail("'port' can only be Array, String or Integer")
        }

        if $conf['ipset'] {
          # this part will generate all the rule that are restricted with ipset
          $ipset_array = $conf['ipset'] ? {
            String => [$conf['ipset']],
            Array => $conf['ipset'],
            default => fail("'ipset' can only be Array, or String")
          }
          $ipset_array.each |$ipset_element| {
            firewall_multi {
              default:
                chain  => "INPUT_${zone}",
                proto  => $conf[proto],
                dport  => $conf[port],
                action => accept;
              "150 fwb INPUT_${zone} Allow inbound ${name} port(s): ${ports_spaces} ipset:fwb_${ipset_element}_v4":
                ipset    => "fwb_${ipset_element}_v4 src",
                provider => 'iptables';
              "150 fwb INPUT_${zone} Allow inbound ${name} port(s): ${ports_spaces} ipset:fwb_${ipset_element}_v6":
                ipset    => "fwb_${ipset_element}_v6 src",
                provider => 'ip6tables';
            }
          }
        } else {
          firewall_multi {
            default:
              chain  => "INPUT_${zone}",
              proto  => $conf[proto],
              dport  => $conf[port],
              action => accept;
            "150 fwb INPUT_${zone} Allow inbound ${name} port(s): ${ports_spaces} v4":
              provider => 'iptables';
            "150 fwb INPUT_${zone} Allow inbound ${name} port(s): ${ports_spaces} v6":
              provider => 'ip6tables';
          }
        }
      }
    } else {
      echo { "FW Builder zone ${zone}": message => "No work to do in ${zone} !! (this could be normal)" }
    }
  }

  [$fw_conf, $ipsets]
}
