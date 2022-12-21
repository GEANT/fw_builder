# Module for Firewall Builder

## Table of Contents

1. [Firewall builder](#firewall-builder)
2. [Fail2ban allow list](#fail2ban-allow-list)
3. [Authors](#authors)

## Firewall builder <a name="firewall-builder"></a>

This is a configuration example in Hiera:

```yaml
firewall:
  # in this section you can group IPs
  custom_ipset:
    authz:
      # specify a list of IPs, Networks, FQDNs under the name "authz"
      # FQDN elements must have at least A or AAAA record 
      list:
        - '150.254.166.19'
        - '150.254.208.67'
        - '2001:718:ff05:206::155'
        - '2001:718:ff05:206::166'
        - "www.geant.org"
        - "www.google.uz"
    rackspace:
      # specify a list of IPs or Networks under the name "rackspace"
      list:
        - '134.213.42.227'
        - '2a00:1a48:15e1:4:33d7:40d8:d11f:abb5'
        - '134.213.42.228'
        - '2a00:1a48:15e1:4:31d5:3397:4fd6:7ad3'
        - '10.100.4.0/24'
        - "2001:630:280:20::/64"
      # run a hieradata lookup against an array of IPs, FQDNs existing in
      # hiera and group them under the name "rackspace"
      hieradata:
        - "haproxy_servers"
        - "db_servers"
      # run a query on the puppetDB, produces a list of IPs
      # and group them under the name "rackspace". 
      # An empty match will cause a puppet fail
      puppetdb:
        - { 'name': 'myserver\d+\.geant\.org' }  # by default it matches the same environment of the host
        - { 'name': 'otherserver\d+\.geant\.org', 'env': 'uat' }
        - { 'name': 'moreservers\d+\.geant\.org', 'env': ['uat', 'test'] }
  # this section contains addresses NOT belonging to the internal network
  # if you do not specify an "ipset", the connection will be open world-wide
  # ipsets from the public section will be added to "fail2ban" ignoreip list
  public:
    # open http/https to everyone
    web:
      port: [80, 443]
    # open ldap/ldaps to ipset groups "authz" and "rackspace"
    ldap_ports:
      port: [389, 636]
      proto: ['tcp']
      ipset: ["authz", "rackspace"]
  # this section contains addresses belonging to the internal network
  # if you do not specify an "ipset" it will open to everyone in the internal network
  trust:
    # open the specified ports to all internal networks
    trusted_ports:
      port: [389, 443, 636, 3000, 3001, 3268, 6379, 6380, 8000]
      proto: ['tcp']
    # open DB ports to "haproxy_servers"
    db_ports:
      port: [3306]
      proto: ['tcp']
      ipset: "haproxy_servers"
```

## Fail2ban allow list <a name="fail2ban-allow-list"></a>

ipsets listed in the "public" section of the firewall builder will be added to Fail2ban allow-list.

## Authors

[Pete Pedersen](mailto:pete.pedersen@geant.org)
[Massimiliano Adamo](mailto:massimiliano.adamo@geant.org)