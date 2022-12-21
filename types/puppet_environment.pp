#
# @summary Allowed Puppet Environments
#
#
type Fw_builder::Puppet_environment = Variant[
  Enum[
    'test',
    'uat',
    'production'
  ],
  Array[Enum[
    'test',
    'uat',
    'production'
    ]
  ]
]
