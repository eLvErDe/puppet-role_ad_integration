#
# @summary Integrate Linux machine into Active Directory, including domain join, pam, sshd, ssh keys in AD, sudo, FS extended ACLs, motd
#
# @example role_ad_integration
#   class { 'role_ad_integration':
#     domain  => 'domain.local',
#     servers => ['server1.domain.local', 'server2.domain.local'],
#     ad_join_username => 'account-to-use',
#     ad_join_password => 'p4ssw0rd',
#     ad_join_machines_ou => 'OU=machines,DC=domain,DC=local',
#     ad_gpo_map_remote_interactive => ['+xrdp-sesman'],
#     shell   => '/bin/bash',
#     homedir => '/home/%d/%u',
#     allowed_groups => ['Administrators', 'Users'],
#     admin_groups => ['Administrators'],
#     sudo_by_group => {'Users' => ['ALL=(root) NOPASSWD:/usr/sbin/reboot', 'ALL=(root) NOPASSWD:/usr/sbin/poweroff']}
#     read_acl_by_path => {'/var/log': ['Users']},
#     write_acl_by_path => {'/etc': ['Administrators'], '/opt': ['Administrators']},
#     motd => 'This is a restricted server',
#   }
#
# @param ignore_ad_config
#  Skip everything, defaults to true for safety
#
# @param domain
#  Active Directory domain (DNS) name
#
# @param ad_join_username
#  Username to use to join machine to AD domain
#
# @param ad_join_password
#  Password to use to join machine to AD domain
#
# @param ad_join_machines_ou
#  Target OU to join machines in, e.g: OU=machines,DC=domain,DC=local
#
# @param ad_gpo_map_remote_interactive
#  Service allowed for remote interactive login, +sshd is implicit here and can be disabled with -sshd, +xrdp-sesman can be used to allow xrdp
#
# @param servers
#  List of AD servers *FQDN*, it has to be FQDNs
#
# @param shell
#  Force the following shell to all users, can be either an absolute path or nologin (will get nologin path depending on distro)
#
# @param homedir
#  Force home directory to given path, %d for domain, %u for username
#
# @param allowed_groups
#  List of AD groups allowed to login (letter, digit, dot, dash, underscore, space, minimum 3 chars)
#
# @param admin_groups
#  List of AD groups that will get full sudo access
#
# @param sudo_by_group
#  Hashmap containing list of additional sudo entry indexed by group name
#
# @param read_acl_by_path
#  Hashmap containing list of groups to set r-x extended ACL indexed by folder path

# @param write_acl_by_path
#  Hashmap containing list of groups to set rwx extended ACL indexed by folder path
#
# @param motd
#  Custom /etc/motd file content, optional
#

class role_ad_integration (
  Boolean $ignore_ad_config = true,
  Stdlib::Fqdn $domain = undef,
  Pattern[/\A[a-zA-Z0-9\.\-_ ]{3,}\z/] $ad_join_username = undef,
  String[1] $ad_join_password = undef,
  Pattern[/\A(OU\=|ou\=)/] $ad_join_machines_ou = undef,
  Array[Pattern[/\A(\+|-)[a-zA-Z0-9\.\-_ ]+\z/]] $ad_gpo_map_remote_interactive = [],
  Array[Stdlib::Fqdn] $servers = undef,
  Variant[Stdlib::Unixpath, Enum['nologin']] $shell = 'nologin',
  Stdlib::Unixpath $homedir = '/home/%d/%u',
  # Removed space from group name because hercules-team/augeasproviders_ssh does not like it
  Array[Pattern[/\A[a-zA-Z0-9\.\-_]{3,}\z/]] $allowed_groups = [],
  Array[Pattern[/\A[a-zA-Z0-9\.\-_]{3,}\z/]] $admin_groups = [],
  Hash[Pattern[/\A[a-zA-Z0-9\.\-_]{3,}\z/], Array[String[1]]] $sudo_by_group = {},
  Hash[Stdlib::Unixpath, Struct[{
    groups => Array[Pattern[/\A[a-zA-Z0-9\.\-_]{3,}\z/], 1],
    mask   => Optional[Pattern[/\A(r|\-)(w|\-)(x|\-)\z/]],
  }]] $read_acl_by_path = {},
  Hash[Stdlib::Unixpath, Struct[{
    groups => Array[Pattern[/\A[a-zA-Z0-9\.\-_]{3,}\z/], 1],
    mask   => Optional[Pattern[/\A(r|\-)(w|\-)(x|\-)\z/]],
  }]] $write_acl_by_path = {},
  Optional[String] $motd = undef,
) {

  if (!$ignore_ad_config) {

    if ($::operatingsystem == 'Debian' and String($::operatingsystemmajrelease) in ['10', '11']) {
      $nologin_path = '/usr/sbin/nologin'
    } elsif ($::operatingsystem == 'CentOS' and String($::operatingsystemmajrelease) in ['7']) {
      $nologin_path = '/sbin/nologin'
    } else {
      fail("Unsupported ::operatingsystem ${::operatingsystem} ::operatingsystemmajrelease ${$::operatingsystemmajrelease}, only Debian 10/11 and CentOS 7 supported")
    }

    # Join to Active Directory
    class {'::adcli':
      ad_domain        => downcase($domain),
      ad_join_username => $ad_join_username,
      ad_join_password => $ad_join_password,
      ad_join_ou       => $ad_join_machines_ou,
    }

    # Configure SSSD for user mapping
    $sssd_shell = $shell == 'nologin' ? {true => $nologin_path, default => $shell} 
    if ($::osfamily == 'Debian') {
        ensure_packages(['krb5-user'])
    }

    Class['::adcli'] -> Class['::sssd']

    # On recent Debian services are activated by systemd socket
    if ($::operatingsystem == 'Debian' and Integer($::operatingsystemmajrelease) >= 11) {
      $services = []
    } else {
      $services = ['nss', 'pam', 'ssh']
    }

    class {'::sssd':
      config => {
        'sssd' => {
          'domains'             => downcase($domain),
          'config_file_version' => 2,
          'services'            => $services,
        },
        "domain/${downcase($domain)}" => {
          'ad_domain'                      => downcase($domain),
          'ad_server'                      => $servers,
          'krb5_realm'                     => upcase($domain),
          'realmd_tags'                    => [],
          'cache_credentials'              => true,
          'id_provider'                    => 'ad',
          'krb5_store_password_if_offline' => true,
          'override_shell'                 => $sssd_shell,        # ignore LDAP shell property and force this value
          'default_shell'                  => $sssd_shell,
          'override_homedir'               => $homedir,           # ignore LDAP home property and force this value
          'fallback_homedir'               => $homedir,
          'ldap_id_mapping'                => true,               # sssd will hash SID, so it should be consistent accross servers 
          'use_fully_qualified_names'      => false,              # do not require @domain.com in login username
          'access_provider'                => 'simple',           # simple access_provider allow easy filtering on allowed groups
          'simple_allow_groups'            => map ($allowed_groups) | $group | { strip(downcase($group)) },    # only grant access to users from these groups
          'ad_gpo_map_remote_interactive'  => $ad_gpo_map_remote_interactive,  # can be used to allow other services for interactive login, e.g: +xrdp-sesman or -sshd to remove default sshd
          'ldap_user_extra_attrs'          => ['altSecurityIdentities:altSecurityIdentities'],  # map ssh public keys, also require sshd_config change 
          'ldap_user_ssh_public_key'       => 'altSecurityIdentities',
        }  # end: "domain/${downcase($domain)}"
      } # end: config
    } # end: class {'::sssd':

    # Configure sshd to retreive pub key from sssd
    $sshd_package_name = 'openssh-server'
    $sshd_service_name = $::osfamily ? { 'Debian' => 'ssh', default  => 'sshd' }
    ensure_packages($sshd_package_name)

    # comment parameter is supposed to work with recent ssh provider but it does not (?!?!?)
    sshd_config { 'AuthorizedKeysCommand':
      ensure  => present,
      value   => '/usr/bin/sss_ssh_authorizedkeys',
      notify  => Service[$sshd_service_name],
      require => Package[$sshd_package_name],
      #comment => 'Added by puppet letzit/role_ad_integration',
    }
    sshd_config { 'AuthorizedKeysCommandUser':
      ensure  => present,
      value   => 'root',
      notify  => Service[$sshd_service_name],
      require => Package[$sshd_package_name],
      #comment => 'Added by puppet letzit/role_ad_integration',
    }
    # /!\ Groups name with space are not supported
    # /!\ Previous group matcher are NOT removed, but it should be disabled anyway because of sssd simple_allow_groups config options
    # https://github.com/hercules-team/augeasproviders_ssh/issues/70
    $allowed_groups.each |String $group| {
      sshd_config { "Match Group ${group} AllowUsers *":
        ensure    => 'present',
        condition => {"Group" => strip(downcase($group))},  # AD is case insensitive, Linux isnt
        key       => 'AllowUsers',
        value     => '*',
        notify    => Service[$sshd_service_name],
        require   => Package[$sshd_package_name],
        #comment => 'Added by puppet letzit/role_ad_integration',
       }
    }

    # Configure sudo
    ensure_packages('sudo')
    $admin_groups.each |$admin_group| {
      if !($admin_group in $allowed_groups) {
        fail("Admin group ${admin_group} must be one of allowed_groups ${allowed_groups}")
      }
    }
    $admin_groups.each |$admin_group| {
      $admin_group_sudo_filename = regsubst(downcase($admin_group), /[^a-z0-9\-]/, '', 'G')
      file { "/etc/sudoers.d/00-puppet-ad-admin-group-${admin_group_sudo_filename}":
        ensure  => 'file',
        owner   => 'root',
        group   => 'root',
        mode    => '0640',
        content => "%${downcase($admin_group)}\tALL=(ALL:ALL) ALL\n",
        require => Package['sudo'],
      }
    }
    $sudo_by_group.each |$sudo_group, $sudo_group_rules| {
      if !($sudo_group in $allowed_groups) {
        fail("Sudo group ${sudo_group} must be one of allowed_groups ${allowed_groups}")
      }
      if ($sudo_group in $admin_groups) {
        fail("Sudo group ${sudo_group} is a member of admin_groups ${admin_groups}")
      }
    }
    $sudo_by_group.each |$sudo_group, $sudo_group_rules| {
      $sudo_group_sudo_filename = regsubst(downcase($sudo_group), /[^a-z0-9\-]/, '', 'G')
      $sudo_group_rules_prefixed = inline_template('<%= @sudo_group_rules.map {|x| "%" + @sudo_group + "\t" + x }.join("\n") %>')
      file { "/etc/sudoers.d/00-puppet-ad-group-${sudo_group_sudo_filename}":
        ensure  => 'file',
        owner   => 'root',
        group   => 'root',
        mode    => '0640',
        content => "${sudo_group_rules_prefixed}\n",
        require => Package['sudo'],
      }
    }

    # Configure read/write FS permissions
    ensure_packages('acl')
    $read_acl_by_path.each |$read_folder, $read_params| {
      $read_params['groups'].each |$read_group| {
        if !($read_group in $allowed_groups) {
          fail("Read ACL group ${read_group} must be one of allowed_groups ${allowed_groups}")
        }
      }
    }
    $write_acl_by_path.each |$write_folder, $write_params| {
      $write_params['groups'].each |$write_group| {
        if !($write_group in $allowed_groups) {
          fail("Write ACL group ${write_group} must be one of allowed_groups ${allowed_groups}")
        }
      }
    }
    $read_acl_by_path.each |$read_folder, $read_params| {
      $read_acl_list = $read_params['groups'].map |$read_group| { "group:${downcase($read_group)}:r-x" }
      $read_acl_default_list = $read_params['groups'].map |$read_group| { "default:group:${downcase($read_group)}:r-x" }
      if ($read_params['mask']) {
        $read_acl_mask = ["mask::${read_params['mask']}", "default:mask::${read_params['mask']}"]
      } else {
        $read_acl_mask = []
      }
      posix_acl { $read_folder:
        action     => set,
        permission => concat($read_acl_list, $read_acl_default_list, $read_acl_mask),
        provider   => posixacl,
        recursive  => true,
        require    => [Package['acl'], Class['::sssd']],
      }
    }
    $write_acl_by_path.each |$write_folder, $write_params| {
      $write_acl_list = $write_params['groups'].map |$write_group| { "group:${downcase($write_group)}:rwx" }
      $write_acl_default_list = $write_params['groups'].map |$write_group| { "default:group:${downcase($write_group)}:rwx" }
      if ($write_params['mask']) {
        $write_acl_mask = ["mask::${write_params['mask']}", "default:mask::${write_params['mask']}"]
      } else {
        $write_acl_mask = []
      }
      posix_acl { $write_folder:
        action     => set,
        permission => concat($write_acl_list, $write_acl_default_list, $write_acl_mask),
        provider   => posixacl,
        recursive  => true,
        require    => [Package['acl'], Class['::sssd']],
      }
    }

    # Configure bash and motd
    if ($::osfamily == 'Debian') {  # For some reason Debian comes with a completely different bashrc than the one from /etc
      file { '/etc/skel/.bashrc':
        ensure => 'absent',
      }
    }
    if $motd {
      file { '/etc/motd':
        content => "${strip($motd)}\n\n",
      }
    }

  }  # end: if (!$ignore_ad_config)

}
