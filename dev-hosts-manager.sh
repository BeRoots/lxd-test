#!/usr/bin/env bash
#set -xe
set -uo pipefail

## BEGIN Description ##########################################################
#
# dev-hosts-manager.sh:
#
# This is a script to manage development hosts containers for this project.
#
## END Description ############################################################

## BEGIN INTERNAL CONSTANTS ###################################################
__DEV_HOSTS_MANAGER_MODZ='su'
__DEV_HOSTS_MANAGER_DEBUG=1
__DEV_HOSTS_MANAGER_VERSION="0.0.1"

__DEV_HOSTS_MANAGER_RC=0
__DEV_HOSTS_MANAGER_EX_OK=0
__DEV_HOSTS_MANAGER_EX_KO=1
__DEV_HOSTS_MANAGER_EX_USAGE=64
__DEV_HOSTS_MANAGER_EX_SOFTWARE=70
__DEV_HOSTS_MANAGER_EX_MISSED_ARGS=79
__DEV_HOSTS_MANAGER_EX_WRONG_USAGE_ARGS=80
__DEV_HOSTS_MANAGER_EX_WRONG_MODULE_ARGS=81
__DEV_HOSTS_MANAGER_EX_COMMAND_NOT_FOUND=127

__DEV_HOSTS_MANAGER_ARGS=($@)
__DEV_HOSTS_MANAGER_ARGS_STR=$@
## END INTERNAL CONSTANTS #####################################################


## BEGIN Script Usage Requirments #############################################
case $__DEV_HOSTS_MANAGER_MODZ in
  'root')
    if ! [[ $(logname) = 'root' ]]; then
      echo -e "\e[31mERROR: ${0##*/}: This tool is only runnable by a login session as root (not root elevated by su or sudo).\e[0m"
      exit $__DEV_HOSTS_MANAGER_EX_USAGE
    fi;;
  'su')
    if ! [[ $(whoami) = 'root' ]]; then
      echo -e "\e[31mERROR: ${0##*/}: Using this tool require root privileges. Ensure your logged as root or use it with sudo.\e[0m"
      exit $__DEV_HOSTS_MANAGER_EX_USAGE
    fi;;
  'sudo')
    if [[ $(logname) = 'root' ]] || ! [[ $(whoami) = 'root' ]] || [[ $(whoami) = 'root' ]] && [[ ${SUDO_USER:-} == '' ]]; then
      echo -e "\e[31mERROR: ${0##*/}: Using this tool as root isn't a good idea. Ensure your not logged as root and use it with sudo.\e[0m"
      exit $__DEV_HOSTS_MANAGER_EX_USAGE
    fi;;
  'user')
    if [[ $(whoami) = 'root' ]]; then
      echo -e "\e[31mERROR: ${0##*/}: Don't use this tool with root privileges.\e[0m"
      exit $__DEV_HOSTS_MANAGER_EX_USAGE
    fi;;
  'off') # nothing to do
    ;;
  *)
    echo -e "\e[31mERROR: ${0##*/}: 'modz' not defined or value case not implemented.\e[0m"; exit $__DEV_HOSTS_MANAGER_EX_SOFTWARE;;
esac

if ! hash lxd; then
  echo -e "\e[31mERROR: ${0##*/}: This tool require LXD and it seems not installed on your system. Please see ./README.md.\e[0m"
  exit $__DEV_HOSTS_MANAGER_EX_COMMAND_NOT_FOUND
fi
## END Script Usage Requirments ###############################################


## BEGIN Variables ############################################################
container_image="debian/11/cloud"
project_name="myproj"
openvpn_container_names=(openvpn-ra openvpn-s2s)
## END Variables ##############################################################


## BEGIN Dependencies #########################################################

## END Dependencies ###########################################################


## BEGIN Fonctions ############################################################
function __dev_hosts_manager_help () {
  local rc=0
  echo -e "\e[36m  DESCRIPTION:
  -----------

    This is a simple script to manage development hosts containers for this project.

  USAGE :
  -----

    ${0##*/} [-h] [--help]

  Synopsis : ${0##*/} [options] <command>
  --------

  Options :
  -------

    -h, --help : Command help

    -v, --version : Display utility's version

  Commands :
  --------

    init : Intitate LXD project and its component (network; devices; ...)

    start: Start containers their from old state

    stop: Stop containers

    reset: Reset containers as new

    flush: Destroy the project at all

  Examples :
  --------

    ${0##*/} --help : Show the help page

    ${0##*/} --version : Show the version of this tool

    ${0##*/} init : Initiate the project if not exist yet

    ${0##*/} start : Start containers from their old state

    ${0##*/} stop : Stop containers

    ${0##*/} reset : Restart containers as new containers

    ${0##*/} flush : Destroy the initiated project at all

  Troubleshootings :
  ----------------

    - See https://gl.sebastien-deschamps.com/ref_name/project_name/issues
  \e[0m"; ((rc=rc+$?))

  return $rc
}

function __dev_hosts_manager_version () {
  local rc=0
  echo -e "${0##*/} version: $__DEV_HOSTS_MANAGER_VERSION"; ((rc=rc+$?))

  return $rc
}

function __dev_hosts_manager_init_project () {
  local rc=0

  # Init LXD if not initiated yet   #@TODO read type of storage from users and adapt the preseed 

    echo '---
config:
  images.auto_update_interval: "0"
networks:
- config:
    ipv4.address: auto
    ipv6.address: auto
  description: "Default bridge (ip v4 and v6 auto network)"
  name: lxdbr0
  type: ""
  project: default
storage_pools:
- config:
    source: /var/snap/lxd/common/lxd/storage-pools/default
  description: "Default storage pool (dir)"
  name: default
  driver: dir
profiles:
- config: {}
  description: "Default profile"
  devices:
    eth0:
      name: eth0
      network: lxdbr0
      type: nic
    root:
      path: /
      pool: default
      type: disk
  name: default
projects: []
cluster: null' | lxd init --preseed; ((rc=rc+$?))
  fi

  # create project if not exist yet
  if [[ $(lxc project list | grep -c $project_name) -eq 0 ]]; then
    runuser -p -u $LOGNAME -- \
      lxc project create \
        $project_name \
        -c features.images=true \
        -c features.profiles=true \
        -c features.storage.volumes=false \
        -c features.networks=false; ((rc=rc+$?))
  fi

  # switch on the project if not selected
  if [[ $(lxc project list | grep -c "$project_name (current)") -eq 0 ]]; then
    runuser -p -u $LOGNAME -- \
        lxc project switch $project_name; ((rc=rc+$?))
  fi

  # Create bridged network if not exist yet
  if [[ $(lxc network list | grep -c "$project_name-br0") -eq 0 ]]; then
    runuser -p -u $LOGNAME -- \
      lxc network create \
        $project_name-br0 \
        --type=bridge \
        --project=$project_name \
        ipv4.address=10.222.0.1/24 \
        ipv4.nat=true \
        ipv4.firewall=false \
        ipv6.address=none \
        ipv6.firewall=false \
        dns.domain="lxd" \
        dns.mode="managed" \
        dns.search="lxd"; ((rc=rc+$?))

####@TODO seems not working        dns.zone.forward="managed" \
####@TODO seems not working        dns.zone.reverse.ipv4="managed" \
####@TODO seems not working        dns.zone.reverse.ipv6="none"; ((rc=rc+$?))
#@TODO to test        raw.dnsmasq=""

    #@TODO UFW alternative and others...
    if hash firewall-cmd && ! firewall-cmd --zone=trusted --query-interface=$project_name-br0 > /dev/null 2>&1; then
      firewall-cmd --zone=trusted --change-interface=$project_name-br0 --permanent && sudo firewall-cmd --reload; ((rc=rc+$?))
      firewall-cmd --reload; ((rc=rc+$?))
    fi
  fi

  # Create storage if not exist yet
  if [[ $(lxc storage list | grep -c "$project_name-storage") -eq 0 ]]; then
    srcpath=$(pwd)"/0_storage-pool"

    mkdir -p $srcpath; ((rc=rc+$?))

    runuser -p -u $LOGNAME -- \
      lxc storage create $project_name-storage dir source=$srcpath; ((rc=rc+$?))
  fi

  # Create profile if not exist yet
  if [[ $(lxc profile list | grep -c "$project_name-profile") -eq 0 ]]; then
    runuser -p -u $LOGNAME -- \
      lxc profile copy default $project_name-profile; ((rc=rc+$?))
    if [[ $(lxc profile device ls | grep -c 'root'); then
      runuser -p -u $LOGNAME -- \
        lxc profile device add $project_name-profile root disk path=/ pool=$project_name-storage; ((rc=rc+$?))
    fi

    # @TODO clean that if not usefull. Normally seems impossible to do something to override this later 
    #if [[ $(lxc profile device ls | grep -c 'eth0'); then
      #runuser -p -u $LOGNAME -- \
      #  lxc profile device add $project_name-profile eth0 nic name=eth0 network=$project_name-br0; ((rc=rc+$?))
    #fi
  fi

  return $rc
}

function __dev_hosts_manager_build_image () {
  local rc=0

  # get the given image locally with an alias
  lxc image copy images:$container_image local: --alias $container_image; ((rc=rc+$?))


  # create a cloud-config.yml file. This file should ensure:
  #   - root password have a default value
  #   - default user exist and have default name and password
  #   - openssh-server is installed and have a default configuration
  #   -
  # All of those ensure that you have an ansible ssh ready configuration
  echo "#cloud-config
users:
  - name: root
    plain_text_passwd: debian666
package_update: true
package_upgrade: true
packages:
  - openssh-server
write_files:
  - content: |
      #	\$OpenBSD: sshd_config,v 1.103 2018/04/09 20:41:22 tj Exp $

      # This is the sshd server system-wide configuration file.  See
      # sshd_config(5) for more information.

      # This sshd was compiled with PATH=/usr/bin:/bin:/usr/sbin:/sbin

      # The strategy used for options in the default sshd_config shipped with
      # OpenSSH is to specify options with their default value where
      # possible, but leave them commented.  Uncommented options override the
      # default value.

      Include /etc/ssh/sshd_config.d/*.conf

      #Port 22
      #AddressFamily any
      #ListenAddress 0.0.0.0
      #ListenAddress ::

      #HostKey /etc/ssh/ssh_host_rsa_key
      #HostKey /etc/ssh/ssh_host_ecdsa_key
      #HostKey /etc/ssh/ssh_host_ed25519_key

      # Ciphers and keying
      #RekeyLimit default none

      # Logging
      #SyslogFacility AUTH
      #LogLevel INFO

      # Authentication:

      #LoginGraceTime 2m
      #PermitRootLogin prohibit-password
      PermitRootLogin yes
      #StrictModes yes
      #MaxAuthTries 6
      #MaxSessions 10

      #PubkeyAuthentication yes

      # Expect .ssh/authorized_keys2 to be disregarded by default in future.
      #AuthorizedKeysFile	.ssh/authorized_keys .ssh/authorized_keys2

      #AuthorizedPrincipalsFile none

      #AuthorizedKeysCommand none
      #AuthorizedKeysCommandUser nobody

      # For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
      #HostbasedAuthentication no
      # Change to yes if you don't trust ~/.ssh/known_hosts for
      # HostbasedAuthentication
      #IgnoreUserKnownHosts no
      # Don't read the user's ~/.rhosts and ~/.shosts files
      #IgnoreRhosts yes

      # To disable tunneled clear text passwords, change to no here!
      PasswordAuthentication yes
      #PermitEmptyPasswords no

      # Change to yes to enable challenge-response passwords (beware issues with
      # some PAM modules and threads)
      ChallengeResponseAuthentication no

      # Kerberos options
      #KerberosAuthentication no
      #KerberosOrLocalPasswd yes
      #KerberosTicketCleanup yes
      #KerberosGetAFSToken no

      # GSSAPI options
      #GSSAPIAuthentication no
      #GSSAPICleanupCredentials yes
      #GSSAPIStrictAcceptorCheck yes
      #GSSAPIKeyExchange no

      # Set this to 'yes' to enable PAM authentication, account processing,
      # and session processing. If this is enabled, PAM authentication will
      # be allowed through the ChallengeResponseAuthentication and
      # PasswordAuthentication.  Depending on your PAM configuration,
      # PAM authentication via ChallengeResponseAuthentication may bypass
      # the setting of \"PermitRootLogin without-password\".
      # If you just want the PAM account and session checks to run without
      # PAM authentication, then enable this but set PasswordAuthentication
      # and ChallengeResponseAuthentication to 'no'.
      UsePAM yes

      #AllowAgentForwarding yes
      #AllowTcpForwarding yes
      #GatewayPorts no
      X11Forwarding yes
      #X11DisplayOffset 10
      #X11UseLocalhost yes
      #PermitTTY yes
      PrintMotd no
      #PrintLastLog yes
      #TCPKeepAlive yes
      #PermitUserEnvironment no
      #Compression delayed
      #ClientAliveInterval 0
      #ClientAliveCountMax 3
      #UseDNS no
      #PidFile /var/run/sshd.pid
      #MaxStartups 10:30:100
      #PermitTunnel no
      #ChrootDirectory none
      #VersionAddendum none

      # no default banner path
      #Banner none

      # Allow client to pass locale environment variables
      AcceptEnv LANG LC_*

      # override default of no subsystems
      Subsystem sftp /usr/lib/openssh/sftp-server

      # Example of overriding settings on a per-user basis
      #Match User anoncvs
      #	X11Forwarding no
      #	AllowTcpForwarding no
      #	PermitTTY no
      #	ForceCommand cvs server
      ClientAliveInterval 120
    path: /etc/ssh/sshd_config.new
  - content: |
      #!/usr/bin/env bash
      set -uo pipefail
      
      while ! [[ -f /etc/ssh/sshd_config ]] && ! [[ -f /etc/ssh/sshd_config.new ]]; do
          sleep 5
      done
      
      cp /etc/ssh/sshd_config /etc/ssh/sshd_config.origin && \
      mv /etc/ssh/sshd_config.new /etc/ssh/sshd_config && \
      systemctl restart ssh
      
      exit \$?
    path: /root/wait-cloudinit.sh
    owner: root:root
    permissions: 0755
runcmd:
  - /root/wait-cloudinit.sh" > /tmp/cloud-config.yml; ((rc=rc+$?))

  runuser -p -u $LOGNAME -- \
    lxc init local:$container_image -p $project_name-profile tmp-build1; ((rc=rc+$?))

  runuser -p -u $LOGNAME -- \
    lxc config device add tmp-build1 eth0 nic name=eth0 network=$project_name-br0; ((rc=rc+$?))

  runuser -p -u $LOGNAME -- \
    lxc network attach $project_name-br0 tmp-build1 eth0 eth0; ((rc=rc+$?))

  runuser -p -u $LOGNAME -- \
    lxc config set tmp-build1 user.user-data - < /tmp/cloud-config.yml; ((rc=rc+$?))

  # clean cloud-config.yml
  rm -f /tmp/cloud-config.yml; ((rc=rc+$?))

  # start tmp-build1 to start the cloud-init process
  runuser -p -u $LOGNAME -- \
    lxc start tmp-build1; ((rc=rc+$?))

  # Wait for cloud-init will be done
  runuser -p -u $LOGNAME -- \
    lxc exec tmp-build1 -- cloud-init status --wait; ((rc=rc+$?))

  # start tmp-build1 to start the cloud-init process
  runuser -p -u $LOGNAME -- \
    lxc exec tmp-build1 -- touch /etc/cloud/cloud-init.disabled; ((rc=rc+$?))

  # stop tmp-build1
  runuser -p -u $LOGNAME -- \
    lxc stop tmp-build1; ((rc=rc+$?))

  # export the container to an image for later usage
  runuser -p -u $LOGNAME -- \
    lxc publish tmp-build1 --alias $project_name-built-image; ((rc=rc+$?))

  # remove the tmp-build1 container
  runuser -p -u $LOGNAME -- \
    lxc delete tmp-build1; ((rc=rc+$?))

  return $rc
}

function __dev_hosts_manager_start () {
  local rc=0
  local i=1

  if __dev_hosts_manager_is_selected; then
    for cont in $openvpn_container_names; do
      if [[ $(lxc ls | grep -c $cont) -eq 0 ]]; then
        ((i=i + 1))
        runuser -p -u $LOGNAME -- \
          lxc init local:$project_name-built-image -p $project_name-profile $cont; ((rc=rc+$?))
        # runuser -p -u $LOGNAME -- \
        #   lxc config device set $cont eth0 ipv4.address=10.222.0.$i; ((rc=rc+$?))
        runuser -p -u $LOGNAME -- \
          lxc config device add $cont eth0 nic name=eth0 network=$project_name-br0 ipv4.address=10.222.0.$i; ((rc=rc+$?))

        runuser -p -u $LOGNAME -- \
          lxc network attach $project_name-br0 tmp-build1 eth0 eth0; ((rc=rc+$?))
      fi

      runuser -p -u $LOGNAME -- \
        lxc start $cont; ((rc=rc+$?))
    done
  fi

  return $rc
}

function __dev_hosts_manager_stop () {
  local rc=0

  if __dev_hosts_manager_is_selected; then
    for cont in $openvpn_container_names; do
      runuser -p -u $LOGNAME -- \
        lxc stop $cont; ((rc=rc+$?))
    done
  fi

  return $rc
}

function __dev_hosts_manager_reset () {
  local rc=0

  if __dev_hosts_manager_is_selected; then
    # simply remove all container and run creation again
    for cont in $openvpn_container_names; do
      runuser -p -u $LOGNAME -- \
        lxc delete $cont --force; ((rc=rc+$?))
    done

    __dev_hosts_manager_start; ((rc=rc+$?))
  fi

  return $rc
}

function __dev_hosts_manager_flush () {
  local rc=0

  if __dev_hosts_manager_is_selected; then
    # delete all containers
    for cont in $openvpn_container_names; do
      if [[ $(lxc ls | grep -c $cont) -gt 0 ]]; then
        runuser -p -u $LOGNAME -- \
          lxc delete $cont --force; ((rc=rc+$?))
      fi
    done

    # delete all images
    runuser -p -u $LOGNAME -- \
      lxc image delete local:$container_image; ((rc=rc+$?))
    runuser -p -u $LOGNAME -- \
      lxc image delete local:$project_name-built-image; ((rc=rc+$?))

    # Go back to default project
    runuser -p -u $LOGNAME -- \
      lxc project switch default; ((rc=rc+$?))

    # remove network ; devices; profile; storage ; and project
    runuser -p -u $LOGNAME -- \
      lxc network delete $project_name-br0; ((rc=rc+$?))

    srcpath=$(pwd)"/0_storage-pool"
    runuser -p -u $LOGNAME -- \
      lxc storage delete $project_name-storage && rm -rf $srcpath; ((rc=rc+$?))

    runuser -p -u $LOGNAME -- \
      lxc profile device remove $project_name-profile eth0; ((rc=rc+$?))

    runuser -p -u $LOGNAME -- \
      lxc profile device remove $project_name-profile root; ((rc=rc+$?))

    runuser -p -u $LOGNAME -- \
      lxc profile delete $project_name-profile; ((rc=rc+$?))

    runuser -p -u $LOGNAME -- \
      lxc project delete $project_name; ((rc=rc+$?))
  fi

  return $rc
}

function __dev_hosts_manager_is_selected () {
  local rc=0

  # Exit with error message if project not exist yet
  if [[ $(lxc project list | grep -c "$project_name") -eq 0 ]]; then
    echo -e "\e[31mError: ${0##*/}: The project named '$project_name' not exist.\e[0m"
    exit $__DEV_HOSTS_MANAGER_EX_USAGE
  fi

  # switch on the project if not selected
  if [[ $(lxc project list | grep -c "$project_name (current)") -eq 0 ]]; then
    runuser -p -u $LOGNAME -- \
      lxc project switch $project_name; ((rc=rc+$?))

    if [[ $rc -lt 0 ]]; then
      echo -e "\e[31mError: ${0##*/}: Project switching failed.\e[0m"
      exit $__DEV_HOSTS_MANAGER_EX_KO
    fi
  fi

  return $rc
}

## END Functions ##############################################################


## BEGIN Main Function #########################################################
function __openvpn_ra_s2s_main () {
  local rc=0

  # If is a standard usage argument
  if ! [[ "${__DEV_HOSTS_MANAGER_ARGS[0]:-}" == '' ]] && [[ "${__DEV_HOSTS_MANAGER_ARGS[0]:0:1}" = "-" ]]; then
    case "${__DEV_HOSTS_MANAGER_ARGS[0]}" in
      "-h"|"--help")
        __dev_hosts_manager_help; ((rc=rc+$?))
        ;;
      "-v"|"--version")
        __dev_hosts_manager_version; ((rc=rc+$?))
        ;;
      *)
        echo -e "\e[31mERROR: ${0##*/} : Invalid argument specified. Run -h or --help\e[0m"
        exit $__DEV_HOSTS_MANAGER_EX_WRONG_USAGE_ARGS
        ;;
    esac
  # Else it is a module argument
  else
    case "${__DEV_HOSTS_MANAGER_ARGS[0]:-}" in
      "init")
        __dev_hosts_manager_init_project; ((rc=rc+$?))
        __dev_hosts_manager_build_image; ((rc=rc+$?))
        __dev_hosts_manager_start; ((rc=rc+$?))
        ;;
      "stop")
        __dev_hosts_manager_stop; ((rc=rc+$?))
        ;;
      "start")
        __dev_hosts_manager_start; ((rc=rc+$?))
        ;;
      "reset")
        __dev_hosts_manager_reset; ((rc=rc+$?))
        ;;
      "flush")
        __dev_hosts_manager_flush; ((rc=rc+$?))
        ;;
      '')
      	echo -e "\e[31mERROR: ${0##*/} : No subcommand specified. Show the help bellow.\e[0m"
        __dev_hosts_manager_help; ((rc=rc+$?))
        ;;
      *)
        echo -e "\e[31mERROR: ${0##*/} : Invalid subcommand specified. Run -h or --help.\e[0m"
        exit $__DEV_HOSTS_MANAGER_EX_WRONG_MODULE_ARGS
        ;;
    esac
  fi

  return $rc
}
## BEGIN Main Function #########################################################


## BEGIN Main Execution #######################################################
__openvpn_ra_s2s_main
exit $?
## END Main Execution #########################################################


## BEGIN USAGE COPY/PASTE HELPER ##############################################
## END USAGE COPY/PASTE HELPER ################################################
