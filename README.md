# Configuration compiler for ConfigServer Firewall & LFD

This nifty little PHP-CLI tool will help you deploy a centralised configuration for [CSF](https://configserver.com/cp/csf.html) to multiple managed servers. Certain files, such as "csf.conf", are even compiled for each server according to the operating system and container each server runs.

This is ideal if you have 2 or more Linux based servers that run CSF, whether or not they are using cPanel/WHM, that you want to keep a good tidy centralised configuration for.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development, testing, and live purposes.

### Prerequisites

Requirements for running this tool from a management station:

* Any system that can run PHP-CLI will do. (Even Windows.)
* [PHP](https://www.php.net) 7.2 or later: Available to most Linux distributions via `apt-get` or `yum`. You don't need anything web related, but you will need the command line interface.
* [Secure Shell 2 extension for PHP](http://php.net/manual/en/book.ssh2.php): Required for deployment.
* [YAML extension for PHP](http://php.net/manual/en/book.yaml.php): Optional, but allows your server list to be in YAML format. (Otherwise it'll have to be JSON.).

A pageant compatible key agent for SSH authentication will make your life easier. You can use OpenSSH formatted ID key pair files, but if they are encrypted with a password this will show up in the operating system's process list. The alternative is to use unencrypted keys, which comes with its own hazards. (This is why you should get a key agent working.)

Requirements for servers you are deploying a centralised configuration to:

* Linux with root access. ([cPanel/WHM](https://cpanel.com/) is optional.)
* SSH daemon:
  * Shell command execution must be supported.
  * File transfers using SFTP must be supported.
  * Public key authentication must be supported and configured. (No passwords!)
* [SH](https://en.wikipedia.org/wiki/Bourne_shell), [BASH](https://en.wikipedia.org/wiki/Bash_(Unix_shell)), or 100% compatible shell.
* [CSF](https://configserver.com/cp/csf.html) along with any of its prerequisites: This should be installed to each server in advance, even if it's just the default configuration in testing mode. (The service must not be disabled though.)
* [IPSET](http://ipset.netfilter.org/): This will significantly improve the performance of your Linux firewall, but will not likely work on a VPS contained within Virtuozzo or OpenVZ. (Works great for VPSes contained within ESXi, KVM, and VirtualBox.)

The following functionality won't be available to any server of which has an unconnectable or untrustworthy SSH daemon, or if SSH authentication cannot be established:

* Determining the location of important binaries automatically via `type -P`.
* Downloading server specific allow/deny lists.
* Uploading compiled configurations.
* Restarting CSF+LFD automatically.

You are thereby bound to performing these tasks manually, which kind of defeats the purpose of this tool.

## Installing

Create some space, be it a folder or virtual disk container, to hold your centralised configuration along with this tool. This folder will pretty much be allocated for your cluster of servers, so if you have a separate cluster you want to manage away from this one, you'll need multiple instances of this tool.

You will also need a sub-folder called `_all`, which will contain any CSF configurations shared amongst all of your servers. Each server should also have its own sub-folder. Each of these top level folders should then contain the sub-folder structure `/etc/csf`.

In a running example we'll use some Greek mythology figures representing a cluster of 3 managed servers: [Zeus, Hades, and Poseidon](https://en.wikipedia.org/wiki/Age_of_Mythology). Here is how your instance should be structured:

```
greek-cluster
 |- compile-csf.php
 |- compile-csf.yaml OR compile-csf.yml OR compile-csf.json
 |- _all
 |  |- etc
 |     |- csf
 |- zeus
 |  |- etc
 |     |- csf
 |- hades
 |  |- etc
 |     |- csf
 |- poseidon
 |  |- etc
 |     |- csf
```

The path `/_all/etc/csf` should contain the default CSF configuration but with any amendments you want to make to all servers.

You're now ready to build up `compile-csf.yaml` (or `compile-csf.json`), where we specify some information about each server.

## Configuration

I'd recommend you start off by copying `compile-csf.sample.yaml` (or `compile-csf.sample.json`) to `compile-csf.yaml` (or `compile-csf.json`) then editing it yourself in a text editor. The majority of this is quite self-explanatory.

Firstly each server, which in our example is "zeus", "hades", and "poseidon", is a node at the root of the confi1guration tree.

Explaining the contents each node, we have:

### *The server node itself*

This is a short alias or name for this server. This will need its own sub-folder within your instance, as a sibling to the `_all` folder, and how the tool will reference each server in any CLI switches/printouts.

**Do not start the name of a server with an underscore `_`. It will be ignored.**

### hostname

This can be a LAN host name or a fully qualified domain name (FQDN) for this server.

It should be something that is really contactable over your private network or public Internet, be it DNS, static hosts, or even WINS. This tool will use this as the primary network destination to contact the server, because it works with IPv4 and IPv6.

### container

Specify the hypervisor containing your server, if any.

Choices are currently:

* **physical**: This server is not contained within a hypervisor. (Classic physical installation.) -- This will be assumed if you omit this.
* **esxi**: [VMWare ESXi](https://www.vmware.com/products/esxi-and-esx.html) guest.
* **vmw**: [WMWare Workstation](https://www.vmware.com/uk/products/workstation.html) guest or similar, including [VMWare Player](https://www.vmware.com/products/player/playerpro-evaluation.html).
* **kvm**: Linux [Kernel Virtual Machine](https://www.linux-kvm.org/page/Main_Page) guest.
* **virtuozzo**: [Virtuozzo](https://openvz.org) guest.
* **openvz**: [OpenVZ](https://openvz.org) guest.
* **virtualbox**: [Oracle VM VirtualBox](https://www.virtualbox.org/) guest.

Currently only **openvz** and **virtuozzo** have any special functionality. Selecting these will disable the use of [IPSET](http://ipset.netfilter.org/), because it is almost certain that this will not function within these environments.

*Future functionality could come from this.*

### type

Specify the type (or family) of Linux you're using. I know this isn't really a good name for this option and it may change in future.

Most distributions of Linux (in production use) tend to fork from half a dozen tier 1 distributions, of which often use the majority of the underlying framework of their parent. For example Ubuntu Linux is at some point forked from Debian Linux, and in CSF terms works near identical.

Choices are currently:

* **whm**: This server has [cPanel/WHM](https://cpanel.com/). If your server has this definitely select it, because this has a *dramatic* influence over how CSF is configured.
* **debian**: [Debian Linux](https://www.debian.org/). This would include Debian itself and those that fork from it, for example [Ubuntu](https://www.ubuntu.com/), [Knoppix](http://www.knopper.net/knoppix/index-en.html), and [Linux Mint](https://www.linuxmint.com/).
* **rhel**: [Red Hat Enterprise Linux](https://www.redhat.com/en/technologies/linux-platforms/enterprise-linux). This would include RHEL itself and those that fork from it, for example [CentOS](https://www.centos.org/), [CloudLinux OS](https://www.cloudlinux.com/all-products/product-overview/cloudlinuxos), [Oracle Linux](https://www.oracle.com/linux), and [Scientific Linux](https://www.scientificlinux.org/).

Currently only choosing **whm** (for cPanel) or not choosing **whm** has any special functionality. Choosing **whm** simply turns off the "generic" setting in CSF so it knows to use features specific to cPanel/WHM environments. It also adjusts the URL of the Apache server status page.

### os

Specify the operating system and version of Linux you're using. This one is in a way more significant than **type** because this is responsible for knowing where on your server various binaries are located.

This can vary even in different versions of the same distribution, for example the locations of the "iptables" binary moved from `/sbin/iptables` in Debian 8 "Jessie" to `/usr/sbin/iptables` in Debian 9 "Stretch". CSF needs to know this to function correctly at all. (It's a similar story when you look at RHEL forks too.)

Choices are currently:

* **almalinux8**: AlmaLinux 8.x
* **centos6**: CentOS 6.x
* **centos7**: CentOS 7.x
* **centos8**: CentOS 8.x
* **cloudlinux6**: CloudLinux OS on RHEL 6.x compatible
* **cloudlinux7**: CloudLinux OS on RHEL 7.x compatible
* **cloudlinux8**: CloudLinux OS on RHEL 8.x compatible
* **debian8**: Debian 8 "Jessie"
* **debian9**: Debian 9 "Stretch"
* **debian10**: Debian 10 "Buster"
* **debian11**: Debian 11 "Bullseye"
* **rhel6**: Red Hat Enterprise Linux 6.x
* **rhel7**: Red Hat Enterprise Linux 7.x
* **rhel8**: Red Hat Enterprise Linux 8.x
* **ubuntu-16.04**: Ubuntu 16.04 LTS "Xenial"
* **ubuntu-22.04**: Ubuntu 22.04 LTS "Jammy Jellyfish"

These choices all have their binary locations hard-coded as they will very rarely move unless you've done a distribution upgrade. (More common on Debian and forks.) That being said this tool is capable of using the `type -P` binary providing it is available to determine the exact location of all required binaries.

The use of `type -P` can be disabled by defining the "**explicitBins**" option as `true`. This means the tool doesn't have to spend as much time on each server, but limits your choice to the hard-coded options.

You can of course hard-code your own Linux distribution/version if you like, and as I don't have much time to trawl through each distribution, this would be a welcome contribution. Check in the `Build specifically for this server using a template` block, specifically the `OS specific` section of the tool's source code for this.

### ipv4

The IPv4 address of the server.

Either this or "**ipv6**" is required if you want to use CSF's clustering feature, whereby your cluster of servers will inform each other about attacks they are receiving and act as a team to drop further packets from such attackers.

The tool will also use this to contact your server if the "**hostname**" cannot be resolved/contacted.

### ipv6

The IPv6 address of the server.

Either this or "**ipv4**" is required if you want to use CSF's clustering feature, whereby your cluster of servers will inform each other about attacks they are receiving and act as a team to drop further packets from such attackers.

The tool will also use this to contact your server if the "**hostname**" cannot be resolved/contacted.

### portSsh

Simply the port number of the SSH daemon on your server, from 1-65535.

This is **22** by default, and assumed as such if you omit this, but it's a basic security trait that you never run an SSH daemon listening on this port for any public facing machine. (You're just inviting attacks by leaving this as default.) You should choose a random number between 1025-65535, or perhaps just put something in front of **22** to make it **10022** for example.

This is fundamental to much of this tool's useful functionality as per the SSH daemon prerequisites.

### sshFingerprint

A single or list of [SHA-1](https://en.wikipedia.org/wiki/SHA-1) hash sum of the SSH daemon's public key in hexadecimal notation. This can either be a single string or an array of strings if your server has multiple host keys (e.g. supports both RSA and ED25519).

Use the included `get-ssh-fingerprint.php` CLI tool to help you retrieve this, for example:

```php-cli get-ssh-fingerprint.php zeus.example.com 10022```

You should be provided with an output such as:

```
zeus.example.com:10022:

Establishing SSH link...
SSH fingerprint is: BC84EF63681040834FBFF2CF363B85AEE97902CF
```

You would therefore use "**BC84EF63681040834FBFF2CF363B85AEE97902CF**" as the value for this option.

If this changes server side this tool will refuse to complete a connection with the SSH daemon as there is a possibility that your server's security has been compromised.

This is fundamental to much of this tool's useful functionality as per the SSH daemon prerequisites.

### pathCsf

The location on your server where CSF's configurations are stored. In nearly all cases this is `/etc/csf`, thus this is to be assumed if you omit this option.

This will be reflected in the locally compiled configuration this tool builds for this server.

### noClusterRules

If set and is `true`, exclude this server from runtime allow/deny rule sharing. This is for both manual commands and automatic detections.

The default stance is that all servers will share allow/deny rules with each other at runtime.

### csfConf

This is an object of CSF configurations you want to define for this server only.

It acts as an override on both the hard-coded options (such as use of [IPSET](http://ipset.netfilter.org/)), runtime determined options (such as binary locations), and your base `csf.conf` options.

Useful scenarios include:

* Disabling CSF features that aren't relevant: For example if a server doesn't perform any mail functions you could switch off these attack scanners.
* Different country code accept/deny/ignore lists: For example if a server is dedicated to a specific website that must be accessed in a typically less than reputable country.
* Different TCP/UDP accept/deny ports: For example if a server runs some extra applications from the norm, like DNS or a game server.
* Different CPU resources: For example if a server has more/less CPU threads available you could increase/decrease the load warning thresholds accordingly.

You literally just specify pairs of option keys and values as you would in `csf.conf`, for example:

```
csfConf:
    LF_IPSET:           0   # We know IPSET cannot be installed on this server
    PT_LOAD_LEVEL:      12  # This server has more than the typical 4 CPU threads available
    X_ARF_TO:           ~   # Don't spam me with abuse reports for this server
```

## Deployment

Once you have your configuration ready to deploy you simply need to execute the tool from a terminal via a CLI compatible [PHP](https://www.php.net) binary. Simple example:

```php compile-csf.php```

The corresponding servers configuration file will be looked for in the same folder as the tool.

This will assume that:

* SSH authentication via a key agent (pageant) will be attempted.
* SSH authentication via key files will NOT be attempted.
* All configured servers will be actioned.
* You are using YAML format configuration.
* Compiled configuration will be uploaded to each server.
* CSF+LFD will be fully restarted on each server after upload. (Via `csf -ra`.)

There are various command line switches you can use to control this behaviour, visible via `--help`.

* `--nopageant`: If set, do not attempt to use an key agent (pageant) for SSH autnetication.
* `--sshkeypublic=file`: Specify an OpenSSH formatted public key ID file for SSH authentication.
* `--sshkeyprivate=file`: Specify an OpenSSH formatted private key ID file for SSH authentication.
* `--sshkeypassword=password`: Specify a password for an encrypted OpenSSH formatted private key ID file. (DANGEROUS! This will show up in the process list of the operating system!)
* `--servers=name1,name2,...`: Only action the specified server names, split with a comma. For example to just work on Zeus and Hades, use `--servers=zeus,hades`.
* `--serversfiletype=type`: Specify the configuration file format. (json, yml, or yaml.)
* `--noupload`: Do not upload the compiled configuration to servers.
* `--norestart`: Do not restart CSF+LFD on servers after upload.

## Built With

* [PHP](https://www.php.net): Entirely PHP.

## Contributing

Please read [CONTRIBUTING.md](https://gist.github.com/PurpleBooth/b24679402957c63ec426) for details on our code of conduct, and the process for submitting pull requests to us.

### Potential features

I don't have anything further planned as this fulfils my purpose, but some suggestions are:

* Deploying the initial CSF installation itself.
* Specifying an alternative instance (cluster) folder so only 1 copy of this tool would need to be kept.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/your/project/tags).

## Authors

* **Adam Reece** - *Initial work* - [Adambean](https://github.com/Adambean)

See also the list of [contributors](https://github.com/your/project/contributors) who participated in this project.

## License

Copyright 2017 Adam Reece

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the [License](LICENSE) for the specific language governing permissions and limitations under the License.
