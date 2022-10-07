<?php

/**
 * Configuration compiler for ConfigServer Firewall & LFD
 * -----------------------------------------------------------------------------
 * By Adam "Adambean" Reece - www.reece.wales
 * https://github.com/Adambean/compile-csf
 *
 * This nifty little tool will help you deploy a centralised configuration for
 * CSF+LFD to multiple managed servers. Certain files, such as "csf.conf", are
 * even compiled for each server according to the operating system it runs.
 *
 * Please check the corresponding "README.md" for instructions on using this.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * "LICENSE" for the specific language governing permissions and limitations
 * under the License.
 */

printf("Configuration compiler for ConfigServer Firewall & LFD\n\n");

$sshUsePageant      = true;     // Attempt to use an SSH key agent for authentication. (Pageant.)
$sshKeyFilePublic   = null;     // SSH public key file to use for authentication. (OpenSSH format.)
$sshKeyFilePrivate  = null;     // SSH private key file to use for authentication. (OpenSSH format.)
$sshKeyFilePassword = null;     // SSH private key password if encrypted. (This will show in PS!)
$serversToAction    = [];
$serversToActionNum = 0;
$serversFileType    = "yml";
$serversFileTypes   = ["json", "yml", "yaml"];
$enableUpload       = true;     // Try to upload after compilation?
$enableRestart      = true;     // Restart CSF and LFD after upload?

define("CSF_PER_SERVER_LINE", "### SERVER SPECIFIC ENTRIES BELOW THIS LINE ### DO NOT EDIT/REMOVE THIS LINE ###");

function showUsage($exitCode = 0)
{
    if ($exitCode = intval($exitCode)) {
        printf("\n");
    }

    printf("Usage:\n\n");
    printf("\t--help                      Show usage.\n");
    printf("\n");
    printf("\t--nopageant                 Do not attempt to use an SSH key agent for authentication. (Pageant.)\n");
    printf("\t--sshkeypublic=file         SSH public key file to use for authentication. (OpenSSH format.)\n");
    printf("\t--sshkeyprivate=file        SSH private key file to use for authentication. (OpenSSH format.)\n");
    printf("\t--sshkeypassword=passowrd   SSH private key password if encrypted. (This will show in PS!)\n");
    printf("\n");
    printf("\t--servers=name1,name2,...   Only action specific servers. (Split multiple with a comma.)\n");
    printf("\t--serversfiletype=type      Server list file type. (Type can be json, yml, or yaml.)\n");
    printf("\n");
    printf("\t--upload                    Enable upload after compilation.\n");
    printf("\t--noupload                  Disable upload after compilation.\n");
    printf("\t--restart                   Enable service restart after upload.\n");
    printf("\t--norestart                 Disable service restart after upload.\n");

    exit($exitCode);
}

foreach ($argv as $i => $arg) {
    if ($i == 0) {
        continue; // Ignore script name
    }

    $argMatches = [];
    if (preg_match("/--([a-zA-Z0-9-]+)=?(.*)?/", $arg, $argMatches) !== false && count($argMatches) >= 2) {
        $argSwitch  = strtolower(trim($argMatches[1]));
        $argValue   = isset($argMatches[2]) ? trim($argMatches[2]) : null;

        switch ($argSwitch) {
            case "help":
                showUsage();
                break;

            case "sshkeypublic":
            case "sshkeyprivate":
                $argKeyType = substr($argSwitch, 6);

                if (!$argSshKeyFile = trim($argValue)) {
                    printf("[Error] No %s SSH key file specified.\n", $argKeyType);
                    showUsage(1);
                }

                if (!file_exists($argSshKeyFile)) {
                    printf("[Error] No %s SSH key file not found.\n", $argKeyType);
                    showUsage(1);
                }

                if (!is_file($argSshKeyFile)) {
                    printf("[Error] No %s SSH key file is not a file.\n", $argKeyType);
                    showUsage(1);
                }

                if (!is_readable($argSshKeyFile)) {
                    printf("[Error] No %s SSH key file is not readable.\n", $argKeyType);
                    showUsage(1);
                }

                $sshKeyFileVar  = sprintf("sshKeyFile%s", ucfirst($argKeyType));
                $$sshKeyFileVar = $argSshKeyFile;
                printf("SSH %s key file defined as \"%s\".\n", $argKeyType, $argSshKeyFile);
                break;

            case "sshkeyfilepassword":
                if (!$sshKeyFilePassword = trim($argValue)) {
                    printf("[Error] No servers specified.\n");
                    showUsage(1);
                }

                printf("SSH private key password set.\n");
                break;

            case "nopageant":
                $sshUsePageant = false;
                printf("SSH key agent will not be used.\n");
                break;

            case "servers":
                if (!$argServersStr = trim($argValue)) {
                    printf("[Error] No servers specified.\n");
                    showUsage(1);
                }

                $argServers = explode(',', $argServersStr);
                if (count($argServers) < 1) {
                    printf("[Error] No servers specified.\n");
                    showUsage(1);
                }

                foreach ($argServers as &$serverToAction) {
                    if ($serverToAction = trim($serverToAction)) {
                        $serversToAction[] = $serverToAction;
                    }
                }

                $serversToActionNum = count($serversToAction);

                printf("Only the following %d server(s) will be actioned: %s\n", $serversToActionNum, implode(", ", $serversToAction));
                break;

            case "upload":
                $enableUpload = true;
                printf("Upload enabled.\n");
                break;

            case "noupload":
                $enableUpload = false;
                printf("Upload disabled.\n");
                break;

            case "restart":
                $enableRestart = true;
                printf("Restart enabled.\n");
                break;

            case "norestart":
                $enableRestart = false;
                printf("Restart disabled.\n");
                break;

            case "serverfiletype":
                if (!$argValue) {
                    printf("[Error] No servers file type specified.\n");
                    showUsage(1);
                }

                if (!in_array($argValue, $serversFileTypes)) {
                    printf("[Error] Unknown servers file type \"%s\".\n", $argValue);
                    showUsage(1);
                }

                $serversFileType = $argValue;
                printf("Server list file type set to \"%s\".\n", $serversFileType);
                break;

            default:
                printf("Unknown switch \"%s\".\n\n", $argSwitch);
                showUsage(1);
        }
    } else {
        printf("Unknown argument #%d \"%s\".\n\n", $i, $arg);
        showUsage(1);
    }
}

if (!boolval($sshUsePageant) && ((!$sshKeyFilePublic = trim($sshKeyFilePublic)) || (!$sshKeyFilePrivate = trim($sshKeyFilePrivate)))) {
    printf("[Error] No viable SSH authentication method available.\nPlease use a key agent (Pageant) or key files (OpenSSH format).\n");
    showUsage(1);
}



printf("\nLoading base configuration...\n");

$directoryCsfBase = sprintf("%s/_all/etc/csf", __DIR__);
if (!is_dir($directoryCsfBase)) {
    printf("- Base CSF directory not found, creating...\n");
    mkdir($directoryCsfBase, 0770, true);
    if (!is_dir($directoryCsfBase)) {
        printf("[Error] Failed to create base CSF directory \"%s\".\n", $directoryCsfBase);
        exit(1);
    }
}



printf("\nLoading servers...\n");

$serversFileType    = trim($serversFileType);
if (!in_array($serversFileType, $serversFileTypes)) {
    printf("[Error] Unknown servers file type \"%s\".\n", $serversFileType);
    exit(1);
}

$serversFile        = sprintf("%s.%s", substr(__FILE__, 0, strrpos(__FILE__, '.')), $serversFileType);
$serversFileSample  = sprintf("%s.sample.%s", substr(__FILE__, 0, strrpos(__FILE__, '.')), $serversFileType);
if (!file_exists($serversFile)) {
    printf("[Error] Server list file \"%s\" not found.\n", $serversFile);

    if (file_exists($serversFileSample) && is_file($serversFileSample)) {
        printf("I see that the sample server list file \"%s\" exists though.\nYou should make a copy of this as \"%s\" then configure it.\n", $serversFileSample, $serversFile);
    }

    exit(1);
}

if (!is_file($serversFile)) {
    printf("[Error] Server list file \"%s\" not a file.\n", $serversFile);
    exit(1);
}

if (!is_readable($serversFile)) {
    printf("[Error] Server list file \"%s\" not readable.\n", $serversFile);
    exit(1);
}

$servers            = [];
switch ($serversFileType) {
    case "json":
        $servers = json_decode(file_get_contents($serversFile), true);
        break;

    case "yml":
    case "yaml":
        if (!function_exists("yaml_parse_file")) {
            printf("[Critical] YAML for PHP is not installed. If this is a problem you must use JSON instead.\n");
            exit(1);
        }
        $servers = yaml_parse_file($serversFile);
        break;

    default:
        printf("[Error] Unknown servers file type \"%s\".\n", $serversFileType);
        exit(1);
}

$serverCount        = count($servers);
if ($serverCount < 1) {
    printf("[Error] No servers in configuration.\n");
    exit(1);
}

printf("Found %d server(s) in configuration, %d to process.\n", $serverCount, ($serversToActionNum >= 1 ? $serversToActionNum : $serverCount));



printf("\nLooking at server list...\n");

$allServersAsCluster        = [];
$allServersAsClusterString  = "";

foreach ($servers as $s => $server) {
    if ('_' === substr($s, 0, 1)) {
        printf("[Warning] Ignoring server \"%s\" because it starts with a special character.\n", $s);
        unset($servers[$s]);
        continue;
    }

    foreach (["ipv4", "ipv6"] as $property) {
        if (array_key_exists($property, $server) && $clusterMemberAddress = trim($server[$property])) {
            $allServersAsCluster[] = $clusterMemberAddress;
            break; // We're doing this because we don't want to add BOTH IPv4 and IPv6. Just add the first one that got defined.
        }
    }
}

$allServersAsClusterString  = implode(",", $allServersAsCluster);



printf("\nProcessing servers...\n");

foreach ($servers as $s => $server) {
    $s = trim($s);
    if (!$s || $s == "_all" || !is_array($server) || count($server) < 1) {
        continue;
    }

    // Is this server skipped?
    if ($serversToActionNum >= 1 && !in_array($s, $serversToAction)) {
        continue;
    }

    // Show server name
    printf("%s:\n", $s);

    // << SSH connection: Open
    printf("- Establishing SSH and SFTP link...\n");

    if (isset($linkSsh) && $linkSsh && is_resource($linkSsh)) {
        if (false === @ssh2_exec($linkSsh, "exit")) {
            printf("- SSH connection to previous server did not close cleanly.\n");
        }

        $linkSsh        = null;
        $linkSshAuthed  = false;
        $linkSftp       = null;
    }

    $linkSsh        = null;
    $linkSshAuthed  = false;
    $linkSftp       = null;

    if (empty($server["hostname"])) {
        printf("- - Host name not defined!\n");
        continue;
    }

    if (!$server["hostname"] = trim($server["hostname"])) {
        printf("- - Host name empty!\n");
        continue;
    }

    if (empty($server["portSsh"])) {
        printf("- - SSH port not defined!\n");
        continue;
    }

    $server["portSsh"] = intval($server["portSsh"]);
    if ($server["portSsh"] < 1 || $server["portSsh"] > 65535) {
        printf("- - SSH port invalid! (%d)\n", $server["portSsh"]);
        continue;
    }

    if (empty($server["sshFingerprint"])) {
        printf("- - SSH fingerprint not defined!\n");
        continue;
    }

    if (!$server["sshFingerprint"] = trim($server["sshFingerprint"])) {
        printf("- - SSH fingerprint empty!\n");
        continue;
    }

    try {
        if (!function_exists("ssh2_connect")) {
            throw new \Exception("SSH2 for PHP is not installed.\n");
        }

        // Try hostname
        if (!$linkSsh || !is_resource($linkSsh)) {
            $linkSsh = null;
            $linkSsh = @ssh2_connect($server["hostname"], $server["portSsh"]);
        }

        // Try IPv6
        if (!$linkSsh || !is_resource($linkSsh)) {
            $linkSsh = null;
            $linkSsh = @ssh2_connect($server["ipv6"], $server["portSsh"]);
        }

        // Try IPv4
        if (!$linkSsh || !is_resource($linkSsh)) {
            $linkSsh = null;
            $linkSsh = @ssh2_connect($server["ipv4"], $server["portSsh"]);
        }

        // Failed completely...
        if (!$linkSsh || !is_resource($linkSsh)) {
            $linkSsh = null;
            printf("- - SSH connection couldn't be established!\n");
            continue;
        }
    } catch (\Exception $e) {
        printf("- - SSH connection failed: %s\n", $e->getMessage());
        continue;
    }

    printf("- - SSH connection established.\n");

    if (!$sshFingerprint = trim(ssh2_fingerprint($linkSsh, SSH2_FINGERPRINT_SHA1 | SSH2_FINGERPRINT_HEX))) {
        printf("- - SSH server did not return a fingerprint!\n");
        continue;
    }

    if ($sshFingerprint != $server["sshFingerprint"]) {
        printf("- - SSH fingerprint mismatch! (Presented with %s, but should be %s.)\n", $sshFingerprint, $server["sshFingerprint"]);
        continue;
    }
    printf("- - SSH fingerprint verified. (%s)\n", $sshFingerprint);

    $linkSshAuthed = false;
    if (boolval($sshUsePageant) && @ssh2_auth_agent($linkSsh, "root")) {
        printf("- - SSH connection authenticated. (Key agent.)\n");
        $linkSshAuthed = true;
    } else if ($sshKeyFilePublic && $sshKeyFilePrivate && @ssh2_auth_pubkey_file($linkSsh, "root", $sshKeyFilePublic, $sshKeyFilePrivate, $sshKeyFilePassword)) {
        printf("- - SSH connection authenticated. (Key pair.)\n");
        $linkSshAuthed = true;
    } else {
        printf("- - SSH connection authentication failed! (No method available.)\n");
        continue;
    }

    if (!$linkSshAuthed) {
        printf("- - SSH connection authentication failed!\n");
        continue;
    }

    if (!$linkSftp = ssh2_sftp($linkSsh)) {
        printf("- - SFTP connection failed!\n");
        continue;
    }

    printf("- - SFTP connection established.\n");
    // >> SSH connection: Open

    // << Directory: Server
    $directory = sprintf("%s/%s", __DIR__, $s);
    if (!is_dir($directory)) {
        printf("- Directory not found, creating...\n");
        mkdir($directory, 0770, true);
        if (!is_dir($directory)) {
            printf("[Error] Failed to create directory: \"%s\".\n", $directory);
            exit(1);
        }
    }
    // >> Directory: Server

    if (!$directoryCsf = trim($server["pathCsf"])) {
        $directoryCsf = "/etc/csf";
    }

    // << Directory: CSF (remote)
    $directoryCsfR = sprintf("ssh2.sftp://%s%s", $linkSftp, $directoryCsf);
    if (!is_dir($directoryCsfR)) {
        printf("- CSF directory (remote) not found! Is CSF installed on this server?\n");
        continue;
    }
    // >> Directory: CSF (remote)

    // << Directory: CSF (local)
    $directoryCsfL = sprintf("%s/%s", $directory, $directoryCsf);
    if (!is_dir($directoryCsfL)) {
        printf("- CSF directory (local) not found, creating...\n");
        mkdir($directoryCsfL, 0750, true);
        if (!is_dir($directoryCsfL)) {
            printf("[Error] Failed to create CSF directory (local): \"%s\".\n", $directoryCsfL);
            exit(1);
        }
    }
    // >> Directory: CSF (local)

    // << Build: CSF/LFD
    printf("- Building configuration...\n");
    foreach (scandir($directoryCsfBase) as $c) {
        $c      = trim($c);
        $cPath  = sprintf("%s/%s", $directoryCsfBase,   $c);
        $lPath  = sprintf("%s/%s", $directoryCsfL,      $c);
        $rPath  = sprintf("%s/%s", $directoryCsf,       $c);
        $rPathF = sprintf("%s/%s", $directoryCsfR,      $c);

        if (!is_file($cPath)) {
            continue;
        }

        switch ($c) {
            // << Merge server-specific lines into a template
            case "csf.allow":
            case "csf.deny":
                printf("- - Checking for file \"%s\" on remote server...\n", $c);
                if (file_exists($rPathF)) {
                    if (!ssh2_scp_recv($linkSsh, $rPath, $lPath)) {
                        printf("- - - Found on remote server, but couldn't download it!\n");
                    }
                    printf("- - - Downloaded from remote server.\n");
                }

                if (!file_exists($lPath) || !is_file($lPath) || filesize($lPath) < 1) {
                    printf("- - Copying: {$c}\n");
                    copy($cPath, $lPath);
                    break;
                }

                printf("- - Merging: {$c}\n");
                $cContent = file_get_contents($cPath);
                $lContent = file_get_contents($lPath);
                $mContent = $cContent;

                $lSplit   = null;
                if (empty(CSF_PER_SERVER_LINE) || !strpos($lContent, CSF_PER_SERVER_LINE)) {
                    $lSplit = 0;
                    printf("- - - Not found server specific split.\n");
                }

                foreach (preg_split("/[\r\n]/", $lContent) as $l => $line) {
                    if ($line == CSF_PER_SERVER_LINE) {
                        $lSplit = $l;
                        printf("- - - Found server specific split. (%d)\n", $l);

                        if (strpos($mContent, CSF_PER_SERVER_LINE) !== false) {
                            continue;
                        }
                    }

                    if ($lSplit !== null && (substr($line, 0, 1) !== '#' || intval($lSplit) >= 1)) {
                        if ($line) {
                            $mContent .= sprintf("%s\n", $line);
                        }
                    }
                }

                $mContent = trim($mContent) . "\n";

                if (false === file_put_contents($lPath, $mContent)) {
                    printf("- - - Failed to write merged content. Copying base instead...\n");
                    copy($cPath, $lPath);
                }
                break;
            // >> Merge server-specific lines into a template

            // << Build specifically for this server using a template
            case "csf.conf":
                printf("- - Building: {$c}\n");

                if (!isset($server["csfConf"]) || !is_array($server["csfConf"]) || count($server["csfConf"]) < 1) {
                    printf("- - - No CSF configuration defined for server. Copying base instead...\n");
                    copy($cPath, $lPath);
                    $server["csfConf"] = [];
                }

                // Cluster members
                if ($allServersAsClusterString) {
                    $server["csfConf"]["CLUSTER_SENDTO"]    = $allServersAsClusterString;
                    $server["csfConf"]["CLUSTER_RECVFROM"]  = $allServersAsClusterString;
                }

                // Container specific
                switch ($server["container"]) {
                    case "virtuozzo":
                    case "openvz":
                        $server["csfConf"]["LF_IPSET"]          = 0;
                        break;

                    default:
                        $server["csfConf"]["LF_IPSET"]          = 1;
                }

                // Type specific
                switch ($server["type"]) {
                    case "whm":
                        $server["csfConf"]["GENERIC"]           = 0;
                        $server["csfConf"]["PT_APACHESTATUS"]   = "http://127.0.0.1/whm-server-status";
                        break;

                    default:
                        $server["csfConf"]["GENERIC"]           = 1;
                        $server["csfConf"]["PT_APACHESTATUS"]   = "http://127.0.0.1/server-status";
                }

                // OS specific
                switch ($server["os"]) {
                    case "centos":
                    case "centos6":
                    case "rhel":
                    case "cloudlinux":
                        $server["csfConf"] = array_merge($server["csfConf"], [
                            "CSF"               => "/usr/sbin/csf",

                            "IPTABLES"          => "/sbin/iptables",
                            "IPTABLES_SAVE"     => "/sbin/iptables-save",
                            "IPTABLES_RESTORE"  => "/sbin/iptables-restore",
                            "IP6TABLES"         => "/sbin/ip6tables",
                            "IP6TABLES_SAVE"    => "/sbin/ip6tables-save",
                            "IP6TABLES_RESTORE" => "/sbin/ip6tables-restore",
                            "MODPROBE"          => "/sbin/modprobe",
                            "IFCONFIG"          => "/sbin/ifconfig",
                            "SENDMAIL"          => "/usr/sbin/sendmail",
                            "PS"                => "/bin/ps",
                            "VMSTAT"            => "/usr/bin/vmstat",
                            "NETSTAT"           => "/bin/netstat",
                            "LS"                => "/bin/ls",
                            "MD5SUM"            => "/usr/bin/md5sum",
                            "TAR"               => "/bin/tar",
                            "CHATTR"            => "/usr/bin/chattr",
                            "UNZIP"             => "/usr/bin/unzip",
                            "GUNZIP"            => "/bin/gunzip",
                            "DD"                => "/bin/dd",
                            "TAIL"              => "/usr/bin/tail",
                            "GREP"              => "/bin/grep",
                            "IPSET"             => "/usr/sbin/ipset",
                            "SYSTEMCTL"         => "/usr/bin/systemctl",
                            "HOST"              => "/usr/bin/host",
                            "IP"                => "/sbin/ip",

                            "HTACCESS_LOG"      => "/usr/local/apache/logs/error_log",
                            "MODSEC_LOG"        => "/usr/local/apache/logs/error_log",
                            "SSHD_LOG"          => "/var/log/secure",
                            "SU_LOG"            => "/var/log/secure",
                            "FTPD_LOG"          => "/var/log/messages",
                            "SMTPAUTH_LOG"      => "/var/log/exim_mainlog",
                            "SMTPRELAY_LOG"     => "/var/log/exim_mainlog",
                            "POP3D_LOG"         => "/var/log/maillog",
                            "IMAPD_LOG"         => "/var/log/maillog",
                            "CPANEL_LOG"        => "/usr/local/cpanel/logs/login_log",
                            "CPANEL_ACCESSLOG"  => "/usr/local/cpanel/logs/access_log",
                            "SCRIPT_LOG"        => "/var/log/exim_mainlog",
                            "IPTABLES_LOG"      => "/var/log/messages",
                            "SUHOSIN_LOG"       => "/var/log/messages",
                            "BIND_LOG"          => "/var/log/messages",
                            "SYSLOG_LOG"        => "/var/log/messages",
                            "WEBMIN_LOG"        => "/var/log/secure",
                        ]);
                        break;

                    case "centos7":
                        $server["csfConf"] = array_merge($server["csfConf"], [
                            "CSF"               => "/usr/sbin/csf",

                            "IPTABLES"          => "/sbin/iptables",
                            "IPTABLES_SAVE"     => "/sbin/iptables-save",
                            "IPTABLES_RESTORE"  => "/sbin/iptables-restore",
                            "IP6TABLES"         => "/sbin/ip6tables",
                            "IP6TABLES_SAVE"    => "/sbin/ip6tables-save",
                            "IP6TABLES_RESTORE" => "/sbin/ip6tables-restore",
                            "MODPROBE"          => "/sbin/modprobe",
                            "IFCONFIG"          => "/sbin/ifconfig",
                            "SENDMAIL"          => "/usr/sbin/sendmail",
                            "PS"                => "/usr/bin/ps",
                            "VMSTAT"            => "/usr/bin/vmstat",
                            "NETSTAT"           => "/usr/bin/netstat",
                            "LS"                => "/usr/bin/ls",
                            "MD5SUM"            => "/usr/bin/md5sum",
                            "TAR"               => "/usr/bin/tar",
                            "CHATTR"            => "/usr/bin/chattr",
                            "UNZIP"             => "/usr/bin/unzip",
                            "GUNZIP"            => "/usr/bin/gunzip",
                            "DD"                => "/usr/bin/dd",
                            "TAIL"              => "/usr/bin/tail",
                            "GREP"              => "/bin/grep",
                            "IPSET"             => "/usr/sbin/ipset",
                            "SYSTEMCTL"         => "/usr/bin/systemctl",
                            "HOST"              => "/usr/bin/host",
                            "IP"                => "/usr/sbin/ip",

                            "HTACCESS_LOG"      => "/usr/local/apache/logs/error_log",
                            "MODSEC_LOG"        => "/usr/local/apache/logs/error_log",
                            "SSHD_LOG"          => "/var/log/secure",
                            "SU_LOG"            => "/var/log/secure",
                            "FTPD_LOG"          => "/var/log/messages",
                            "SMTPAUTH_LOG"      => "/var/log/exim_mainlog",
                            "SMTPRELAY_LOG"     => "/var/log/exim_mainlog",
                            "POP3D_LOG"         => "/var/log/maillog",
                            "IMAPD_LOG"         => "/var/log/maillog",
                            "CPANEL_LOG"        => "/usr/local/cpanel/logs/login_log",
                            "CPANEL_ACCESSLOG"  => "/usr/local/cpanel/logs/access_log",
                            "SCRIPT_LOG"        => "/var/log/exim_mainlog",
                            "IPTABLES_LOG"      => "/var/log/messages",
                            "SUHOSIN_LOG"       => "/var/log/messages",
                            "BIND_LOG"          => "/var/log/messages",
                            "SYSLOG_LOG"        => "/var/log/messages",
                            "WEBMIN_LOG"        => "/var/log/secure",
                        ]);
                        break;

                    case "debian":
                    case "debian8":
                        $server["csfConf"] = array_merge($server["csfConf"], [
                            "CSF"               => "/usr/sbin/csf",

                            "IPTABLES"          => "/sbin/iptables",
                            "IPTABLES_SAVE"     => "/sbin/iptables-save",
                            "IPTABLES_RESTORE"  => "/sbin/iptables-restore",
                            "IP6TABLES"         => "/sbin/ip6tables",
                            "IP6TABLES_SAVE"    => "/sbin/ip6tables-save",
                            "IP6TABLES_RESTORE" => "/sbin/ip6tables-restore",
                            "MODPROBE"          => "/sbin/modprobe",
                            "IFCONFIG"          => "/sbin/ifconfig",
                            "SENDMAIL"          => "/usr/sbin/sendmail",
                            "PS"                => "/bin/ps",
                            "VMSTAT"            => "/usr/bin/vmstat",
                            "NETSTAT"           => "/bin/netstat",
                            "LS"                => "/bin/ls",
                            "MD5SUM"            => "/usr/bin/md5sum",
                            "TAR"               => "/bin/tar",
                            "CHATTR"            => "/usr/bin/chattr",
                            "UNZIP"             => "/usr/bin/unzip",
                            "GUNZIP"            => "/bin/gunzip",
                            "DD"                => "/bin/dd",
                            "TAIL"              => "/usr/bin/tail",
                            "GREP"              => "/bin/grep",
                            "IPSET"             => "/sbin/ipset",
                            "SYSTEMCTL"         => "/bin/systemctl",
                            "HOST"              => "/usr/bin/host",
                            "IP"                => "/sbin/ip",

                            "HTACCESS_LOG"      => "/var/log/apache2/error.log",
                            "MODSEC_LOG"        => "/var/log/apache2/error.log",
                            "SSHD_LOG"          => "/var/log/auth.log",
                            "SU_LOG"            => "/var/log/messages",
                            "FTPD_LOG"          => "/var/log/messages",
                            "SMTPAUTH_LOG"      => "/var/log/exim4/mainlog",
                            "SMTPRELAY_LOG"     => "/var/log/exim4/mainlog",
                            "POP3D_LOG"         => "/var/log/exim4/mainlog",
                            "IMAPD_LOG"         => "/var/log/exim4/mainlog",
                            "IPTABLES_LOG"      => "/var/log/messages",
                            "SUHOSIN_LOG"       => "/var/log/messages",
                            "BIND_LOG"          => "/var/log/messages",
                            "SYSLOG_LOG"        => "/var/log/syslog",
                            "WEBMIN_LOG"        => "/var/log/auth.log",
                        ]);
                        break;

                    case "debian9":
                        $server["csfConf"] = array_merge($server["csfConf"], [
                            "CSF"               => "/usr/sbin/csf",

                            "IPTABLES"          => "/usr/sbin/iptables",
                            "IPTABLES_SAVE"     => "/usr/sbin/iptables-save",
                            "IPTABLES_RESTORE"  => "/usr/sbin/iptables-restore",
                            "IP6TABLES"         => "/usr/sbin/ip6tables",
                            "IP6TABLES_SAVE"    => "/usr/sbin/ip6tables-save",
                            "IP6TABLES_RESTORE" => "/usr/sbin/ip6tables-restore",
                            "MODPROBE"          => "/usr/sbin/modprobe",
                            "IFCONFIG"          => "/usr/sbin/ifconfig",
                            "SENDMAIL"          => "/usr/sbin/sendmail",
                            "PS"                => "/usr/bin/ps",
                            "VMSTAT"            => "/usr/bin/vmstat",
                            "NETSTAT"           => "/usr/bin/netstat",
                            "LS"                => "/usr/bin/ls",
                            "MD5SUM"            => "/usr/bin/md5sum",
                            "TAR"               => "/usr/bin/tar",
                            "CHATTR"            => "/usr/bin/chattr",
                            "UNZIP"             => "/usr/bin/unzip",
                            "GUNZIP"            => "/usr/bin/gunzip",
                            "DD"                => "/usr/bin/dd",
                            "TAIL"              => "/usr/bin/tail",
                            "GREP"              => "/usr/bin/grep",
                            "IPSET"             => "/usr/sbin/ipset",
                            "SYSTEMCTL"         => "/usr/bin/systemctl",
                            "HOST"              => "/usr/bin/host",
                            "IP"                => "/usr/sbin/ip",

                            "HTACCESS_LOG"      => "/var/log/apache2/error.log",
                            "MODSEC_LOG"        => "/var/log/apache2/error.log",
                            "SSHD_LOG"          => "/var/log/auth.log",
                            "SU_LOG"            => "/var/log/messages",
                            "FTPD_LOG"          => "/var/log/messages",
                            "SMTPAUTH_LOG"      => "/var/log/exim4/mainlog",
                            "SMTPRELAY_LOG"     => "/var/log/exim4/mainlog",
                            "POP3D_LOG"         => "/var/log/exim4/mainlog",
                            "IMAPD_LOG"         => "/var/log/exim4/mainlog",
                            "IPTABLES_LOG"      => "/var/log/messages",
                            "SUHOSIN_LOG"       => "/var/log/messages",
                            "BIND_LOG"          => "/var/log/messages",
                            "SYSLOG_LOG"        => "/var/log/syslog",
                            "WEBMIN_LOG"        => "/var/log/auth.log",
                        ]);
                        break;

                    case "ubuntu":
                    case "ubuntu-16.04":
                        $server["csfConf"] = array_merge($server["csfConf"], [
                            "CSF"               => "/usr/sbin/csf",

                            "IPTABLES"          => "/sbin/iptables",
                            "IPTABLES_SAVE"     => "/sbin/iptables-save",
                            "IPTABLES_RESTORE"  => "/sbin/iptables-restore",
                            "IP6TABLES"         => "/sbin/ip6tables",
                            "IP6TABLES_SAVE"    => "/sbin/ip6tables-save",
                            "IP6TABLES_RESTORE" => "/sbin/ip6tables-restore",
                            "MODPROBE"          => "/sbin/modprobe",
                            "IFCONFIG"          => "/sbin/ifconfig",
                            "SENDMAIL"          => "/usr/sbin/sendmail",
                            "PS"                => "/bin/ps",
                            "VMSTAT"            => "/usr/bin/vmstat",
                            "NETSTAT"           => "/bin/netstat",
                            "LS"                => "/bin/ls",
                            "MD5SUM"            => "/usr/bin/md5sum",
                            "TAR"               => "/bin/tar",
                            "CHATTR"            => "/usr/bin/chattr",
                            "UNZIP"             => "/usr/bin/unzip",
                            "GUNZIP"            => "/bin/gunzip",
                            "DD"                => "/bin/dd",
                            "TAIL"              => "/usr/bin/tail",
                            "GREP"              => "/bin/grep",
                            "IPSET"             => "/sbin/ipset",
                            "SYSTEMCTL"         => "/bin/systemctl",
                            "HOST"              => "/usr/bin/host",
                            "IP"                => "/sbin/ip",

                            "HTACCESS_LOG"      => "/var/log/apache2/error.log",
                            "MODSEC_LOG"        => "/var/log/apache2/error.log",
                            "SSHD_LOG"          => "/var/log/auth.log",
                            "SU_LOG"            => "/var/log/messages",
                            "FTPD_LOG"          => "/var/log/messages",
                            "SMTPAUTH_LOG"      => "/var/log/exim4/mainlog",
                            "SMTPRELAY_LOG"     => "/var/log/exim4/mainlog",
                            "POP3D_LOG"         => "/var/log/exim4/mainlog",
                            "IMAPD_LOG"         => "/var/log/exim4/mainlog",
                            "IPTABLES_LOG"      => "/var/log/messages",
                            "SUHOSIN_LOG"       => "/var/log/messages",
                            "BIND_LOG"          => "/var/log/messages",
                            "SYSLOG_LOG"        => "/var/log/syslog",
                            "WEBMIN_LOG"        => "/var/log/auth.log",
                        ]);
                        break;
                }

                // Detect locations of binaries automatically
                if (!array_key_exists("explicitBins", $server) || !boolval($server["explicitBins"])) {
                    foreach ([
                        "CSF"               => "csf",

                        "IPTABLES"          => "iptables",
                        "IPTABLES_SAVE"     => "iptables-save",
                        "IPTABLES_RESTORE"  => "iptables-restore",
                        "IP6TABLES"         => "ip6tables",
                        "IP6TABLES_SAVE"    => "ip6tables-save",
                        "IP6TABLES_RESTORE" => "ip6tables-restore",
                        "MODPROBE"          => "modprobe",
                        "IFCONFIG"          => "ifconfig",
                        "SENDMAIL"          => "sendmail",
                        "PS"                => "ps",
                        "VMSTAT"            => "vmstat",
                        "NETSTAT"           => "netstat",
                        "LS"                => "ls",
                        "MD5SUM"            => "md5sum",
                        "TAR"               => "tar",
                        "CHATTR"            => "chattr",
                        "UNZIP"             => "unzip",
                        "GUNZIP"            => "gunzip",
                        "DD"                => "dd",
                        "TAIL"              => "tail",
                        "GREP"              => "grep",
                        "IPSET"             => "ipset",
                        "SYSTEMCTL"         => "systemctl",
                        "HOST"              => "host",
                        "IP"                => "ip",
                    ] as $bin => $binFile) {
                        if (false === ($binWhich = @ssh2_exec($linkSsh, sprintf("which %s", $binFile)))) {
                            printf("- - - Binary \"%s\" search failed. Using default location instead...\n", $bin);
                            continue;
                        }

                        stream_set_blocking($binWhich, true);
                        $binWhichOut = ssh2_fetch_stream($binWhich, SSH2_STREAM_STDIO);

                        if (!$binLocation = trim(stream_get_contents($binWhichOut))) {
                            printf("- - - Binary \"%s\" not found. It might not be installed...\n", $bin);
                            continue;
                        }

                        $server["csfConf"][$bin] = $binLocation;
                        printf("- - - Binary \"%s\" found at \"%s\".\n", $bin, $binLocation);
                    }
                }

                $cContent = file_get_contents($cPath);
                $bContent = "";

                foreach (preg_split("/[\r\n]/", $cContent) as $l => $line) {
                    $lineToWrite = trim($line);

                    foreach ($server["csfConf"] as $confKey => $confValue) {
                        if ($confValue === null) {
                            continue;
                        }

                        $confValue      = trim($confValue);
                        $linePattern    = sprintf("/^(%s) = \"([^\\\"]*)\"/", $confKey);
                        $lineMatches    = [];

                        if (preg_match($linePattern, $lineToWrite, $lineMatches)) {
                            printf("- - - %s = %s\n", $confKey, $confValue);
                            $lineToWrite = sprintf("%s = \"%s\"", $confKey, $confValue);
                        }
                    }

                    $bContent .= sprintf("%s\n", $lineToWrite);
                }

                if (false === file_put_contents($lPath, $bContent)) {
                    printf("- - - Failed to write built content. Copying base instead...\n");
                    copy($cPath, $lPath);
                }
                break;
            // >> Build specifically for this server using a template

            // << Copy base as is
            default:
                printf("- - Copying: {$c}\n");
                copy($cPath, $lPath);
            // >> Copy base as is
        }
    }
    // >> Build: CSF/LFD

    // << Upload: CSF/LFD
    if ($enableUpload) {
        printf("- Uploading configuration...\n");
        foreach (scandir($directoryCsfL) as $c) {
            $c      = trim($c);
            $cPath  = sprintf("%s/%s", $directoryCsfBase,   $c);
            $lPath  = sprintf("%s/%s", $directoryCsfL,      $c);
            $rPath  = sprintf("%s/%s", $directoryCsf,       $c);
            $rPathF = sprintf("%s/%s", $directoryCsfR,      $c);

            if (!is_file($lPath)) {
                continue;
            }

            printf("- - Uploading: {$c}\n");
            if (!ssh2_scp_send($linkSsh, $lPath, $rPath, 0640)) {
                printf("- - - Upload failed!\n");
                continue;
            }

            if (!ssh2_sftp_chmod($linkSftp, $rPath, 0640)) {
                printf("- - - Permissions definition failed!\n");
                continue;
            }
        }
    }
    // >> Upload: CSF/LFD

    // << Restart: CSF/LFD
    if ($enableRestart) {
        printf("- Restarting CSF & LFD...\n");
        $binCsf = "/usr/sbin/csf";
        if (!array_key_exists("CSF", $server["csfConf"]) || !$binCsf = trim($server["csfConf"]["CSF"])) {
            printf("- - Binary \"CSF\" search failed. Using default location instead...\n");
        }

        if (false === ($csfRestart = @ssh2_exec($linkSsh, sprintf("%s -ra", $binCsf)))) {
            printf("- - Restart failed! CSF might not be installed...\n");
            continue;
        }

        stream_set_blocking($csfRestart, true);
        $csfRestartOut = ssh2_fetch_stream($csfRestart, SSH2_STREAM_STDIO);
        if (!$csfRestartResult = trim(stream_get_contents($csfRestartOut))) {
            printf("- - Restart failed! No response from service...\n");
            continue;
        }
    }
    // >> Restart: CSF/LFD

    // << SSH connection: Close
    printf("- Closing SSH and SFTP link...\n");
    if ($linkSsh && is_resource($linkSsh)) {
        if (false === @ssh2_exec($linkSsh, "exit")) {
            printf("- - SSH connection did not close cleanly!\n");
        } else {
            printf("- - SSH connection closed.\n");
        }

        $linkSsh        = null;
        $linkSshAuthed  = false;
        $linkSftp       = null;
    }
    // >> SSH connection: Close
}



printf("\nFinished.\n");
exit(0);
