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
 * Reminder for new operating system releases: To build a pre-defined set of
 * binary pathnames, use the command in "detect-bins.sh" from a shell on that
 * system.
 * -----------------------------------------------------------------------------
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

if (PHP_VERSION_ID < 70200) {
    printf("[Critical] PHP 7.2 or later required.\n");
    exit(1);
}

// << Check required functions are available
$requiredFunctionsMissing = 0;

foreach ([
    "ssh2_auth_agent",
    "ssh2_auth_pubkey_file",
    "ssh2_connect",
    "ssh2_exec",
    "ssh2_fingerprint",
] as $requiredFunction) {
    if (!function_exists($requiredFunction)) {
        printf("[Critical] Required function \"%s\" is not available. Please check your PHP has the necessary extensions available.\n", $requiredFunction);
        ++$requiredFunctionsMissing;
    }
}

if ($requiredFunctionsMissing) {
    exit(1);
}
// >> Check required functions are available

/** @var bool $sshUsePageant Attempt to use an SSH key agent for authentication. (Pageant.) */
$sshUsePageant = true;
/** @var string|null $sshKeyFilePublic SSH public key file to use for authentication. (OpenSSH format.) */
$sshKeyFilePublic = null;
/** @var string|null $sshKeyFilePrivate SSH private key file to use for authentication. (OpenSSH format.) */
$sshKeyFilePrivate = null;
/** @var string|null $sshKeyFilePassword SSH private key password if encrypted. (This will show in PS!) */
$sshKeyFilePassword = null;
/** @var string[] $serversToAction Limit action to these servers. */
$serversToAction = [];
/** @var int $serversToActionNum Count of `$serversToAction`. */
$serversToActionNum = 0;
/** @var string $serversFileType Server list file type. */
$serversFileType = "yml";
/** @var string $serversFileType Server list file types that are supported. (This should be a constant really.) */
$serversFileTypes = ["json", "yml", "yaml"];
/** @var bool $enableUpload Try to upload after compilation? */
$enableUpload = true;
/** @var bool $enableRestart Restart CSF and LFD after upload? */
$enableRestart = true;

define("CSF_PER_SERVER_LINE", "### SERVER SPECIFIC ENTRIES BELOW THIS LINE ### DO NOT EDIT/REMOVE THIS LINE ###");

/**
 * Show usage of this command and exit.
 * @param  int|null $exitCode Exit code, or null to not exit
 * @return void
 */
function showUsage(?int $exitCode = 0): void
{
    if (null !== $exitCode && $exitCode) {
        printf("\n");
    }

    printf("Usage:\n\n");
    printf("\t--help                      Show usage.\n");
    printf("\n");
    printf("\t--nopageant                 Do not attempt to use an SSH key agent for authentication. (Pageant.)\n");
    printf("\t--sshkeypublic=file         SSH public key file to use for authentication. (OpenSSH format.)\n");
    printf("\t--sshkeyprivate=file        SSH private key file to use for authentication. (OpenSSH format.)\n");
    printf("\t--sshkeypassword=passowrd   SSH private key password if encrypted. (This will show in PS!)\n");
    printf("\t--sshkeypasswordfile=file   SSH private key password if encrypted from a file. (This will show in PS!)\n");
    printf("\n");
    printf("\t--servers=name1,name2,...   Only action specific servers. (Split multiple with a comma.)\n");
    printf("\t--serversfiletype=type      Server list file type. (Type can be json, yml, or yaml.)\n");
    printf("\n");
    printf("\t--upload                    Enable upload after compilation.\n");
    printf("\t--noupload                  Disable upload after compilation.\n");
    printf("\t--restart                   Enable service restart after upload.\n");
    printf("\t--norestart                 Disable service restart after upload.\n");

    if (null !== $exitCode) {
        exit($exitCode);
    }
}

/** @var array<int, string> $argv */
if (isset($argv) && is_array($argv) && $argv) {
    foreach ($argv as $i => $arg) {
        if (0 === $i) {
            continue; // Ignore script name
        }

        /** @var string[] $argMatches */
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

                    if (!($argSshKeyFile = trim($argValue))) {
                        printf("[Error] %s SSH key file not specified.\n", $argKeyType);
                        showUsage(1);
                    }

                    if (!file_exists($argSshKeyFile) || !is_file($argSshKeyFile) || !is_readable($argSshKeyFile)) {
                        printf("[Error] %s SSH key file not found, not a file, or not readable.\n", $argKeyType);
                        showUsage(1);
                    }

                    $sshKeyFileVar  = sprintf("sshKeyFile%s", ucfirst($argKeyType));
                    $$sshKeyFileVar = $argSshKeyFile;
                    printf("SSH %s key file defined as \"%s\".\n", $argKeyType, $argSshKeyFile);
                    break;

                case "sshkeypassword":
                    if (!($sshKeyFilePassword = trim($argValue))) {
                        printf("[Error] SSH key password not specified.\n");
                        showUsage(1);
                    }

                    printf("SSH private key password set.\n");
                    break;

                case "sshkeypasswordfile":
                    if (!($sshKeyFilePasswordFile = trim($argValue))) {
                        printf("[Error] SSH key password file not specified.\n");
                        showUsage(1);
                    }

                    if (!file_exists($sshKeyFilePasswordFile) || !is_file($sshKeyFilePasswordFile) || !is_readable($sshKeyFilePasswordFile)) {
                        printf("[Error] SSH key password file not found, not a file, or not readable.\n");
                        showUsage(1);
                    }

                    if (!($sshKeyFilePassword = file_get_contents($sshKeyFilePasswordFile))) {
                        printf("[Error] SSH key password not specified in file.\n");
                        showUsage(1);
                    }

                    printf("SSH private key password set from file.\n");
                    break;

                case "nopageant":
                    $sshUsePageant = false;
                    printf("SSH key agent will not be used.\n");
                    break;

                case "servers":
                    if (!($argServersStr = trim($argValue))) {
                        printf("[Error] Servers not specified.\n");
                        showUsage(1);
                    }

                    $argServers = explode(',', $argServersStr);
                    if (empty($argServers)) {
                        printf("[Error] Servers not specified.\n");
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
                        printf("[Error] Servers file type not specified.\n");
                        showUsage(1);
                    }

                    if (!in_array($argValue, $serversFileTypes)) {
                        printf("[Error] Servers file type \"%s\" invalid.\n", $argValue);
                        showUsage(1);
                    }

                    $serversFileType = $argValue;
                    printf("Server list file type set to \"%s\".\n", $serversFileType);
                    break;

                default:
                    printf("Switch \"%s\" invalid.\n\n", $argSwitch);
                    showUsage(1);
            }
        } else {
            printf("Argument #%d \"%s\" invalid.\n\n", $i, $arg);
            showUsage(1);
        }
    }
}

if (
    !boolval($sshUsePageant)
    && (
        null === $sshKeyFilePublic
        || (!($sshKeyFilePublic = trim($sshKeyFilePublic)))
        || null === $sshKeyFilePrivate
        || (!($sshKeyFilePrivate = trim($sshKeyFilePrivate)))
    )
) {
    printf("[Error] Viable SSH authentication method not available.\nPlease use a key agent (Pageant) or key files (OpenSSH format).\n");
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

$serversFileType = trim($serversFileType);
if (!in_array($serversFileType, $serversFileTypes)) {
    printf("[Error] Servers file type \"%s\" invalid.\n", $serversFileType);
    exit(1);
}

/** @var string $serversFile Servers list file. */
$serversFile = sprintf("%s.%s", substr(__FILE__, 0, strrpos(__FILE__, '.')), $serversFileType);
/** @var string $serversFileSample Servers list sample file. */
$serversFileSample = sprintf("%s.sample.%s", substr(__FILE__, 0, strrpos(__FILE__, '.')), $serversFileType);

if (!file_exists($serversFile) || !is_file($serversFile) || !is_readable($serversFile)) {
    printf("[Error] Server list file \"%s\" not found, not a file, or not readable.\n", $serversFile);

    if (file_exists($serversFileSample) && is_file($serversFileSample)) {
        printf("I see that the sample server list file \"%s\" exists though.\nYou should make a copy of this as \"%s\" then configure it.\n", $serversFileSample, $serversFile);
    }

    exit(1);
}

/** @var array<string, array<string, mixed>> $servers Servers list. */
$servers = [];
switch ($serversFileType) {
    case "json":
        /** @var array<string, array<string, mixed>> $servers Servers list. */
        $servers = json_decode(file_get_contents($serversFile), true);
        break;

    case "yml":
    case "yaml":
        if (!function_exists("yaml_parse_file")) {
            printf("[Critical] YAML for PHP is not installed. If this is a problem you must use JSON instead.\n");
            exit(1);
        }

        /** @var array<string, array<string, mixed>> $servers Servers list. */
        $servers = yaml_parse_file($serversFile);
        break;

    default:
        printf("[Error] Servers file type \"%s\" invalid.\n", $serversFileType);
        exit(1);
}

if (($serverCount = count($servers)) < 1) {
    printf("[Error] Servers configuration is empty.\n");
    exit(1);
}

printf("Found %d server(s) in configuration, %d to process.\n", $serverCount, ($serversToActionNum >= 1 ? $serversToActionNum : $serverCount));



printf("\nLooking at server list...\n");

/** @var string[] $allServersAsCluster All server addresses in the cluster. */
$allServersAsCluster = [];

foreach ($servers as $s => $server) {
    if ('_' === substr($s, 0, 1)) {
        printf("[Warning] Ignoring server \"%s\" because it starts with a special character.\n", $s);
        unset($servers[$s]);
        continue;
    }

    foreach (["ipv4", "ipv6"] as $k) {
        if (!empty($server[$k]) && ($clusterMemberAddress = trim($server[$k]))) {
            $allServersAsCluster[] = $clusterMemberAddress;
            break; // We're doing this because we don't want to add BOTH IPv4 and IPv6. Just add the first one that got defined.
        }
    }
}

/** @var string $allServersAsClusterString All server addresses in the cluster imploded. */
$allServersAsClusterString = implode(",", $allServersAsCluster);



printf("\nProcessing servers...\n");

/** @var resource|null $linkSsh SSH session handle. */
$linkSsh = null;
/** @var bool $linkSshAuthed SSH session has authenticated. */
$linkSshAuthed = false;
/** @var resource|null $linkSftp SFTP session handle. */
$linkSftp = null;

foreach ($servers as $s => $server) {
    $s = trim($s);
    if (!$s || $s == "_all" || !is_array($server) || empty($server)) {
        continue;
    }

    // Is this server skipped?
    if ($serversToActionNum >= 1 && !in_array($s, $serversToAction)) {
        continue;
    }

    // Show server name
    printf("%s:\n", $s);

    try {
        // << SSH connection: Open
        printf("- Establishing SSH and SFTP link...\n");

        if (isset($linkSsh) && $linkSsh && is_resource($linkSsh)) {
            if (false === ssh2_exec($linkSsh, "exit")) {
                printf("- SSH connection to previous server did not close cleanly.\n");
            }

            $linkSsh = null;
            $linkSshAuthed = false;
            $linkSftp = null;
        }

        if (empty($server["hostname"])) {
            throw new \UnexpectedValueException("Host name not defined.");
        }

        if (!($server["hostname"] = trim($server["hostname"]))) {
            throw new \UnexpectedValueException("Host name not specified.");
        }

        if (empty($server["portSsh"])) {
            throw new \UnexpectedValueException("SSH port not defined.");
        }

        $server["portSsh"] = intval($server["portSsh"]);
        if ($server["portSsh"] < 1 || $server["portSsh"] > 65535) {
            throw new \UnexpectedValueException(sprintf("SSH port %d invalid.", $server["portSsh"]));
        }

        if (empty($server["sshFingerprint"])) {
            throw new \UnexpectedValueException("SSH fingerprint not defined.");
        }

        if (
            (is_array($server["sshFingerprint"]) && empty($server["sshFingerprint"]))
            || (is_string($server["sshFingerprint"]) && !($server["sshFingerprint"] = trim($server["sshFingerprint"])))
        ) {
            throw new UnexpectedValueException("SSH fingerprint not specified.");
        }

        foreach (["hostname", "ipv6", "ipv4"] as $k) {
            if (is_resource($linkSsh = ssh2_connect($server[$k], $server["portSsh"]))) {
                break; // Connection established
            }
        }

        if (!$linkSsh || !is_resource($linkSsh)) {
            throw new \RuntimeException("SSH connection failed.");
        }

        printf("- - SSH connection established.\n");

        if (!($sshFingerprint = trim(ssh2_fingerprint($linkSsh, SSH2_FINGERPRINT_SHA1 | SSH2_FINGERPRINT_HEX)))) {
            throw new \RuntimeException("SSH server did not return a fingerprint.");
        }

        if (
            (is_array($server["sshFingerprint"]) && !in_array($sshFingerprint, $server["sshFingerprint"]))
            || (is_string($server["sshFingerprint"]) && $sshFingerprint != $server["sshFingerprint"])
        ) {
            throw new \RuntimeException(sprintf(
                "SSH fingerprint mismatch. (Presented with %s, but should be %s.)",
                $sshFingerprint,
                is_array($server["sshFingerprint"])
                    ? implode("/", $server["sshFingerprint"])
                    : $server["sshFingerprint"]
            ));
        }
        printf("- - SSH fingerprint verified. (%s)\n", $sshFingerprint);

        if (!$linkSshAuthed && $sshUsePageant) {
            if (ssh2_auth_agent($linkSsh, "root")) {
                printf("- - SSH connection authenticated. (Key agent.)\n");
                $linkSshAuthed = true;
            } else {
                printf("- - SSH connection failed. (Key agent.)\n");
            }
        }

        if (!$linkSshAuthed && $sshKeyFilePublic && $sshKeyFilePrivate) {
            if (ssh2_auth_pubkey_file($linkSsh, "root", $sshKeyFilePublic, $sshKeyFilePrivate, $sshKeyFilePassword)) {
                printf("- - SSH connection authenticated. (Key pair.)\n");
                $linkSshAuthed = true;
            } else {
                printf("- - SSH connection failed. (Key pair.)\n");
            }
        }

        if (!$linkSshAuthed) {
            throw new \RuntimeException("SSH connection authentication failed. (No method available.)");
        }

        if (!($linkSftp = ssh2_sftp($linkSsh))) {
            throw new \RuntimeException("SFTP connection failed.");
        }

        printf("- - SFTP connection established.\n");
        // >> SSH connection: Open

        // << Directory: Server
        $directory = sprintf("%s/%s", __DIR__, $s);
        if (!is_dir($directory)) {
            printf("- Directory not found, creating...\n");
            mkdir($directory, 0770, true);

            if (!is_dir($directory)) {
                throw new \RuntimeException(sprintf("Failed to create directory: \"%s\".", $directory));
            }
        }
        // >> Directory: Server

        if (!($directoryCsf = trim($server["pathCsf"]))) {
            $directoryCsf = "/etc/csf";
        }

        // << Directory: CSF (remote)
        $directoryCsfR = sprintf("ssh2.sftp://%s%s", $linkSftp, $directoryCsf);
        if (!is_dir($directoryCsfR)) {
            printf("- CSF directory (remote) not found. Is CSF installed on this server?\n");
            continue;
        }
        // >> Directory: CSF (remote)

        // << Directory: CSF (local)
        $directoryCsfL = sprintf("%s/%s", $directory, $directoryCsf);
        if (!is_dir($directoryCsfL)) {
            printf("- CSF directory (local) not found, creating...\n");
            mkdir($directoryCsfL, 0750, true);

            if (!is_dir($directoryCsfL)) {
                throw new \RuntimeException(sprintf("Failed to create CSF directory (local): \"%s\".", $directoryCsfL));
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
                case "csf.allow":
                case "csf.deny":
                    // << Merge server-specific lines into a template
                    printf("- - Checking for file \"%s\" on remote server...\n", $c);
                    if (file_exists($rPathF)) {
                        if (!ssh2_scp_recv($linkSsh, $rPath, $lPath)) {
                            printf("- - - Found on remote server, but couldn't download it!\n");
                        }
                        printf("- - - Downloaded from remote server.\n");
                    }

                    if (!file_exists($lPath) || !is_file($lPath) || filesize($lPath) < 1) {
                        printf("- - Copying: %s\n", $c);
                        copy($cPath, $lPath);
                        break;
                    }

                    printf("- - Merging: %s\n", $c);
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

                case "csf.conf":
                    // << Build specifically for this server using a template
                    printf("- - Building: %s\n", $c);

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
                        case "centos6":
                        case "rhel6":
                        case "cloudlinux6":
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

                        case "rhel7":
                        case "centos7":
                        case "cloudlinux7":
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

                        case "rhel8":
                        case "centos8":
                        case "almalinux8":
                        case "cloudlinux8":
                        case "rhel9":
                        case "centos9":
                        case "almalinux9":
                        case "cloudlinux9":
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

                        case "debian8":
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

                        case "debian9":
                        case "debian10":
                        case "debian11":
                        case "debian12":
                        case "ubuntu-20.04":
                        case "ubuntu-22.04":
                        case "ubuntu-24.04":
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
                    }

                    // Detect locations of binaries automatically
                    if (empty($server["explicitBins"]) || !boolval($server["explicitBins"])) {
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
                            if (false === ($binLocator = ssh2_exec($linkSsh, sprintf("type -P %s", $binFile)))) {
                                printf("- - - Binary \"%s\" search failed. Using default location instead...\n", $bin);
                                continue;
                            }

                            stream_set_blocking($binLocator, true);
                            $binLocatorOut = ssh2_fetch_stream($binLocator, SSH2_STREAM_STDIO);

                            if (!($binLocation = trim(stream_get_contents($binLocatorOut)))) {
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

                default:
                    // << Copy base as is
                    printf("- - Copying: %s\n", $c);
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

                printf("- - Uploading: %s\n", $c);
                if (!ssh2_scp_send($linkSsh, $lPath, $rPath, 0640)) {
                    printf("- - - Upload failed.\n");
                    continue;
                }

                if (!ssh2_sftp_chmod($linkSftp, $rPath, 0640)) {
                    printf("- - - Permissions definition failed.\n");
                    continue;
                }
            }
        }
        // >> Upload: CSF/LFD

        // << Restart: CSF/LFD
        if ($enableRestart) {
            printf("- Restarting CSF & LFD...\n");
            $binCsf = "/usr/sbin/csf";
            if (empty($server["csfConf"]["CSF"]) || !($binCsf = trim($server["csfConf"]["CSF"]))) {
                printf("- - Binary \"CSF\" search failed. Using default location instead...\n");
            }

            if (false === ($csfRestart = ssh2_exec($linkSsh, sprintf("%s -ra", $binCsf)))) {
                throw new \RuntimeException("Restart failed. CSF might not be installed...");
            }

            stream_set_blocking($csfRestart, true);
            $csfRestartOut = ssh2_fetch_stream($csfRestart, SSH2_STREAM_STDIO);
            if (!($csfRestartResult = trim(stream_get_contents($csfRestartOut)))) {
                throw new \RuntimeException("Restart failed. No response from service...");
            }
        }
        // >> Restart: CSF/LFD

        // << SSH connection: Close
        printf("- Closing SSH and SFTP link...\n");
        if ($linkSsh && is_resource($linkSsh)) {
            if (false === ssh2_exec($linkSsh, "exit")) {
                printf("- - SSH connection did not close cleanly.\n");
            } else {
                printf("- - SSH connection closed.\n");
            }

            $linkSsh = null;
            $linkSshAuthed = false;
            $linkSftp = null;
        }
        // >> SSH connection: Close
    } catch (\Exception $e) {
        printf("- - %s\n", $e->getMessage());
        continue;
    }
}



printf("\nFinished.\n");
exit(0);
