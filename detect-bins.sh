#!/bin/bash

for BIN_NAME in iptables iptables-save iptables-restore ip6tables ip6tables-save ip6tables-restore modprobe ifconfig sendmail ps vmstat netstat ls md5sum tar chattr unzip gunzip dd tail grep ipset systemctl host ip ; do
    printf "                                \"${BIN_NAME}\" => \"$(type -P $BIN_NAME)\",\n"
done

exit 0
