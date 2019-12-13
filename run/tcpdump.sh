#!/bin/bash

SOURCE="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd $SOURCE/../

source include/config.txt

tcpdump -i ${inputdevice} -w ${folder}/capture-%m-%d_%H.%M.%S.%s.pcap -G ${duration} -C ${filesize}