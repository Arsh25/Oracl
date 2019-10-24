#!/bin/bash

source config.txt

tcpdump -i ${inputdevice} -w ${folder}/capture-%m-%d_%H.%M.%S.%s.pcap -G ${duration} -C ${filesize}