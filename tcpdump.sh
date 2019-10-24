#!/bin/bash

echo "Welcome to pcapture set up for Oracl"
echo "recommened that you check you network device name with ifconfig"
echo "Please input your inputdevice that will be used to capture traffic"
read inputdevice

echo "is ${inputdevice} correct,"
read -p "Continue (y/n)?" choice
case "$choice" in 
  y|Y ) ;;
  n|N ) echo "goodbye" &&  exit;;
  * ) echo "invalid" && exit;;
esac
echo
mkdir /var/tmp/oracl
echo "files will be stored in /var/tmp/oracl/capture_date_time_captured.pcap creating a new file every 10 mins or 10mb in file size."

tcpdump -i ${inputdevice} -w /var/tmp/oracl/capture-%m-%d_%H.%M.%S.%s.pcap -G 600 -C 10