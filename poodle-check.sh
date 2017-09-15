#!/bin/bash

# Use this script for scanning https hosts for sslv3 support.
# Requierements: nmap, timeout, awk, openssl 

sslv3_check () {
  nmap_input_log="$1"

  if [ -d $nmap_input_log ]; then
    for file in $( ls -1 $nmap_input_log )*; do
      $0 -c $nmap_input_log/$file
    done
  else
    for i in $( awk -F" " '/open/{ print $2 }' $nmap_input_log ); do
      host_name=$( host $i | cut -d " " -f 5 )
      echo | timeout 3 openssl s_client -connect ${i}:443 -ssl3 2>&1 | grep -qo "sslv3 alert handshake failure" && echo "OK: ${i} ${host_name} Not vulnerable" || echo "FAIL:  ${i} ${host_name} vulnerable; sslv3 connection accepted"; 
    done
  fi
}

nmap_scan () {
  nmap_logdir=nmap_logs_$(date +%Y%m%d)

  if ! [ -d $nmap_logdir ]; then
    mkdir $nmap_logdir
  fi

  echo "Write logs to ./${nmap_logdir}"

  while read a; do
    nmap_logname=$( echo $a | sed 's%/%_%g' ).log
    nmap -oG - -Pn -p 443 "$a" > "${nmap_logdir}/${nmap_logname}"
    sslv3_check "${nmap_logdir}/${nmap_logname}"
  done < $1
}

usage () {
  echo "Check target for sslv3 support:"
  echo "Usage: $0 -c <list of ip addresses or hostnames | directory with lists>" 
  echo
  echo "Use nmap to scan networks and then check for sslv3 support"
  echo "Usage: $0 -s <list of subnets or ip addresses>"
}

if [ $# -eq 0 ]; then
  echo "$# non-option arguments"
  usage
fi

while getopts ":c:s:h" opt; do
  case $opt in
    c)
      sslv3_check $OPTARG 
      ;;
    s)
      nmap_scan $OPTARG
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
    h)
      usage
      ;;
    *)
      usage
      ;;
  esac
done
