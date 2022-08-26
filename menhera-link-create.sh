#!/bin/sh
# -*- indent-tabs-mode: nil; tab-width: 2; -*-
# vim: set ts=&2 sw=2 et ai :

dir=` dirname "$0" `

uid=` id -u `

if [ "$uid" -ne 0 ] ; then
  echo "Error: You must be root" >&2
  exit 1
fi

for last; do true; done

dev_name=$last

log_file=/var/log/menhera-link_${dev_name}.log
pid_file=/var/run/menhera-link_${dev_name}.pid

"$dir"/target/release/menhera-link create "$@" </dev/null > "$log_file" 2>&1 &

pid=$!

echo $pid > "$pid_file"

echo "Launched: PID=$pid, log=$log_file" >&2

# Wait for the interface to configure
sleep 2
