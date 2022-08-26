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

dev_name=$1

pid_file=/var/run/menhera-link_${dev_name}.pid
pid=` cat "$pid_file" `

kill -TERM $pid
echo "Terminated: PID=$pid" >&2
