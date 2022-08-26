#!/bin/sh
# -*- indent-tabs-mode: nil; tab-width: 2; -*-
# vim: set ts=&2 sw=2 et ai :

dir=` dirname "$0" `

exec "$dir"/target/release/menhera-link generate-shared-secret "$1"
