#!/bin/bash

set -e

tst='./check-ssbd -q'

default=0
if grep spec_store_bypass_disable /proc/cmdline; then
	if ! grep spec_store_bypass_disable=seccomp /proc/cmdline; then
		echo "Only seccomp mode is supported for now" 1>&2
		exit 1
	fi
fi

cpu_id=
if grep -qm 1 '^vendor_id[[:space:]]\+: GenuineIntel$' /proc/cpuinfo; then
	cpu_id="intel"
elif grep -qm 1 '^vendor_id[[:space:]]*: AuthenticAMD' /proc/cpuinfo; then
	if grep -qm 1 '^cpu family[[:space:]]*: 23' /proc/cpuinfo; then
		cpu_id="amd-17h"
	elif grep -qm 1 '^cpu family[[:space:]]*: 22' /proc/cpuinfo; then
		cpu_id="amd-16h"
	elif grep -qm 1 '^cpu family[[:space:]]*: 22' /proc/cpuinfo; then
		cpu_id="amd-15h"
	fi
else
	echo "ERROR: Only Intel and AMD processors are support for now" 1>&2
	exit 1
fi

tst="$tst -C $cpu_id"

$tst -e 0

$tst -s spec-allow -e 0
$tst -s empty -e 1

$tst -p enable -e 0
$tst -p disable -e 1
$tst -p force-disable -e 1

$tst -s spec-allow -p enable -e 0
$tst -s spec-allow -p disable -e 1
$tst -s spec-allow -p force-disable -e 1
$tst -s empty -p enable -e 1
$tst -s empty -p disable -e 1
$tst -s empty -p force-disable -e 1

$tst -e 0 -- $tst -e 0
$tst -e 0 -- $tst -s spec-allow -e 0
$tst -e 0 -- $tst -s empty -e 1

$tst -e 0 -- $tst -p enable -e 0
$tst -e 0 -- $tst -p disable -e 1
$tst -e 0 -- $tst -p force-disable -e 1

$tst -s spec-allow -e 0 -- $tst -s spec-allow -e 0
$tst -s spec-allow -e 0 -- $tst -s empty -e 1
$tst -s empty -e 1 -- $tst -s spec-allow -e 1
$tst -s empty -e 1 -- $tst -s empty -e 1

$tst -s spec-allow -e 0:30 -- $tst -p enable -e 0:30 -- \
 $tst -p disable -e 1:30 -- $tst -p force-disable -e 1:30 -- \
 $tst -s empty -e 1:30
