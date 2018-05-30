#!/bin/bash

set -- $v

e='./ssbd-exec'
v='./ssbd-verify'

default=0
if grep spec_store_bypass_disable /proc/cmdline; then
	if ! grep spec_store_bypass_disable=seccomp /proc/cmdline; then
		echo "Only seccomp mode is supported for now" 1>&2
		exit 1
	fi
fi

$v 0

$e -s spec-allow -- $v 0
$e -s empty -- $v 1

$e -p enable -- $v 0
$e -p disable -- $v 1
$e -p force-disable -- $v 1

$e -s spec-allow -p enable -- $v 0
$e -s spec-allow -p disable -- $v 1
$e -s spec-allow -p force-disable -- $v 1
$e -s empty -p enable -- $v 1
$e -s empty -p disable -- $v 1
$e -s empty -p force-disable -- $v 1

$e -- $e -- $v 0
$e -- $e -s spec-allow -- $v 0
$e -- $e -s empty -- $v 1

$e -- $e -p enable -- $v 0
$e -- $e -p disable -- $v 1
$e -- $e -p force-disable -- $v 1

$e -s spec-allow -- $e -s spec-allow -- $v 0
$e -s spec-allow -- $e -s empty -- $v 1
$e -s empty -- $e -s spec-allow -- $v 1
$e -s empty -- $e -s empty -- $v 1
