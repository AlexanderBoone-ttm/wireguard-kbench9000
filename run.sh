#!/bin/bash
set -e

nob_cpus() {
	echo "[+] Setting non-boot CPUs to status $1"
	for i in /sys/devices/system/cpu/*/online; do
		echo "$1" > "$i"
	done
}

noturbo() {
	echo "[+] Setting no-turbo to status $1"
	echo "$1" > /sys/devices/system/cpu/intel_pstate/no_turbo
}

[[ -e kbench9000.ko ]]

trap "nob_cpus 1; noturbo 0;" INT TERM EXIT
noturbo 1
nob_cpus 0

echo "[+] Inserting module to run tests"
stamp="$(date +%s)"
insmod kbench9000.ko stamp="$stamp"

echo "[+] Gathering results"
dmesg | sed -n "s/.*kbench9000: $stamp: \\(.*\\)/\\x1b[37m\\x1b[44m\\x1b[1m\\1\\x1b[0m/p"
