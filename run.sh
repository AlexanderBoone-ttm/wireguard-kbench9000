#!/bin/bash
set -e

nob_cpus() {
	echo "[+] Setting non-boot CPUs to status $1"
	for i in /sys/devices/system/cpu/*/online; do
		[[ $i == *cpu0* ]] && continue
		echo "$1" > "$i"
	done
}

[[ -e kbench9000.ko ]]

trap "nob_cpus 1" INT TERM EXIT
nob_cpus 0

echo "[+] Inserting module to run tests"
stamp="$(date +%s)"
insmod kbench9000.ko stamp="$stamp"

echo "[+] Gathering results"
dmesg | sed -n "s/.*kbench9000: $stamp: \\(.*\\)/\\x1b[37m\\x1b[44m\\x1b[1m\\1\\x1b[0m/p"
