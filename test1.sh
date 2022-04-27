#!/bin/sh

PYTHON="${PYTHON:-python3}"
WAKEUP_TIME="${WAKEUP_TIME:-2}"

die() {
	local m="$1"
	echo "FATAL: ${m}" >&2
	exit 1
}

MYTMP=
PIDS=
cleanup() {
	local p
	for p in ${PIDS}; do
		kill -9 "${p}" > /dev/null 2>&1
	done
	rm -fr "${MYTMP}"
}
trap cleanup 0

background() {
	local r
	"${@}" &
	PIDS="${PIDS} $!"
	return ${r}
}

test_sanity() {
	local pid

        background "${PYTHON}" -m pyrsecurechannel --config=test1.conf --log-level=DEBUG
	pid="$!"
	sleep "${WAKEUP_TIME}"
        "${PYTHON}" -m pyrloopclient --host=localhost --port=8002 || die "8002 failed"
        "${PYTHON}" -m pyrloopclient --host=localhost --port=8012 || die "8012 failed"

	sleep "${WAKEUP_TIME}"
	kill "${pid}"
	wait "${pid}" || die "master failed"
}

test_names() {
	local PREFIX="${MYTMP}/test_names"
	local pid
	local f

	mkdir -p "${PREFIX}"

	sed 's/\(client_name\)=.*/\1=URI:urn:test:bad/' test1.conf > "${PREFIX}/test1-bad-client.conf"
	sed 's/\(server_hostname\)\.*/\1=bad/' test1.conf > "${PREFIX}/test1-bad-server.conf"

	for f in test1-bad-client.conf test1-bad-server.conf; do
		echo "Executing with '${f}'"

		background "${PYTHON}" -m pyrsecurechannel --config="${PREFIX}/${f}"
		pid="$!"
		sleep "${WAKEUP_TIME}"
		"${PYTHON}" -m pyrloopclient --host=localhost --port=8002 && die "8002 succeeded with '${f}'"

		sleep "${WAKEUP_TIME}"
		kill "${pid}"
		wait "${pid}" || die "master failed"
	done
}

test_load1() {
	local pid
	local clients
	local f

        background "${PYTHON}" -m pyrsecurechannel --config=test1.conf
	pid="$!"
	sleep "${WAKEUP_TIME}"

        for f in 0 1 2 3 4 5 6 7 8 9; do
                background "${PYTHON}" -m pyrloopclient --host=localhost --port=8002
                clients="${clients} $!"
                background "${PYTHON}" -m pyrloopclient --host=localhost --port=8012
                clients="${clients} $!"
        done

	local status=0
        for c in ${clients}; do
                wait "${c}" || status=1
        done
        [ ${status} -eq 0 ] || die "One of client failed"

	sleep "${WAKEUP_TIME}"
	kill "${pid}"
	wait "${pid}" || die "master failed"
}

test_split() {
	local pid_looback
	local pid_right
	local pid_left

	echo "Starting all"
        background "${PYTHON}" -m pyrsecurechannel --config=test1.conf --channel=loopback
	pid_loopback="$!"
        background "${PYTHON}" -m pyrsecurechannel --config=test1.conf --channel=right-plain --channel=right-tls
	pid_right="$!"
        background "${PYTHON}" -m pyrsecurechannel --config=test1.conf --channel=left-plain --channel=left-tls
	pid_left="$!"
	sleep "${WAKEUP_TIME}"

        "${PYTHON}" -m pyrloopclient --host=localhost --port=8002 || die "8002 failed"
        "${PYTHON}" -m pyrloopclient --host=localhost --port=8012 || die "8012 failed"

	echo "Stopping right"
	kill "${pid_right}"
	wait "${pid_right}"
        "${PYTHON}" -m pyrloopclient --host=localhost --port=8002 && die "8002 succeeded"
        "${PYTHON}" -m pyrloopclient --host=localhost --port=8012 && die "8012 succeeded"

	echo "Starting right"
        background "${PYTHON}" -m pyrsecurechannel --config=test1.conf --channel=right-plain --channel=right-tls
	pid_right="$!"
	sleep "${WAKEUP_TIME}"

        "${PYTHON}" -m pyrloopclient --host=localhost --port=8002 || die "8002 failed"
        "${PYTHON}" -m pyrloopclient --host=localhost --port=8012 || die "8012 failed"

	echo "Stopping loopback"
	kill "${pid_loopback}"
	wait "${pid_loopback}"
        "${PYTHON}" -m pyrloopclient --host=localhost --port=8002 && die "8002 succeeded"
        "${PYTHON}" -m pyrloopclient --host=localhost --port=8012 && die "8012 succeeded"

	echo "Starting loopback"
        background "${PYTHON}" -m pyrsecurechannel --config=test1.conf --channel=loopback
	pid_loopback="$!"
	sleep "${WAKEUP_TIME}"

        "${PYTHON}" -m pyrloopclient --host=localhost --port=8002 || die "8002 failed"
        "${PYTHON}" -m pyrloopclient --host=localhost --port=8012 || die "8012 failed"

	sleep "${WAKEUP_TIME}"
	for p in "${pid_loopback}" "${pid_right}" "${pid_left}"; do
		kill "${p}"
		wait "${p}" || die "master failed"
	done
}

test_load_split() {
	local pid
	local f

        background "${PYTHON}" -m pyrsecurechannel --config=test1.conf --channel=loopback
	pid="${pid} $!"
        background "${PYTHON}" -m pyrsecurechannel --config=test1.conf --channel=right-plain --channel=right-tls
	pid="${pid} $!"
        background "${PYTHON}" -m pyrsecurechannel --config=test1.conf --channel=left-plain --channel=left-tls
	pid="${pid} $!"
	sleep "${WAKEUP_TIME}"

        for f in 0 1 2 3 4 5 6 7 8 9; do
                background "${PYTHON}" -m pyrloopclient --host=localhost --port=8002
                clients="${clients} $!"
                background "${PYTHON}" -m pyrloopclient --host=localhost --port=8012
                clients="${clients} $!"
        done

	local status=0
        for c in ${clients}; do
                wait "${c}" || status=1
        done
        [ ${status} -eq 0 ] || die "One of client failed"

	sleep "${WAKEUP_TIME}"
	for p in ${pid}; do
		kill "${p}"
		wait "${p}" || die "master failed"
	done
}

test_revoked() {
	local PREFIX="${MYTMP}/test_revoked"
	local pid
	local n
	local m
	local r

	mkdir -p "${PREFIX}"

	for n in server client; do
		sed "s#store/${n}1#store/${n}1-revoked#" test1.conf > "${PREFIX}/test1-revoked-${n}-check.conf"
		sed 's/VERIFY_CRL_CHECK_CHAIN//g' "${PREFIX}/test1-revoked-${n}-check.conf" > "${PREFIX}/test1-revoked-${n}-nocheck.conf"
	done

	for m in nocheck check; do
		for n in server client; do

			echo "Executing with '${m}-${n}'"

			background "${PYTHON}" -m pyrsecurechannel --config="${PREFIX}/test1-revoked-${n}-${m}.conf"
			pid="$!"
			sleep "${WAKEUP_TIME}"
			"${PYTHON}" -m pyrloopclient --host=localhost --port=8002
			r=$?

			case "${m}" in
				nocheck) [ "${r}" -eq 0 ] || die "8002 succeeded with '${m}-${n}'" ;;
				check) [ "${r}" -ne 0 ] || die "8002 succeeded with '${m}-${n}'" ;;
			esac

			sleep "${WAKEUP_TIME}"
			kill "${pid}"
			wait "${pid}" || die "master failed"
		done
	done
}

MYTMP="$(mktemp -d)"

TESTS="${TESTS:-test_sanity test_names test_load1 test_split test_load_split test_revoked}"

for test in $TESTS; do
	echo "------------------------"
	echo "${test}"
	echo "------------------------"
	"${test}"
done
