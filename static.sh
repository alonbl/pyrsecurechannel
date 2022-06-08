#!/bin/sh

EXIT=0

die() {
	local m="$1"
	echo "FAIL: ${m}" >&2
	EXIT=1
}

MODULES="pyrsecurechannel pyrloopclient"

black . || die "black"
codespell --ignore-words=.codespell-ignore-words --skip "*.crt,*.pem,*.req,openssl-easyrsa.cnf,*_cache" || die "codespell"
pycodestyle . || die "pycodestyle"
pylint ${MODULES} || die "pylint"
python3 -m mypy ${MODULES} || die "mypy"

exit ${EXIT}
