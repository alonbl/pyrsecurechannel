#!/bin/sh

EXIT=0

die() {
	local m="$1"
	echo "FAIL: ${m}" >&2
	EXIT=1
}

pycodestyle --config=.pycodestyle . || die "pycodestyle"
pylint pyrsecurechannel pyrloopclient || die "pylint"

# TODO - ubuntu-22.04
# Add and resolve --warn-unused-ignores

python3 -m mypy \
	--check-untyped-defs \
	--disallow-incomplete-defs \
	--disallow-untyped-calls \
	--disallow-untyped-decorators \
	--disallow-untyped-defs \
	--no-implicit-optional \
	--no-warn-unused-ignores \
	--strict \
	--strict-equality \
	--warn-redundant-casts \
	--warn-return-any \
	--warn-unreachable \
	pyrsecurechannel \
	pyrloopclient \
	|| die "mypy"

exit ${EXIT}
