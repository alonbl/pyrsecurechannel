# A simplified python based secure channel proxy

## Overview

Configuration example is provided in tree.

Deeper understanding of TLS configuration is available at
[python-ssl](https://docs.python.org/3/library/ssl.html#ssl-contexts).


## Pre-requisits

* `Python>=3.8`

## Test

Quick test, run in parallel:

```sh
$ python3 -m pyrsecurechannel --config=test1.conf
$ python3 -m pyrloopclient --host=localhost --port=8002
```

The test can be run within source tree before or after installation.
The `pki-root` prerequisites are required for test to run.

Additional information available at [test1.md](test1.md).

## Build

```sh
# apt install python3-setuptools
# apt install python3-pip
$ python3 ./setup.py bdist_wheel
```

## Install

```sh
# apt install python3-pip
# pip3 install dist/pyrsecurechannel-*.whl
```

## Uninstall

```sh
# pip3 uninstall pyrsecurechannel
```

## Future

Using external keys (engine based) is not supported, for example:
* https://github.com/python/cpython/issues/60691
* https://github.com/python/cpython/issues/72881

A proper implementation will not be able to leverage the plain python support.

## Development

Pre-requisits:

* pycodestyle
* pylint
* mypy

Versions are aligned to ubuntu LTS 20.04.
