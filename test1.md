# test1 setup


## Diagram

```
client ---plain--> left-tls:8002   ---tls-----> right-tls:8001   ---plain---.
                                                                             >  loopback:8000
client ---plain--> left-plain:8012 ---plain---> right-plain:8011 ---plain---'
```

## Setup

### Separated

In order to run the left in different machine update the `test1.conf`
`host` option in `[left-*:client]` section to match the machine where the
right process resides.

```
$ python3 -m pyrsecurechannel --config=test1.conf --channel=loopback
$ python3 -m pyrsecurechannel --config=test1.conf --channel=right-plain --channel=right-tls
$ python3 -m pyrsecurechannel --config=test1.conf --channel=left-plain --channel=left-tls
```

### All-in-one

```
$ python3 -m pyrsecurechannel --config=test1.conf
```

## Test

Plain mode path:

```
$ python3 -m pyrloopclient --host=localhost --port=8012
```

Secure channel path:

```
$ python3 -m pyrloopclient --host=localhost --port=8002
```
