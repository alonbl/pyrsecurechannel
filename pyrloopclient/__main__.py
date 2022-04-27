#!/usr/bin/python3

import argparse
import os
import socket
import time


def main() -> None:
    parser = argparse.ArgumentParser(description='pyloopclient')
    parser.add_argument(
        '--host',
        metavar='HOST',
        default='',
        help='Host address',
    )
    parser.add_argument(
        '--port',
        metavar='PORT',
        type=int,
        required=True,
        help='Host port',
    )
    parser.add_argument(
        '--iter',
        metavar='N',
        type=int,
        default=10,
        help='Number of iterations (%(default)s)',
    )
    args = parser.parse_args()

    gold = os.urandom(1024 * 10)
    start = time.time()
    count = 0
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((args.host, args.port))
        for _ in range(args.iter * 1024):
            buf = gold
            while buf:
                n = sock.send(buf)  # pylint: disable=invalid-name
                buf = buf[n:]

            buf = bytearray()
            while len(buf) < len(gold):
                tmp = sock.recv(len(gold) - len(buf))
                if not tmp:
                    raise RuntimeError('Unexpected disconnect')
                buf += tmp
            if buf != gold:
                raise RuntimeError('Corruption')
            count += len(buf)
    end = time.time()
    print(f'Throughput: {(count/(end-start)):,.2f}Bps')


if __name__ == '__main__':
    main()
