#!/usr/bin/python3

import argparse
import asyncio
import configparser
import contextlib
import enum
import importlib.metadata
import logging
import pathlib
import re
import signal
import socket
import ssl
import sys
import typing


# pylint no-member: https://github.com/PyCQA/pylint/issues/2422
# mypy _SSLContext: https://github.com/python/typeshed/issues/1630  # TODO: remove ubuntu-22.04


LOG_LEVELS: typing.Dict[str, int] = {
    'CRITICAL': logging.CRITICAL,
    'ERROR': logging.ERROR,
    'WARNING': logging.WARNING,
    'INFO': logging.INFO,
    'DEBUG': logging.DEBUG,
}


class PrintableError(RuntimeError):
    pass


class ContextFilter(logging.Filter):  # pylint: disable=too-few-public-methods
    def __init__(
            self,
            attrs: typing.Sequence[str],
    ):
        super().__init__()
        self._attrs = attrs

    def filter(
            self,
            record: logging.LogRecord,
    ) -> bool:
        for attr in self._attrs:
            if not getattr(record, attr, None):
                setattr(record, attr, '')
        return True


class Channel():  # pylint: disable=too-few-public-methods

    class Type(enum.Enum):
        LOOPBACK = enum.auto()
        PROXY = enum.auto()

    CHUNK_SIZE = 10*1024

    def __init__(
            self,
            channel: str,
    ):
        self._logger = logging.LoggerAdapter(
            logging.getLogger('pyrsc.channel'),
            extra=dict(
                channel=channel,
            ),
        )

    def _dump_writer(
            self,
            writer: asyncio.StreamWriter,
    ) -> None:
        if self._logger.isEnabledFor(logging.DEBUG):
            self._logger.debug('writer: %r', writer)
            for i in 'sockname', 'peername', 'peercert':
                self._logger.debug('extra: %s=%r', i, writer.get_extra_info(i))

    @staticmethod
    def _get_writer_info(
            writer: asyncio.StreamWriter,
    ) -> str:
        sockname: typing.Optional[typing.Tuple[typing.Any]] = writer.get_extra_info('sockname')
        peername: typing.Optional[typing.Tuple[typing.Any]] = writer.get_extra_info('peername')
        peercert: typing.Optional[typing.Dict[str, typing.Any]] = writer.get_extra_info('peercert')
        return ''.join((
            f"local.socket={':'.join((str(x) for x in sockname))} " if sockname else '',
            f"peer.socket={':'.join((str(x) for x in peername))} " if peername else '',
            'peer.subject={subj} peer.san={san} '.format(  # pylint: disable=consider-using-f-string
                subj=', '.join((', '.join(('='.join(y) for y in x)) for x in peercert.get('subject', ()))),
                san=', '.join((':'.join(x) for x in peercert.get('subjectAltName', ()))),
            ) if peercert else '',
        ))

    @staticmethod
    def _verify_peer(
            writer: asyncio.StreamWriter,
            client_name: str,
    ) -> None:
        if client_name:
            peercert = writer.get_extra_info('peercert')
            if not peercert:
                raise PrintableError("Expected peer certificate")
            if tuple(client_name.split(':', 1)) not in peercert['subjectAltName']:
                raise PrintableError(f"Expected peer name mismatch, expected {client_name} actual {{peer}}".format(
                    peer=', '.join((':'.join(x) for x in peercert.get('subjectAltName', ()))),
                ))


class LoopbackChannel(Channel):  # pylint: disable=too-few-public-methods

    def __init__(
            self,
            channel: str,
            server_args: typing.Dict[str, typing.Any],
            client_name: str,
    ):
        super().__init__(channel)
        self._server_args = server_args
        self._client_name = client_name

    async def _handler(
            self,
            reader: asyncio.StreamReader,
            _writer: asyncio.StreamWriter,
    ) -> None:
        try:
            with contextlib.closing(_writer) as writer:
                self._dump_writer(writer)
                info = self._get_writer_info(writer)
                self._logger.info('%-10s: %s', 'accept', info)
                self._verify_peer(writer, self._client_name)

                while not reader.at_eof():
                    writer.write(await reader.read(self.CHUNK_SIZE))

                self._logger.info('%-10s: %s', 'disconnect', info)
        except PrintableError as ex:
            self._logger.warning(ex)
        except Exception as ex:  # pylint: disable=broad-except
            self._logger.warning(ex, exc_info=True)

    def create(self) -> typing.Coroutine[typing.Any, typing.Any, asyncio.AbstractServer]:
        return asyncio.start_server(
            self._handler,
            **self._server_args,
        )


class ProxyChannel(Channel):  # pylint: disable=too-few-public-methods

    def __init__(
            self,
            channel: str,
            server_args: typing.Dict[str, typing.Any],
            client_name: str,
            connect_args: typing.Dict[str, typing.Any],
    ):
        super().__init__(channel)
        self._server_args = server_args
        self._client_name = client_name
        self._connect_args = connect_args

    async def _pipe(
            self,
            reader: asyncio.StreamReader,
            _writer: asyncio.StreamWriter,
    ) -> None:
        try:
            with contextlib.closing(_writer) as writer:
                while not reader.at_eof():
                    writer.write(await reader.read(self.CHUNK_SIZE))
        except Exception as ex:  # pylint: disable=broad-except
            self._logger.warning(ex, exc_info=True)

    async def _handler(
            self,
            reader: asyncio.StreamReader,
            _writer: asyncio.StreamWriter,
    ) -> None:
        try:
            with contextlib.closing(_writer) as writer:
                self._dump_writer(writer)

                info = self._get_writer_info(writer)
                self._logger.info('%-10s: %s', 'accept', info)
                self._verify_peer(writer, self._client_name)

                (remote_reader, remote_writer) = await asyncio.open_connection(**self._connect_args)
                self._dump_writer(remote_writer)
                remote_info = self._get_writer_info(remote_writer)
                self._logger.info('%-10s: %s', 'connected', remote_info)

                await asyncio.gather(
                    self._pipe(reader, remote_writer),
                    self._pipe(remote_reader, writer),
                )

                self._logger.info('%-10s: %s', 'disconnect', remote_info)
                self._logger.info('%-10s: %s', 'disconnect', info)
        except (PrintableError, ssl.SSLCertVerificationError) as ex:
            self._logger.warning(ex)
        except Exception as ex:  # pylint: disable=broad-except
            self._logger.warning(ex, exc_info=True)

    def create(self) -> typing.Coroutine[typing.Any, typing.Any, asyncio.AbstractServer]:
        return asyncio.start_server(
            self._handler,
            **self._server_args,
        )


_SPLIT_COMMA = re.compile(r'\s*,\s*')


def _split_comma(  # pylint: disable=invalid-name # TODO: ubuntu-22.04 move to 's' line
        s: str,
) -> typing.List[str]:
    return _SPLIT_COMMA.split(s.strip())


def _setup_log(
        args: argparse.Namespace,
        config: configparser.ConfigParser,
) -> None:
    handler = logging.StreamHandler()
    if args.log_file:
        handler.setStream(open(args.log_file, 'a', encoding='utf-8'))  # pylint: disable=consider-using-with
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(
        logging.Formatter(
            config.get(
                'global',
                'logformat',
                fallback='%(asctime)s - %(levelname)-8s %(name)-15s [%(channel)-15s] %(message)s',
            )
        )
    )
    handler.addFilter(ContextFilter(('channel',)))
    logging.getLogger(None).addHandler(handler)

    logger = logging.getLogger('pyrsc')
    logger.setLevel(LOG_LEVELS.get(args.log_level, logging.INFO))


def _setup_argparser(
        distribution: importlib.metadata.Distribution
) -> argparse.ArgumentParser:

    # TODO: remove python-3.10
    name = getattr(distribution, 'name', 'pyrsecurechannel')

    parser = argparse.ArgumentParser(
        prog=name,
        description='Python based secure channel',
    )
    parser.add_argument(
        '--version',
        action='version',
        version=f'{name}-{distribution.version}',
    )
    parser.add_argument(
        '--log-level',
        metavar='LEVEL',
        choices=LOG_LEVELS.keys(),
        default='INFO',
        help=f"Log level {', '.join(LOG_LEVELS.keys())}",
    )
    parser.add_argument(
        '--log-file',
        metavar='FILE',
        help='Log file to use, default is stdout',
    )
    parser.add_argument(
        '--config',
        metavar='FILE',
        required=True,
        help='Secure channel configuration file',
    )
    parser.add_argument(
        '--channel',
        metavar='CHANNEL',
        action='append',
        help='Enable channel, override config channels, may be specified multiple times',
    )
    return parser


def _get_ssl_ctx(
        section: configparser.SectionProxy,
        purpose: ssl.Purpose,
) -> typing.Optional[ssl.SSLContext]:

    ssl_ctx: typing.Optional[ssl.SSLContext] = None

    if section.getboolean('tls'):
        ssl_ctx = ssl.create_default_context(purpose)
        if 'keyfile' in section:
            ssl_ctx.load_cert_chain(
                certfile=section['certfile'],
                keyfile=section['keyfile'],
            )
        if 'dhfile' in section:
            ssl_ctx.load_dh_params(section['dhfile'])
        ssl_ctx.load_verify_locations(capath=section.get('capath'))
        ssl_ctx.check_hostname = True
        ssl_ctx.hostname_checks_common_name = False  # type: ignore # TODO: remove ubuntu-22.04
        if 'verify_mode' in section:
            ssl_ctx.verify_mode = ssl.VerifyMode[  # pylint: disable=no-member # pylint bug
                section['verify_mode']
            ]
        if 'verify_flags' in section:
            ssl_ctx.verify_flags = ssl.VerifyFlags.VERIFY_DEFAULT  # pylint: disable=no-member # pylint bug
            for flag in _split_comma(section['verify_flags']):
                ssl_ctx.verify_flags |= ssl.VerifyFlags[  # pylint: disable=no-member # pylint bug
                    flag
                ] if flag else 0
        if 'ciphers' in section:
            ssl_ctx.set_ciphers(section['ciphers'])
        ssl_ctx.keylog_filename = section.get('sslkeylogfile')  # type: ignore # TODO: remove ubuntu-22.04

    return ssl_ctx


def _get_server_args(
        section: configparser.SectionProxy,
) -> typing.Dict[str, typing.Any]:
    return dict(
        server_args=dict(
            host=section.get('host', 'localhost'),
            port=section.getint('port'),
            flags=socket.AI_PASSIVE | socket.SOCK_STREAM,
            ssl=_get_ssl_ctx(
                section=section,
                purpose=ssl.Purpose.CLIENT_AUTH,
            ),
        ),
        client_name=section.get('client_name'),
    )


def _get_connect_args(
        section: configparser.SectionProxy,
) -> typing.Dict[str, typing.Any]:
    return dict(
        connect_args=dict(
            host=section.get('host', 'localhost'),
            port=section.getint('port'),
            flags=socket.SOCK_STREAM,
            local_addr=(
                section['bind_addr'],
                section['bind_port']
            ) if 'bind_addr' in section else None,
            ssl=_get_ssl_ctx(
                section=section,
                purpose=ssl.Purpose.SERVER_AUTH,
            ),
            server_hostname=section.get('server_hostname'),
        ),
    )


def main() -> None:  # pylint: disable=too-many-statements
    exit_code = 1

    try:
        distribution = importlib.metadata.distribution('pyrsecurechannel')
    except importlib.metadata.PackageNotFoundError:
        distribution = importlib.metadata.PathDistribution(path=pathlib.Path())

    args = _setup_argparser(distribution).parse_args()
    config = configparser.ConfigParser()
    config.read(args.config)

    _setup_log(args, config)
    logger = logging.getLogger('pyrsc')

    logger.info('Startup, version=%s', distribution.version)
    logger.debug('Config: %r', dict(((x, dict(y)) for x, y in config.items())))
    logger.debug('Args: %r', args)

    try:
        with contextlib.closing(asyncio.new_event_loop()) as loop:
            try:
                loop.add_signal_handler(signal.SIGTERM, loop.stop)
                loop.add_signal_handler(signal.SIGINT, loop.stop)
            except NotImplementedError:
                pass

            servers: typing.Dict[str, asyncio.AbstractServer] = {}

            for channel in args.channel if args.channel else _split_comma(config.get('global', 'channels')):
                channel_section = config[channel]

                stype = Channel.Type[channel_section.get('type', 'none').upper()]
                server_key = f'{stype}:{channel}'
                if stype is Channel.Type.PROXY:
                    client_section = config[channel_section['proxy.client']]
                    server_section = config[channel_section['proxy.server']]

                    servers[server_key] = loop.run_until_complete(
                        ProxyChannel(  # type: ignore  # TODO: remove ubuntu-22.04
                            channel=channel,
                            **_get_server_args(server_section),
                            **_get_connect_args(client_section),
                        ).create()
                    )
                elif stype is Channel.Type.LOOPBACK:
                    servers[server_key] = loop.run_until_complete(
                        LoopbackChannel(
                            channel=channel,
                            **_get_server_args(channel_section),
                        ).create()
                    )
                else:
                    raise PrintableError(f"Invalid channel type '{stype}' in '{channel}'")

            logger.debug('Servers: %r', servers)
            try:
                loop.run_forever()
            except:  # noqa
                for server in servers.values():
                    server.close()
                raise

            exit_code = 0
    except KeyboardInterrupt:
        exit_code = 0
    except PrintableError as ex:
        logger.critical(ex)
    except Exception as ex:  # pylint: disable=broad-except
        logger.critical(ex, exc_info=True)

    logger.info('Terminate')
    logger.debug('Exit %d', exit_code)
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
