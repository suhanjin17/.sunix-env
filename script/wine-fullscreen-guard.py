#!/usr/bin/env python3
"""Sway Wine fullscreen guard. Usage: start (default), stop, status, run.

No Sway/Wine configuration changes or extra packages. While running, a .pid
file beside this script prevents duplicate instances; it is removed on exit.
Only fullscreen is disabled: floating, focus, window size and position are
left to Sway. Events are reactive, so a brief fullscreen flash is possible.
"""

import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import socket
import struct
import sys


SCRIPT = Path(__file__).resolve()
PIDFILE = SCRIPT.with_suffix('.pid')
HEADER = struct.Struct('=6sII')
WINDOW_EVENT = 0x80000003
SHUTDOWN_EVENT = 0x80000006
IDENTITY = re.compile(r'^wine(?:64)?(?:$|[._/-])|\.exe$', re.I)


def receive(connection):
    def exact(size):
        data = bytearray()
        while len(data) < size:
            chunk = connection.recv(size - len(data))
            if not chunk:
                raise EOFError('Sway 연결이 종료되었습니다.')
            data.extend(chunk)
        return data

    magic, length, kind = HEADER.unpack(exact(HEADER.size))
    if magic != b'i3-ipc' or length > 64 * 1024 * 1024:
        raise RuntimeError('잘못된 Sway IPC 응답입니다.')
    return kind, json.loads(exact(length))


def request(connection, kind, payload=''):
    body = payload.encode()
    connection.sendall(HEADER.pack(b'i3-ipc', len(body), kind) + body)
    response_kind, response = receive(connection)
    if response_kind != kind:
        raise RuntimeError('예상하지 못한 Sway IPC 응답입니다.')
    return response


def is_wine(node):
    properties = node.get('window_properties') or {}
    identities = [node.get('app_id'), properties.get('class'), properties.get('instance')]
    if any(IDENTITY.search(value) for value in identities if value):
        return True
    pid = node.get('pid')
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        process = Path(f'/proc/{pid}')
        return bool(IDENTITY.search((process / 'comm').read_text().strip())
                    or IDENTITY.search((process / 'exe').readlink().name))
    except OSError:
        return False


def protect(connection, node):
    if not node.get('fullscreen_mode') or not is_wine(node):
        return
    con_id = node.get('id')
    if not isinstance(con_id, int) or con_id <= 0:
        return
    results = request(connection, 0, f'[con_id={con_id}] fullscreen disable')
    for result in results:
        if not result.get('success'):
            # A view may disappear between its event and this command.
            print(result.get('error', '전체화면 해제 실패'), file=sys.stderr, flush=True)


def walk(node):
    yield node
    for child in node.get('nodes', []) + node.get('floating_nodes', []):
        yield from walk(child)


def connect(path):
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(5)
    try:
        connection.connect(path)
    except BaseException:
        connection.close()
        raise
    return connection


def current_pid():
    try:
        with PIDFILE.open() as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pid = int(handle.read().strip())
                args = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
                return pid if os.fsencode(SCRIPT) in args else None
    except (OSError, ValueError):
        pass
    return None


def serve(ready=None):
    def announce(message):
        nonlocal ready
        if ready is None:
            print(message, flush=True)
        else:
            os.write(ready, (message + '\n').encode())
            os.close(ready)
            ready = None

    def terminate(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    locked = False
    try:
        path = os.environ.get('SWAYSOCK') or os.environ.get('I3SOCK')
        if not path:
            raise RuntimeError('Sway 세션의 foot 터미널에서 실행하세요. SWAYSOCK이 없습니다.')
        # Connect before creating the PID file: failed starts leave no files.
        with connect(path) as commands, connect(path) as events:
            subscribed = request(events, 2, json.dumps(['window', 'shutdown']))
            if not subscribed.get('success'):
                raise RuntimeError('Sway 이벤트 구독 실패')
            events.settimeout(None)
            with PIDFILE.open('a+') as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise RuntimeError('이미 실행 중입니다.') from None
                locked = True
                try:
                    lock.seek(0)
                    lock.truncate()
                    lock.write(str(os.getpid()) + '\n')
                    lock.flush()
                    # Subscribe first so changes during the initial scan are queued.
                    for node in walk(request(commands, 4)):
                        protect(commands, node)
                    announce(f'Wine 전체화면 방어 실행 중 (PID {os.getpid()})')
                    while True:
                        kind, event = receive(events)
                        if kind == SHUTDOWN_EVENT:
                            return 0
                        if kind == WINDOW_EVENT and event.get('change') in {
                            'new', 'fullscreen_mode', 'title', 'focus', 'move'
                        }:
                            protect(commands, event.get('container') or {})
                finally:
                    if locked:
                        PIDFILE.unlink(missing_ok=True)
    except KeyboardInterrupt:
        return 0
    except (OSError, EOFError, RuntimeError, ValueError) as error:
        announce(f'실행 실패: {error}')
        return 1
    finally:
        if ready is not None:
            os.close(ready)


def start():
    pid = current_pid()
    if pid:
        print(f'이미 실행 중입니다 (PID {pid}).')
        return 0
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        os.setsid()
        with open(os.devnull, 'r+') as null:
            for fd in (0, 1, 2):
                os.dup2(null.fileno(), fd)
        os._exit(serve(write_fd))
    os.close(write_fd)
    with os.fdopen(read_fd) as feedback:
        message = feedback.read().strip()
    print(message or '실행 실패: 프로세스가 시작 중 종료되었습니다.')
    if not message.startswith('Wine 전체화면 방어 실행 중'):
        os.waitpid(child, 0)
        return 1
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['start', 'stop', 'status', 'run'],
                        nargs='?', default='start')
    action = parser.parse_args().action
    if action == 'start':
        return start()
    if action == 'run':
        return serve()
    pid = current_pid()
    if action == 'status':
        print(f'실행 중 (PID {pid})' if pid else '실행 중이 아닙니다.')
        return 0 if pid else 1
    if pid:
        # pidfd prevents sending a signal to a newly reused PID.
        try:
            fd = os.pidfd_open(pid)
            try:
                if current_pid() == pid:
                    signal.pidfd_send_signal(fd, signal.SIGTERM)
                    print(f'종료 요청 완료 (PID {pid}).')
            finally:
                os.close(fd)
        except ProcessLookupError:
            print('이미 종료되었습니다.')
    else:
        print('실행 중이 아닙니다.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
