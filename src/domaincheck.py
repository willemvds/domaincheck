from dataclasses import dataclass
import datetime
import enum
import math
import re
import subprocess
import ssl
import socket
import time
import typing

from cryptography import x509
from cryptography.hazmat.backends import default_backend
import h2.connection
import h2.events
import h11

import strencodings

MS_PER_S = 1000  # Milliseconds per Second
NetAddr = typing.Tuple[str, int]

# Neutral header shape shared by the h2 and http/1.1 paths so that
# Report.response_headers does not depend on a protocol-specific format
# (hpack.struct.Header is HTTP/2-only, h11.Headers is HTTP/1.1-only).
Headers = list[tuple[bytes, bytes]]


class HTTPVersion(enum.Enum):
    HTTP11 = "http/1.1"
    H2 = "h2"
    H3 = "h3"


@dataclass(kw_only=True)
class Report:
    fqdn: str
    ips: typing.Sequence[str]
    version: HTTPVersion
    cert: x509.Certificate
    tls_connect_ms: int
    http_response_ms: int
    response_headers: Headers
    body: str


IPv4_regex = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.)){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"


def is_IPv4(v: bytes) -> bool:
    match = re.search(
        IPv4_regex, v.decode(strencodings.UTF8, strencodings.DecodeErrors.REPLACE)
    )
    return match is not None


def bytea_to_str(v: bytes) -> str:
    return v.decode(strencodings.UTF8)


def ips(fqdn: str) -> typing.Sequence[str]:
    run_result = subprocess.run(["dog", "-1", fqdn], capture_output=True)
    ips = run_result.stdout.split(b"\n")
    ips = filter(is_IPv4, ips)
    ips = list(map(bytea_to_str, ips))
    return ips


def is_cert_valid(cert: x509.Certificate) -> bool:
    now = datetime.datetime.now(datetime.timezone.utc)
    return now <= cert.not_valid_after_utc


def print_cert_info(cert: x509.Certificate):
    print(f" cert = {cert}")
    print(f"Subject: {cert.subject}")
    print(f"Issuer: {cert.issuer}")
    print(f"Serial Number: {cert.serial_number}")
    print(f"Not Before: {cert.not_valid_before_utc.timestamp()}")
    print(f"Not After: {cert.not_valid_after_utc}")
    for extension in cert.extensions:
        if extension.oid != "subjectAltName":
            continue
        print(f"Extension OID: {extension.oid}")
        print(f"Extension Value: {extension.value}")
    public_key = cert.public_key()
    print(f"Public Key Type: {public_key.__class__.__name__}")
    print(f"Public key: {public_key}")


def _h2_roundtrip(
    tls_sock: ssl.SSLSocket, host: str
) -> tuple[Headers, bytes, float, float]:
    """Perform an HTTP/2 GET / over an established TLS socket.

    Returns (response_headers, body, request_sent_at, response_received_at).
    """
    c2 = h2.connection.H2Connection()
    c2.initiate_connection()

    request_sent_at = time.monotonic()
    tls_sock.sendall(c2.data_to_send())

    headers = [
        (":method", "GET"),
        (":path", "/"),
        (":authority", host),
        (":scheme", "https"),
    ]
    c2.send_headers(1, headers, end_stream=True)
    tls_sock.sendall(c2.data_to_send())

    body = b""
    response_headers: Headers = []
    response_stream_ended = False
    while not response_stream_ended:
        data = tls_sock.recv(65536)
        if not data:
            break

        events = c2.receive_data(data)
        for event in events:
            # print(event)
            if isinstance(event, h2.events.ResponseReceived):
                response_headers = event.headers
            elif isinstance(event, h2.events.DataReceived):
                # update flow control so the server doesn't starve us
                c2.acknowledge_received_data(
                    event.flow_controlled_length, event.stream_id
                )
                body += event.data
            elif isinstance(event, h2.events.StreamEnded):
                response_stream_ended = True
                break
        tls_sock.sendall(c2.data_to_send())
    response_received_at = time.monotonic()

    # tell the server we are closing the h2 connection
    c2.close_connection()
    tls_sock.sendall(c2.data_to_send())
    tls_sock.close()

    return response_headers, body, request_sent_at, response_received_at


def _http1_roundtrip(
    tls_sock: ssl.SSLSocket, host: str
) -> tuple[Headers, bytes, float, float]:
    """Perform an HTTP/1.1 GET / over an established TLS socket using h11.

    Returns (response_headers, body, request_sent_at, response_received_at).
    """
    client = h11.Connection(our_role=h11.CLIENT)

    request = h11.Request(
        method="GET",
        target="/",
        headers=[
            (b"host", host.encode(strencodings.UTF8)),
            (b"user-agent", b"domaincheck"),
            (b"accept", b"*/*"),
            (b"connection", b"close"),
        ],
    )

    request_sent_at = time.monotonic()
    # h11.Connection.send() returns the bytes to put on the wire (or
    # None for events that don't immediately produce wire bytes).
    # EndOfMessage finalises the request framing (empty body -> just
    # headers + terminating blank line).
    out = b""
    chunk = client.send(request)
    if chunk is not None:
        out += chunk
    chunk = client.send(h11.EndOfMessage())
    if chunk is not None:
        out += chunk
    tls_sock.sendall(out)

    body = b""
    response_headers: Headers = []
    response_done = False
    while not response_done:
        event = client.next_event()
        if event is h11.NEED_DATA:
            data = tls_sock.recv(65536)
            # Feeding b"" on EOF lets h11 surface a RemoteProtocolError
            # (or finish streaming a completed response) on the next
            # next_event() call. We then loop back; if it still returns
            # NEED_DATA we bail below.
            client.receive_data(data)
            if not data:
                break
            continue
        if event is h11.PAUSED:
            # Shouldn't happen for a simple client GET; bail defensively.
            break
        if isinstance(event, h11.InformationalResponse):
            # 1xx interim responses are not the final answer; keep going.
            continue
        if isinstance(event, h11.Response):
            response_headers = list(event.headers)
        elif isinstance(event, h11.Data):
            body += event.data
        elif isinstance(event, h11.EndOfMessage):
            response_done = True
            break
        elif isinstance(event, h11.ConnectionClosed):
            break

    response_received_at = time.monotonic()

    tls_sock.close()

    return response_headers, body, request_sent_at, response_received_at


def web(fqdn: str, port: int = 443) -> Report:
    ip_list = ips(fqdn)
    ip = ip_list[0]
    # ip, port = addr

    # context = ssl.create_default_context()
    context = ssl._create_unverified_context()
    context.set_alpn_protocols(["h2", "http/1.1"])
    sock = socket.socket(socket.AF_INET)
    tls_sock = context.wrap_socket(sock, server_hostname=fqdn)

    socket_started_at = time.monotonic()
    tls_sock.connect((ip, port))
    socket_connected_at = time.monotonic()
    c = tls_sock.getpeercert(binary_form=True)
    if c is None:
        raise Exception("no cert found")
    cert = x509.load_der_x509_certificate(c, default_backend())

    # Let the server pick; we report whichever protocol was negotiated.
    negotiated_protocol = tls_sock.selected_alpn_protocol()
    if negotiated_protocol == "h2":
        version = HTTPVersion.H2
        response_headers, body, request_sent_at, response_received_at = _h2_roundtrip(
            tls_sock, fqdn
        )
    elif negotiated_protocol == "http/1.1":
        version = HTTPVersion.HTTP11
        response_headers, body, request_sent_at, response_received_at = (
            _http1_roundtrip(tls_sock, fqdn)
        )
    else:
        raise Exception(f"unexpected ALPN protocol negotiated: {negotiated_protocol!r}")

    tls_connect_ms = math.ceil((socket_connected_at - socket_started_at) * MS_PER_S)
    http_response_ms = math.ceil((response_received_at - request_sent_at) * MS_PER_S)

    r = Report(
        fqdn=fqdn,
        ips=ip_list,
        version=version,
        cert=cert,
        tls_connect_ms=tls_connect_ms,
        http_response_ms=http_response_ms,
        response_headers=response_headers,
        body=body.decode(),
    )

    return r


def has_http1_alpn(addr: NetAddr) -> int:
    host, port = addr

    desired_protocol = "http/1.1"

    context = ssl.create_default_context()
    context.set_alpn_protocols([desired_protocol])
    context.check_hostname = False
    context.verify_mode = ssl.CERT_OPTIONAL
    sock = socket.socket(socket.AF_INET)
    tls_sock = context.wrap_socket(sock, server_hostname=host)
    tls_sock.connect((host, port))

    negotiated_protocol = tls_sock.selected_alpn_protocol()
    return negotiated_protocol == desired_protocol


def has_h2_alpn(addr: NetAddr) -> int:
    host, port = addr

    desired_protocol = "h2"

    context = ssl.create_default_context()
    context.set_alpn_protocols([desired_protocol])
    sock = socket.socket(socket.AF_INET)
    tls_sock = context.wrap_socket(sock, server_hostname=host)
    tls_sock.connect((host, port))

    negotiated_protocol = tls_sock.selected_alpn_protocol()
    return negotiated_protocol == desired_protocol
