#!/usr/bin/env python3
"""Python netcat implementation with Diffie-Hellman key exchange and RSA encryption."""

import argparse
import os
import re
import socket
import sys
import threading
from cryptography.hazmat.primitives.asymmetric import dh, rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding



# -------------------------------------------------------------------------------------------------
# GLOBALS
# -------------------------------------------------------------------------------------------------

UDP_CLIENT_ADDR = None
UDP_CLIENT_PORT = None

NAME = os.path.basename(sys.argv[0])
VERSION = "0.1.0-alpha"

# -------------------------------------------------------------------------------------------------
# HELPER FUNCTIONS
# -------------------------------------------------------------------------------------------------

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
# CLIENT/SERVER COMMUNICATION FUNCTIONS
# -------------------------------------------------------------------------------------------------

def send(s, udp=False, crlf=False, verbose=0):
    """Send one newline terminated line to a connected socket."""
    # In case of sending data back to an udp client we need to wait
    # until the client has first connected and told us its addr/port
    if udp and UDP_CLIENT_ADDR is None and UDP_CLIENT_PORT is None:
        while UDP_CLIENT_ADDR is None and UDP_CLIENT_PORT is None:
            pass
        if verbose > 0:
            print("Client:     %s:%i" % (UDP_CLIENT_ADDR, UDP_CLIENT_PORT), file=sys.stderr)

    # Loop for the thread
    while True:
        # Read user input
        data = input()

        # Ensure to terminate with desired newline
        if isinstance(data, bytes):
            data = b2str(data)
        if crlf:
            data += "\r\n"
        else:
            data += "\n"

        size = len(data)
        data = data.encode()
        send = 0

        # Loop until all bytes have been send
        while send < size:
            try:
                if udp:
                    send += s.sendto(data, (UDP_CLIENT_ADDR, UDP_CLIENT_PORT))
                else:
                    send += s.send(data)
            except (OSError, socket.error) as error:
                print("[Send Error] %s" % (error), file=sys.stderr)
                print(s, file=sys.stderr)
                s.close()
                # exit the thread
                return

    # Close connection when thread stops
    s.close()


def receive(s, udp=False, bufsize=1024, verbose=0):
    """Read one newline terminated line from a connected socket."""
    global UDP_CLIENT_ADDR
    global UDP_CLIENT_PORT

    if verbose > 0:
        print("Receiving:  bufsize=%i" % (bufsize), file=sys.stderr)

    # Loop for the thread
    while True:
        data = ""
        size = len(data)

        while True:
            try:
                (byte, addr) = s.recvfrom(bufsize)
                data += b2str(byte)

                # If we're receiving data from a UDP client
                # we can finally set its addr/port in order
                # to send data back to it (see send() function)
                if udp:
                    UDP_CLIENT_ADDR, UDP_CLIENT_PORT = addr

            except socket.error as err:
                print(err, file=sys.stderr)
                print(s, file=sys.stderr)
                s.close()
                sys.exit(1)
            if not data:
                if verbose > 0:
                    print("[Receive Error] Upstream connection is gone", file=sys.stderr)
                s.close()
                # exit the thread
                return
            # Newline terminates the read request
            if data.endswith("\n"):
                break
            # Sometimes a newline is missing at the end
            # If this round has the same data length as previous, we're done
            if size == len(data):
                break
            size = len(data)
        # Remove trailing newlines
        data = data.rstrip("\r\n")
        data = data.rstrip("\n")
        if verbose > 0:
            print("< ", end="", flush=True, file=sys.stderr)
        print(data)

    # Close connection when thread stops
    s.close()

# -------------------------------------------------------------------------------------------------
# DIFFIE-HELLMAN KEY EXCHANGE FUNCTIONS
# -------------------------------------------------------------------------------------------------

def generate_dh_parameters():
    # Specify the cryptographic backend
    backend = default_backend()

    # Generate the Diffie-Hellman parameters
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=backend)

    return parameters


def generate_dh_key_pair(parameters):
    """Generate Diffie-Hellman key pair."""
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key


def exchange_dh_public_key(s, public_key, verbose=0):
    """Exchange Diffie-Hellman public keys."""
    encoded_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    send(s, encoded_public_key, verbose=verbose)
    received_public_key = receive(s, verbose=verbose)
    return serialization.load_pem_public_key(received_public_key)


def derive_dh_shared_secret(private_key, public_key):
    """Derive the shared secret using Diffie-Hellman key exchange."""
    shared_secret = private_key.exchange(public_key)
    return shared_secret


# -------------------------------------------------------------------------------------------------
# RSA ENCRYPTION/DECRYPTION FUNCTIONS
# -------------------------------------------------------------------------------------------------

def generate_rsa_key_pair():
    """Generate RSA key pair."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


def exchange_rsa_public_key(s, public_key, verbose=0):
    """Exchange RSA public keys."""
    encoded_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    send(s, encoded_public_key, verbose=verbose)
    received_public_key = receive(s, verbose=verbose)
    return serialization.load_pem_public_key(received_public_key)


def rsa_encrypt(public_key, plaintext):
    """Encrypt data using RSA public key."""
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return ciphertext


def rsa_decrypt(private_key, ciphertext):
    """Decrypt data using RSA private key."""
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return plaintext.decode()


# -------------------------------------------------------------------------------------------------
# CLIENT/SERVER INITIALIZATION FUNCTIONS
# -------------------------------------------------------------------------------------------------

#
# Server/Client (TCP+UDP)
#
def create_socket(udp=False, verbose=0):
    """Create TCP or UDP socket."""
    try:
        if udp:
            if verbose > 0:
                print("Socket:     UDP", file=sys.stderr)
            return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            if verbose > 0:
                print("Socket:     TCP", file=sys.stderr)
            return socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as error:
        print("[Socker Error] %s", (error), file=sys.stderr)
        sys.exit(1)


#
# Server (TCP+UDP)
#
def bind(s, host, port, verbose=0):
    """Bind TCP or UDP socket to host/port."""
    if verbose > 0:
        print("Binding:    %s:%i" % (host, port), file=sys.stderr)
    try:
        s.bind((host, port))
    except (OverflowError, OSError, socket.error) as error:
        print("[Bind Error] %s" % (error), file=sys.stderr)
        print(s, file=sys.stderr)
        s.close()
        sys.exit(1)


#
# Server (TCP only)
#
def listen(s, backlog=1, verbose=0):
    """Make TCP socket listen."""
    try:
        if verbose > 0:
            print("Listening:  backlog=%i" % (backlog), file=sys.stderr)
        s.listen(backlog)
    except socket.error as error:
        print("[Listen Error] %s", (error), file=sys.stderr)
        print(s, file=sys.stderr)
        s.close()
        sys.exit(1)


#
# Server (TCP only)
#
def accept(s, verbose=0):
    """Accept connections on TCP socket."""
    try:
        c, addr = s.accept()
    except (socket.gaierror, socket.error) as error:
        print("[Accept Error] %s", (error), file=sys.stderr)
        print(s, file=sys.stderr)
        s.close()
        sys.exit(1)

    host, port = addr
    if verbose > 0:
        print("Client:     %s:%i" % (host, port), file=sys.stderr)

    return c


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

def run_client(host, port, udp=False, bufsize=1024, crlf=False, verbose=0):
    """Connect to host:port, perform key exchange, and send/receive encrypted data."""
    global UDP_CLIENT_ADDR
    global UDP_CLIENT_PORT

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

    # Diffie-Hellman Key Exchange
    dh_params = generate_dh_parameters()
    private_key, public_key = generate_dh_key_pair(dh_params)
    received_public_key = exchange_dh_public_key(s, public_key, verbose=verbose)
    shared_secret = derive_dh_shared_secret(private_key, received_public_key)

    # RSA Key Exchange
    private_key_rsa, public_key_rsa = generate_rsa_key_pair()
    received_public_key_rsa = exchange_rsa_public_key(s, public_key_rsa, verbose=verbose)

    # Start sending and receiving threads with encryption/decryption
    tr = threading.Thread(
        target=receive_encrypted, args=(s, shared_secret, bufsize, verbose)
    )
    ts = threading.Thread(
        target=send_encrypted, args=(s, shared_secret, crlf, verbose)
    )
    # If the main thread kills, these threads will be killed too.
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


# -------------------------------------------------------------------------------------------------
# SERVER
# -------------------------------------------------------------------------------------------------

def run_server(host, port, udp=False, backlog=1, bufsize=1024, crlf=False, verbose=0):
    """Start TCP/UDP server on host/port, perform key exchange, and wait endlessly to send/receive encrypted data."""
    s = create_socket(udp=udp, verbose=verbose)

    bind(s, host, port, verbose=verbose)

    if not udp:
        listen(s, backlog=backlog, verbose=verbose)
        c = accept(s, verbose=verbose)
    else:
        c = s

    # Diffie-Hellman Key Exchange
    dh_params = generate_dh_parameters()
    private_key, public_key = generate_dh_key_pair(dh_params)
    send_public_key = exchange_dh_public_key(c, public_key, verbose=verbose)
    shared_secret = derive_dh_shared_secret(private_key, send_public_key)

    # RSA Key Exchange
    private_key_rsa, public_key_rsa = generate_rsa_key_pair()
    send_public_key_rsa = exchange_rsa_public_key(c, public_key_rsa, verbose=verbose)

    # Start sending and receiving threads with encryption/decryption
    tr = threading.Thread(
        target=receive_encrypted, args=(c, shared_secret, bufsize, verbose)
    )
    ts = threading.Thread(
        target=send_encrypted, args=(c, shared_secret, crlf, verbose)
    )
    # If the main thread kills, these threads will be killed too.
    tr.daemon = True
    ts.daemon = True
    # Start threads
    tr.start()
    ts.start()

    # Do cleanup on the main program
    while True:
        if not tr.is_alive():
            c.close()
            s.close()
            sys.exit(0)
        if not ts.is_alive():
            c.close()
            s.close()
            sys.exit(0)


# -------------------------------------------------------------------------------------------------
# ENCRYPTED CLIENT/SERVER COMMUNICATION FUNCTIONS
# -------------------------------------------------------------------------------------------------

udp = False  # Set udp to True if you want to use UDP communication

def send_encrypted(s, shared_secret, crlf=False, verbose=0):
    """Send encrypted data over the connected socket."""
    if udp and UDP_CLIENT_ADDR is None and UDP_CLIENT_PORT is None:
        while UDP_CLIENT_ADDR is None and UDP_CLIENT_PORT is None:
            pass
        if verbose > 0:
            print("Client:     %s:%i" % (UDP_CLIENT_ADDR, UDP_CLIENT_PORT), file=sys.stderr)

    # Rest of the code...


    # Loop for the thread
    while True:
        # Read user input
        data = input()

        # Ensure to terminate with desired newline
        if isinstance(data, bytes):
            data = b2str(data)
        if crlf:
            data += "\r\n"
        else:
            data += "\n"

        size = len(data)
        data = data.encode()
        send = 0

        # Loop until all bytes have been send
        while send < size:
            try:
                # Encrypt the data using shared_secret
                data_encrypted = rsa_encrypt(shared_secret, data[send:])
                if udp:
                    send += s.sendto(data_encrypted, (UDP_CLIENT_ADDR, UDP_CLIENT_PORT))
                else:
                    send += s.send(data_encrypted)
            except (OSError, socket.error) as error:
                print("[Send Error] %s" % (error), file=sys.stderr)
                print(s, file=sys.stderr)
                s.close()
                # exit the thread
                return

    # Close connection when thread stops
    s.close()


def receive_encrypted(s, shared_secret, bufsize=1024, verbose=0):
    """Receive encrypted data over the connected socket."""
    global UDP_CLIENT_ADDR
    global UDP_CLIENT_PORT

    if verbose > 0:
        print("Receiving:  bufsize=%i" % (bufsize), file=sys.stderr)

    # Loop for the thread
    while True:
        data_encrypted = ""
        size = len(data_encrypted)

        while True:
            try:
                (byte, addr) = s.recvfrom(bufsize)
                data_encrypted += b2str(byte)

                # If we're receiving data from a UDP client
                # we can finally set its addr/port in order
                # to send data back to it (see send() function)
                if udp:
                    UDP_CLIENT_ADDR, UDP_CLIENT_PORT = addr

            except socket.error as err:
                print(err, file=sys.stderr)
                print(s, file=sys.stderr)
                s.close()
                sys.exit(1)
            if not data_encrypted:
                if verbose > 0:
                    print("[Receive Error] Upstream connection is gone", file=sys.stderr)
                s.close()
                # exit the thread
                return
            # Newline terminates the read request
            if data_encrypted.endswith("\n"):
                break
            # Sometimes a newline is missing at the end
            # If this round has the same data length as previous, we're done
            if size == len(data_encrypted):
                break
            size = len(data_encrypted)
        # Remove trailing newlines
        data_encrypted = data_encrypted.rstrip("\r\n")
        data_encrypted = data_encrypted.rstrip("\n")

        # Decrypt the received data using shared_secret
        try:
            data = rsa_decrypt(shared_secret, data_encrypted.encode())
            if verbose > 0:
                print("< ", end="", flush=True, file=sys.stderr)
            print(data)
        except Exception as e:
            print("[Decryption Error] %s" % str(e), file=sys.stderr)

    # Close connection when thread stops
    s.close()




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
        )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        sys.exit(1)
