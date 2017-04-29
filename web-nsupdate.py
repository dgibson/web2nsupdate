#! /usr/bin/env python3

import wsgiref
import wsgiref.simple_server
import cgi
import html
import re
import string
import ipaddress
import os
import os.path
import subprocess
import binascii
import base64


domain_re = re.compile(r'[a-z0-9-]+([.][a-z0-9-]+)*')
user_re = re.compile(r'[a-z0-9_]+')
hmac_re = re.compile(rb'[a-zA-Z0-9-]+')
keyname_re = re.compile(rb'[a-zA-Z0-9.]+')
secret_re = re.compile(rb'[a-zA-Z0-9+/=]+')


class Error(Exception):
    pass


def validate_unexpected_params(params):
    for p in params.keys():
        if p not in {'domain', 'user', 'password', 'ip4addr', 'ip6addr'}:
            raise Error("Unexpected parameter '{}'".format(p))


def exactly_one(name, params):
    if name not in params:
        raise Error("Missing parameter '{}'".format(name))
    elif len(params[name]) != 1:
        raise Error("Multiple '{}' parameters".format(name))
    else:
        return params[name][0]


def validate_domain(params):
    domain = exactly_one('domain', params)
    if not domain_re.fullmatch(domain):
        raise Error("Invalid domain parameter")
    return domain


def validate_user(params):
    user = exactly_one('user', params)
    if not user_re.fullmatch(user):
        raise Error("Invalid user name")
    return user


def validate_password(params):
    password = exactly_one('password', params)
    if any(c not in string.printable for c in password):
        raise Error("Invalid characters in password")
    return bytes(password, 'ASCII')


def at_most_one(name, params):
    if name not in params:
        return None
    elif len(params[name]) != 1:
        raise Error("Multiple '{}' parameters".format(name))
    else:
        return params[name][0]


def validate_ip4addr(params):
    ip4addr = at_most_one('ip4addr', params)
    try:
        if ip4addr is not None:
            ip4addr = ipaddress.IPv4Address(ip4addr)
    except ipaddress.AddressValueError:
        raise Error("Invalid IPv4 address")
    return ip4addr


def validate_ip6addr(params):
    ip6addr = at_most_one('ip6addr', params)
    try:
        if ip6addr is not None:
            ip6addr = ipaddress.IPv6Address(ip6addr)
    except ipaddress.AddressValueError:
        raise Error("Invalid IPv6 address")
    return ip6addr


def validate_keyfile(keyfile):
    l = keyfile.split()
    if len(l) != 3:
        raise Error("Badly formatted keyfile")
    hmac, keyname, secret = l

    if not hmac_re.fullmatch(hmac):
        raise Error("Bad characters in algorithm")
    if not keyname_re.fullmatch(keyname):
        raise Error("Bad characters in keyname")
    if not secret_re.fullmatch(secret):
        raise Error("Bad characters in secret")

    try:
        base64.b64decode(secret, validate=True)
    except binascii.Error:
        raise Error("Secret is not valid base64")

    return hmac, keyname, secret


class WebNSUpdateGateway(object):
    def __init__(self, *, logfile, debug=False, gpg_cmd="gpg2", gpg_timeout=1):
        self.logfile = logfile
        self.debug = debug
        self.gpg_cmd = gpg_cmd
        self.gpg_timeout = gpg_timeout

    def log(self, fmt, *args, **kwargs):
        self.logfile.write(fmt.format(*args, **kwargs) + "\n")

    def debuglog(self, fmt, *args, **kwargs):
        if self.debug:
            self.log("DEBUG: " + fmt, *args, **kwargs)

    def respond(self, start_response, status, body):
        body = bytes(body, 'UTF-8')
        hdrs = [
            ('Content-Type', 'text/html'),
            ('Content-Length', str(len(body)))
        ]
        start_response(status, hdrs)
        return [body]

    def error(self, start_response, status, msg):
        self.log("ERROR: {} - {}", status, msg)
        body = """<html>
<title>Error {}</title>
<h1>Error {}</h1>
See log for details.
</html>""".format(html.escape(status), html.escape(status))
        return self.respond(start_response, status, body)

    def read_keyfile(self, user, domain, password):
        path = "~{}/.web-nsupdate/{}.gpg".format(user, domain)
        path = os.path.expanduser(path)

        self.debuglog("Looking for keyfile at: {}", path)

        # These aren't significant from a security point of view (gpg
        # will fail if it can't read the file).  They just make for
        # clearer error messages in likely failure modes.
        if not os.access(path, os.F_OK):
            raise Error("Unknown domain {} for user {}".format(domain, user))
        elif not os.access(path, os.R_OK):
            raise Error("No read permission to keyfile {}".format(path))

        args = [self.gpg_cmd, "--batch", "--passphrase-fd", "0",
                "--decrypt", path]
        self.debuglog("GPG arguments: {}", args)

        try:
            result = subprocess.run(args, input=password,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    timeout=self.gpg_timeout)
        except subprocess.TimeoutExpired:
            msg = "gpg timed out after {} seconds".format(self.gpg_timeout)
            raise Error(msg)

        if result.returncode != 0:
            msg = "gpg returned code {}: {}".format(result.returncode,
                                                    result.stderr)
            raise Error(msg)

        return result.stdout

    def __call__(self, environ, start_response):
        params = cgi.parse_qs(environ['QUERY_STRING'])

        self.debuglog("Raw parameters: {}", params)

        # Basic parameter validation
        # This only checks things without reference to the configuration
        try:
            validate_unexpected_params(params)

            domain = validate_domain(params)
            user = validate_user(params)
            password = validate_password(params)

            ip4addr = validate_ip4addr(params)
            ip6addr = validate_ip6addr(params)

        except Error as e:
            return self.error(start_response, "400 Bad Request", str(e))

        self.debuglog("Parsed request: user={} domain={} A={}  AAAA={}",
                      user, domain, ip4addr, ip6addr)

        # Check against configuration
        try:
            keyfile = self.read_keyfile(user, domain, password)
            hmac, keyname, secret = validate_keyfile(keyfile)
        except Error as e:
            return self.error(start_response, "403 Forbidden", str(e))

        self.debuglog("Parsed keyfile: hmac={} keyname={}", hmac, keyname)

        body = """<html>
<title>Success</title>
<h1>Success</h1>
Done
</html>""".format()
        return self.respond(start_response, "200 OK", body)


if __name__ == '__main__':
    import sys

    host = 'localhost'
    port = 8927

    application = WebNSUpdateGateway(logfile=sys.stderr, debug=True)
    httpd = wsgiref.simple_server.make_server(host, port, application)
    print("Listening on {}:{}".format(host, port))
    httpd.handle_request()
