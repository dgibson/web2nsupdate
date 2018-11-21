#! /usr/bin/env python3

# This file is part of web2nsupdate
#
# web2nsupdate is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# web2nsupdate is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with web2nsupdate.  If not, see
# <http://www.gnu.org/licenses/>.

import wsgiref
import wsgiref.simple_server
import urllib.parse
import html
import re
import string
import ipaddress
import os
import os.path
import subprocess
import binascii
import base64


domain_re = re.compile(r'[a-zA-Z0-9-]+([.][a-zA-Z0-9-]+)*')
user_re = re.compile(r'[a-zA-Z0-9_-]+')
algo_re = re.compile(r'[a-zA-Z0-9-]+')
keyname_re = domain_re
secret_re = re.compile(r'[a-zA-Z0-9+/=]+')


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


def validate_ip4addr(params, remote_addr):
    ip4addr = at_most_one('ip4addr', params)
    try:
        if ip4addr == "":
            return False
        elif ip4addr is not None:
            if ip4addr == "auto":
                ip4addr = remote_addr
            ip4addr = ipaddress.IPv4Address(ip4addr)
    except ipaddress.AddressValueError:
        raise Error("Invalid IPv4 address")
    return ip4addr


def validate_ip6addr(params):
    ip6addr = at_most_one('ip6addr', params)
    try:
        if ip6addr == "":
            return False
        elif ip6addr is not None:
            ip6addr = ipaddress.IPv6Address(ip6addr)
    except ipaddress.AddressValueError:
        raise Error("Invalid IPv6 address")
    return ip6addr


def validate_algo(algo):
    if not algo_re.fullmatch(algo):
        raise Error("Badly formatted algorithm '{}'".format(algo))
    return algo


def validate_keyname(keyname):
    if not keyname_re.fullmatch(keyname):
        raise Error("Invalid key name '{}'".format(keyname))
    return keyname


def validate_secret(secret):
    if not secret_re.fullmatch(secret):
        raise Error("Bad characters in secret")
    try:
        base64.b64decode(secret, validate=True)
    except binascii.Error as e:
        raise Error("Secret is not base64: {}".format(e))
    return secret


def validate_ttl(ttl):
    try:
        return int(ttl, 10)
    except ValueError:
        raise Error("Badly formatted TTL: '{}'".format(ttl))


def parse_configdata(configdata):
    l = configdata.split()
    if len(l) != 3:
        raise Error("Badly formatted configdata")
    hmacname, secret, ttl = l
    l = hmacname.split(':')
    if len(l) != 2:
        raise Error("Badly formatted configdata")
    algo, keyname = l

    return (validate_algo(algo), validate_keyname(keyname),
            validate_secret(secret), validate_ttl(ttl))


class Web2NSUpdate(object):
    def __init__(self, *, logfile, debug=False,
                 openssl_cmd="openssl", nsupdate_cmd="nsupdate",
                 openssl_timeout=1, nsupdate_timeout=5):
        self.logfile = logfile
        self.debug = debug
        self.openssl_cmd = openssl_cmd
        self.nsupdate_cmd = nsupdate_cmd
        self.openssl_timeout = openssl_timeout
        self.nsupdate_timeout = nsupdate_timeout

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

    def read_configdata(self, user, domain, password):
        path = "~{}/.web2nsupdate/{}".format(user, domain)
        path = os.path.expanduser(path)

        self.debuglog("Looking for configdata at: {}", path)

        # These aren't significant from a security point of view
        # (openssl will fail if it can't read the file).  They just
        # make for clearer error messages in likely failure modes.
        if not os.access(path, os.F_OK):
            raise Error("Unknown domain {} for user {}".format(domain, user))
        elif not os.access(path, os.R_OK):
            raise Error("No read permission to configdata {}".format(path))

        args = [self.openssl_cmd, "enc", "-aes256", "-d", "-salt", "-pbkdf2",
                "-in", path, "-pass", "stdin"]
        self.debuglog("openssl arguments: {}", args)

        try:
            result = subprocess.run(args, input=password,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    timeout=self.openssl_timeout)
        except subprocess.TimeoutExpired:
            msg = "openssl timed out after {} seconds".format(self.openssl_timeout)
            raise Error(msg)

        if result.returncode != 0:
            msg = "openssl returned code {}: {}".format(result.returncode,
                                                        result.stderr)
            raise Error(msg)

        try:
            return str(result.stdout, encoding='utf-8', errors='strict')
        except ValueError as e:
            raise Error("Bad encoding in configdata: {}".format(e))

    def nsupdate(self, algo, keyname, secret, domain, ttl, ip4addr, ip6addr):
        cmdseq = "key {}:{} {}\n".format(algo, keyname, secret)

        if ip4addr is not None:
            cmdseq += "update delete {} A\n".format(domain)
            if ip4addr:
                cmdseq += "update add {} {} A {}\n".format(domain, ttl, ip4addr)

        if ip6addr is not None:
            cmdseq += "update delete {} AAAA\n".format(domain)
            if ip6addr:
                cmdseq += "update add {} {} AAAA {}\n".format(domain, ttl, ip6addr)

        cmdseq += "send\n"

        cmdseq = bytes(cmdseq, 'utf-8')

        self.debuglog("nsupdate commands: {}", repr(cmdseq))

        args = [self.nsupdate_cmd]
        try:
            result = subprocess.run(args, input=cmdseq,
                                    stderr=subprocess.PIPE,
                                    timeout=self.nsupdate_timeout)
        except subprocess.TimeoutExpired:
            msg = "nsupdate timed out after {} seconds".format(self.nsupdate_timeout)
            raise Error(msg)

        if result.returncode != 0:
            msg = "nsupdate failed: {}".format(result.stderr)
            raise Error(msg)

    def __call__(self, environ, start_response):
        params = urllib.parse.parse_qs(environ['QUERY_STRING'],
                                       keep_blank_values=True)

        self.debuglog("Raw parameters: {}", params)

        # Basic parameter validation
        # This only checks things without reference to the configuration
        try:
            validate_unexpected_params(params)

            domain = validate_domain(params)
            user = validate_user(params)
            password = validate_password(params)

            ip4addr = validate_ip4addr(params, environ['REMOTE_ADDR'])
            ip6addr = validate_ip6addr(params)

        except Error as e:
            return self.error(start_response, "400 Bad Request", str(e))

        self.debuglog("Parsed request: user={} domain={} A={}  AAAA={}",
                      user, domain, ip4addr, ip6addr)

        # Early exit if no updates needed
        if ip4addr is None and ip6addr is None:
            body = """<html>
<title>Success</title>
<h1>Success</h1>
No update needed
</html>""".format()
            return self.respond(start_response, "200 OK", body)

        # Check against configuration
        try:
            configdata = self.read_configdata(user, domain, password)
            algo, keyname, secret, ttl = parse_configdata(configdata)
        except Error as e:
            return self.error(start_response, "403 Forbidden", str(e))

        self.debuglog("Parsed configdata: {}:{}  TTL={}", algo, keyname, ttl)

        try:
            self.nsupdate(algo, keyname, secret, domain, ttl, ip4addr, ip6addr)
        except Error as e:
            return self.error(start_response, "403 Forbidden", str(e))

        msg = ""
        if ip4addr is not None:
            msg += " A {}".format(ip4addr or "<deleted>")
        if ip6addr is not None:
            msg += " AAAA {}".format(ip6addr or "<deleted>")
        self.log("web2nsupdate updated {} for {}:{}", domain, user, msg)

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

    application = Web2NSUpdate(logfile=sys.stderr, debug=True)
    httpd = wsgiref.simple_server.make_server(host, port, application)
    print("Listening on {}:{}".format(host, port))
    httpd.handle_request()
