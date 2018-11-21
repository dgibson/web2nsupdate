#! /usr/bin/env python3

import web2nsupdate
import optparse
import sys
import re
import binascii
import base64
import os.path
import subprocess

openssl_cmd = 'openssl'

keyfile_algo_re = re.compile(r'\s*algorithm\s+([a-zA-Z0-9-]+)\s*;')
keyfile_keyname_re = re.compile(r'\s*key\s+"([^"]+)"\s*{')
keyfile_secret_re = re.compile(r'\s*secret\s+"([^"]+)"\s*;')

def msg(fmt, *args, **kwargs):
    print(fmt.format(*args, **kwargs), file=sys.stderr)


def die(fmt, *args, **kwargs):
    msg(fmt, *args, **kwargs)
    sys.exit(1)


def usage():
    die("Usage: setup-web2nsupdate <keyfile>")


def parse_keyfile(filename):
    f = open(filename, 'r')

    algo, keyname, secret = None, None, None

    for l in f.readlines():
        m = keyfile_algo_re.match(l)
        if m:
            if algo is not None:
                raise web2nsupdate.Error("Found multiple algorithms");
            algo = m.group(1)

        m = keyfile_keyname_re.match(l)
        if m:
            if keyname is not None:
                raise web2nsupdate.Error("Found multiple keynames");
            keyname = m.group(1)

        m = keyfile_secret_re.match(l)
        if m:
            if secret is not None:
                raise web2nsupdate.Error("Found multiple secrets");
            secret = m.group(1)

    if algo is None:
        raise web2nsupdate.Error("Didn't find algorithm")
    if keyname is None:
        raise web2nsupdate.Error("Didn't find keyname")
    if secret is None:
        raise web2nsupdate.Error("Didn't find secret")

    return algo, keyname, secret


def write_configdata(path, configdata):
    args = [openssl_cmd, "enc", "-aes256", "-salt", "-pbkdf2",
            "-out", path]

    data = bytes(configdata, 'UTF-8')

    result = subprocess.run(args, input=data)

    if result.returncode != 0:
        die("Failed to encrypt configdata")


def main():
    parser = optparse.OptionParser()

    opts, args = parser.parse_args()

    if len(args) != 1:
        usage()

    try:
        algo, keyname, secret = parse_keyfile(args[0])

        algo = web2nsupdate.validate_algo(algo)
        keyname = web2nsupdate.validate_keyname(keyname)
        secret = web2nsupdate.validate_secret(secret)
    except web2nsupdate.Error as e:
        die("Couldn't parse keyfile: {}", e)

    # FIXME: Should be able to change these defaults
    domain = keyname
    ttl = 900

    configdata = "{}:{} {} {}".format(algo, keyname, secret, ttl)

    # Sanity check
    assert (web2nsupdate.parse_configdata(configdata)
            == (algo, keyname, secret, ttl))

    dir = os.path.expanduser("~/.web2nsupdate")
    path = os.path.join(dir, domain)

    if os.access(path, os.F_OK):
        die("{} already exists", path)

    if not os.access(dir, os.F_OK):
        os.mkdir(dir)

    if not os.access(dir, os.X_OK | os.W_OK):
        die("{} has incorrect permissions", dir)

    write_configdata(path, configdata)


if __name__ == '__main__':
    main()
