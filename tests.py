#! /usr/bin/env python3

import web2nsupdate

from nose.tools import assert_equal, raises

def test_validate_algo():
    assert_equal(web2nsupdate.validate_algo("hmac-sha256"), "hmac-sha256")
    assert_equal(web2nsupdate.validate_algo("hmac-md5"), "hmac-md5")


@raises(web2nsupdate.Error)
def test_bad_algo1():
    web2nsupdate.validate_algo("foo:bar")


def test_validate_keyname():
    assert_equal(web2nsupdate.validate_keyname("key.example.com"),
                 "key.example.com")


@raises(web2nsupdate.Error)
def test_bad_keyname1():
    web2nsupdate.validate_keyname("foo..bar")
