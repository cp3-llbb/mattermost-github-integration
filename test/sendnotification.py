#!/usr/bin/env python

import os.path
import requests
import json

# taken from https://gist.github.com/andrewgross/8ba32af80ecccb894b82774782e7dcd4#gistcomment-1869315
import base64
from OpenSSL.crypto import (sign, load_privatekey, FILETYPE_PEM, TYPE_RSA, PKey, dump_privatekey, dump_publickey)

def generate_keys():
    """
    Generate a new RSA key, return the PEM encoded public and private keys
    """
    pkey = PKey()
    pkey.generate_key(TYPE_RSA, 2048)
    public_key = dump_publickey(FILETYPE_PEM, pkey)
    private_key = dump_privatekey(FILETYPE_PEM, pkey)
    return public_key, private_key

def generate_signature(pem_private_key, content):
    """
    Given a private key and some content, generate a base64 encoded signature for that content.
    Use this during testing in combination with the public key to mimic the travis API.
    """
    private_key = load_privatekey(FILETYPE_PEM, pem_private_key)
    signature = sign(private_key, content, str('sha1'))
    return base64.b64encode(signature)

if __name__ == "__main__":
    import argparse
    argparser = argparse.ArgumentParser("Send Github and Travis notifications to a local server for testing")
    argparser.add_argument("--server", default="localhost:5000", help="Flask app url")
    argparser.add_argument("--test-github", action="store_true", help="Send a test Github notification")
    argparser.add_argument("--test-travis", action="store_true", help="Send a test Github notification")
    argparser.add_argument("--test-gitlab", action="store_true", help="Send a test Github notification")
    argparser.add_argument("--githubpayload", default="github_payload.json", help="A Github notification for testing")
    argparser.add_argument("--githubsecret", default="mysecret", help="Secret to use for Github notifications")
    argparser.add_argument("--travispayload", default="travis_payload.json", help="A Github notification for testing")
    argparser.add_argument("--newkeys", action="store_true", help="Force generating a new testing keypair (for signing the Travis test notifications)")
    argparser.add_argument("--pubkey", default="pubkey.test", help="File to save the public key to")
    argparser.add_argument("--privkey", default="privkey.test", help="File to save the private key to")
    argparser.add_argument("--gitlabpayload", default="gitlab_payload_push.json", help="A Gitlab notification for testing")
    argparser.add_argument("--gitlabevent", default="Push Hook", help="X-Gitlab-Event header value")
    argparser.add_argument("--gitlabsecret", default="mysecret2", help="Secret to use for a Gitlab notification")
    args = argparser.parse_args()

    if args.test_github:
        ## get payload
        if not os.path.isfile(args.githubpayload):
            raise RuntimeError("No such file: {}".format(args.githubpayload))
        with open(args.githubpayload) as pf:
            cont = pf.read()
            payload = cont.encode()
        ## sign it
        import hmac
        import hashlib
        sig = hmac.new(args.githubsecret.encode(), digestmod=hashlib.sha1)
        sig.update(payload)
        signature = sig.hexdigest()

        requests.post(args.server, data=payload,
                headers={
                      "Content-Type"     : "application/json"
                    , "X-Github-Event"   : "ping"
                    , "X-Hub-Signature"  : "sha1={}".format(signature)
                    }
                )

    if args.test_travis:
        ## get the keypair
        pubkey, privkey = None, None
        if not args.newkeys:
            if os.path.isfile(args.pubkey):
                with open(args.pubkey) as pkf:
                    cont = pkf.read()
                    pubkey = cont.encode()
            if not pubkey:
                print("No public key read from {}, a new pair will be generated".format(args.pubkey))
            if os.path.isfile(args.pubkey):
                with open(args.privkey) as pkf:
                    cont = pkf.read()
                    privkey = cont.encode()
            if not privkey:
                print("No private key read from {}, a new pair will be generated".format(args.privkey))
        if args.newkeys or not ( pubkey and privkey ):
            pubkey, privkey = generate_keys()
            with open(args.pubkey, "w") as pkf:
                pkf.write(pubkey.decode())
            with open(args.privkey, "w") as pkf:
                pkf.write(privkey.decode())

        if not os.path.isfile(args.travispayload):
            raise RuntimeError("No such file: {}".format(args.travispayload))
        with open(args.travispayload) as pf:
            payload = pf.read()

        signature = generate_signature(privkey, payload)

        requests.post(args.server, data={"payload" : payload},
                headers={
                      "Travis-Repo-Slug" : "cp3-llbb/justatest"
                    , "Signature"        : signature
                    }
                )
    if args.test_gitlab:
        ## get payload
        if not os.path.isfile(args.gitlabpayload):
            raise RuntimeError("No such file: {}".format(args.gitlabpayload))
        with open(args.gitlabpayload) as pf:
            cont = pf.read()

        requests.post(args.server, data=cont,
                headers={
                      "Content-Type"     : "application/json"
                    , "X-Gitlab-Token"   : args.gitlabsecret.encode()
                    , "X-Gitlab-Event"   : args.gitlabevent
                    }
                )
