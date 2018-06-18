import json
import requests
from flask import request

from mattermostgithub import config, app

import hmac
import hashlib
SECRET = hmac.new(config.SECRET, digestmod=hashlib.sha1) if config.SECRET else None

def check_signature_githubsecret(signature, secret, payload):
    sig2 = secret.copy()
    sig2.update(payload)
    return sig2.hexdigest() == signature

def get_travis_public_key():
    from urllib.parse import urlparse
    import os.path

    cfg_url = config.TRAVIS_CONFIG_URL
    if urlparse(cfg_url).scheme: ## valid url
        response = requests.get(config.TRAVIS_CONFIG_URL, timeout=10.0)
        response.raise_for_status()
        return response.json()['config']['notifications']['webhook']['public_key']
    elif os.path.isfile(cfg_url): ## local file (for testing)
        with open(cfg_url, "r") as pkf:
            cont = pkf.read()
            pubkey = cont.encode()
            if not pubkey:
                raise RuntimeError("No public key found in {}".format(cfg_url))
            return pubkey
    else:
        raise ValueError("Travis config url '{}' is neither a valid url nor an existing local file path".format(cfg_url))

import OpenSSL.crypto
def check_signature(signature, pubkey, payload):
    from OpenSSL.crypto import verify, load_publickey, FILETYPE_PEM, X509
    pkey_public_key = load_publickey(FILETYPE_PEM, pubkey)
    cert = X509()
    cert.set_pubkey(pkey_public_key)
    verify(cert, signature, payload, str('sha1'))

@app.route(config.SERVER['hook'] or "/", methods=['GET'])
def alive():
    return 'Server Up and Running', 200

@app.route(config.SERVER['hook'] or "/", methods=['POST'])
def root():
    if "X-Github-Event" in request.headers:
        ## assume Github notification, authenticate if needed
        if SECRET:
            signature = request.headers.get('X-Hub-Signature', None)
            if not signature:
                return 'Missing X-Hub-Signature', 400
            if not check_signature_githubsecret(signature.split("=")[1], SECRET, request.data):
                return 'Invalid X-Hub-Signature', 400

        json_data = request.json
        if not json_data:
            print('Invalid Content-Type')
            return 'Content-Type must be application/json and the request body must contain valid JSON', 400

        try:
            return handle_github(json_data, request.headers['X-Github-Event'])
        except Exception as ex:
            print("Error interpreting github notification: {}".format(ex))
            return "Internal error", 400

    elif "Travis-Repo-Slug" in request.headers:
        payload = request.form.get("payload")
        if not payload:
            return "Invalid payload", 400

        ### Travis-CI notification, verify
        ## adapted from https://gist.github.com/andrewgross/8ba32af80ecccb894b82774782e7dcd4
        if config.TRAVIS_CONFIG_URL:
            if "Signature" not in request.headers:
                return "No signature", 404
            import base64
            signature = base64.b64decode(request.headers["Signature"])
            try:
                pubkey = get_travis_public_key()
            except requests.Timeout:
                print("Travis public key timeout")
                return "Could not get travis server public key", 400
            except requests.RequestException as ex:
                print("Travis public key exception: {0}".format(ex.message))
                return "Could not get travis server public key", 400
            except Exception as ex:
                print("Problem getting public key: {}".format(ex))
                return "Internal error", 400
            try:
                check_signature(signature, pubkey, payload)
            except OpenSSL.crypto.Error:
                print("Request failed verification")
                return "Unauthorized", 404

        try:
            data = json.loads(payload)
            return handle_travis(data)
        except Exception as ex:
            print("Error interpreting travis notification: {}".format(ex))
            return "Internal error", 400
    elif "X-Gitlab-Event" in request.headers:
        ## Gitlab notification, authenticate if needed
        if ( not config.GITLAB_SECRET ) or request.headers.get("X-Gitlab-Token", None) != config.GITLAB_SECRET:
            return "Invalid X-Gitlab-Token", 400

        json_data = request.json
        if not json_data:
            print('Invalid Content-Type')
            return 'Content-Type must be application/json and the request body must contain valid JSON', 400

        try:
            return handle_gitlab(json_data, request.headers['X-Gitlab-Event'])
        except Exception as ex:
            print("Error interpreting gitlab notification: {}".format(ex))
            return "Internal error", 400
    else:
        print("Unknown notification type")
        return "Unknown notification type", 400

def handle_github(data, event):
    from mattermostgithub.github_payload import (
        PullRequest, PullRequestComment, Issue, IssueComment,
        Repository, Branch, Push, Tag, CommitComment, Wiki
    )
    msg = ""
    if event == "ping":
        msg = "ping from %s" % data['repository']['full_name']
    elif event == "pull_request":
        if data['action'] == "opened":
            msg = PullRequest(data).opened()
        elif data['action'] == "closed":
            msg = PullRequest(data).closed()
        elif data['action'] == "assigned":
            msg = PullRequest(data).assigned()
        elif data['action'] == "synchronize":
            msg = PullRequest(data).synchronize()
    elif event == "issues":
        if data['action'] == "opened":
            msg = Issue(data).opened()
        elif data['action'] == "closed":
            msg = Issue(data).closed()
        elif data['action'] == "labeled":
            msg = Issue(data).labeled()
        elif data['action'] == "assigned":
            msg = Issue(data).assigned()
    elif event == "issue_comment":
        if data['action'] == "created":
            msg = IssueComment(data).created()
    elif event == "repository":
        if data['action'] == "created":
            msg = Repository(data).created()
    elif event == "create":
        if data['ref_type'] == "branch":
            msg = Branch(data).created()
        elif data['ref_type'] == "tag":
            msg = Tag(data).created()
    elif event == "delete":
        if data['ref_type'] == "branch":
            msg = Branch(data).deleted()
    elif event == "pull_request_review_comment":
        if data['action'] == "created":
            msg = PullRequestComment(data).created()
    elif event == "push":
        if not (data['deleted'] and data['forced']):
            if not data['ref'].startswith("refs/tags/"):
                msg = Push(data).commits()
    elif event == "commit_comment":
        if data['action'] == "created":
            msg = CommitComment(data).created()
    elif event == "gollum":
        msg = Wiki(data).updated()

    if msg:
        hook_info = get_hook_info(data)
        if hook_info:
            url, channel = get_hook_info(data)

            if hasattr(config, "GITHUB_IGNORE_ACTIONS") and \
               event in config.GITHUB_IGNORE_ACTIONS and \
               data['action'] in config.GITHUB_IGNORE_ACTIONS[event]:
                return "Notification action ignored (as per configuration)"

            post(msg, url, channel)
            return "Notification successfully posted to Mattermost"
        else:
            return "Notification ignored (repository is blacklisted)."
    else:
        return "Not implemented", 400

def handle_travis(data):
    ## repo info
    repo_msg = "[{name}]({url})".format(name=data["repository"]["name"], url=data["repository"]["url"])

    ## status message
    buildstatus_msg = "[#{no}]({url}) {status}".format(
            no=data["number"],
            url=data["build_url"],
            status=data["status_message"].lower())

    ## interpret event
    ntype = data["type"]
    event_msg = "EVENT_PLACEHOLDER"
    if ntype == "push":
        event_msg = "pushed commit {commit} on branch {branch} by {author}".format(
                commit="[{0}]({1})".format(data["message"].split("\n")[0], data["compare_url"]),
                branch=data["branch"],
                author=("[{name}](mailto:{mail}){0}".format(
                      ( "" if data["author_name"] == data["committer_name"] and data["author_email"] == data["committer_email"]
                      else " with [{name}](mailto:{mail})".format(name=data["committer_name"], mail=data["committer_email"]))
                    , name=data["author_name"], mail=data["author_email"]
                    )
                )
                )
    elif ntype == "pull_request":
        event_msg = "pull request {prid} \"{prtitle}\" by {author}".format(
                prid="[#{0}]({1})".format(data["pull_request_number"], data["compare_url"]),
                prtitle=data["pull_request_title"],
                author="[{name}]({mail})".format(name=data["author_name"], mail=data["author_email"])
                )
    else:
        raise ValueError("Unknown event type {}".format(data["type"]))

    msg = "Travis build {build_status} for {event} in {repo}".format(
            repo=repo_msg,
            build_status=buildstatus_msg,
            event=event_msg)

    hook_info = get_hook_info(data)
    if hook_info:
        url, channel = hook_info
        post(msg, url, channel)
        return "Notification successfully posted to Mattermost"
    else:
        return "Notification ignored (repository is blacklisted)."

def handle_gitlab(data, event):
    import os.path
    def puser_link(udata, web_base): ## for push events
        nmemail = "[{nm}]({profile})".format(nm=udata["user_name"], profile=os.path.join(web_base, udata["user_username"])) if "user_username" in udata else udata["user_name"]
        if config.SHOW_AVATARS:
            return "![]({av}) {nm}".format(av=udata["user_avatar"], nm=nmemail)
        return nmemail
    def user_link(udata, web_base):
        nmemail = "[{nm}]({profile})".format(nm=udata["name"], profile=os.path.join(web_base, udata["username"]))
        if config.SHOW_AVATARS:
            return "![]({av}) {nm}".format(av=udata["avatar_url"], nm=nmemail)
        return nmemail
    def repo_link(repodata):
        return "[{nm}]({url})".format(nm=repodata["name"], url=repodata["homepage"])
    def ref_link(ref, repourl):
        return "[{nm}]({repourl}/tree/{nm})".format(nm="/".join(ref.split("/")[2:]), repourl=repourl)
    def commit_linkmsg(cdata):
        return "[`{chsh}`]({curl}) {cmsg}".format(
                  chsh=cdata["id"][:7]
                , curl=cdata["url"]
                , cmsg=cdata["message"].split("\n")[0]
                )
    def issuemrsnippet_link(objdata, url):
        return "[#{iid}: {title}]({url})".format(iid=objdata.get("iid", objdata["id"]), title=objdata["title"], url=url)

    actionTransl = {
              "open"   : "opened"
            , "close"  : "closed"
            , "update" : "updated"
            , "merge"  : "merged"
            , "reopen" : "reopened"
            , "create" : "created"
            , "delete" : "deleted"
            }
    repoweb = data["repository"]["homepage"] if "repository" in data else data["project"]["web_url"]
    webbase = "/".join(repoweb.split("/")[:-2]) ## remove last two paths
    attrs = data.get("object_attributes", dict())
    msg = None
    if event == "Push Hook":
        msg = "{user} pushed {ncomm} to {branch} in {repo}\n{commitlist}".format(
              user=puser_link(data, webbase)
            , repo=repo_link(data["repository"])
            , branch=ref_link(data["ref"], repourl=repoweb)
            , ncomm=("{0:d} commits".format(data["total_commits_count"]) if data["total_commits_count"] > 1 else "a commit")
            , commitlist="\n".join("- {}".format(commit_linkmsg(cdata)) for cdata in data["commits"])
            )
    elif event == "Tag Push Hook":
        if data["object_kind"] == "tag_push":
            msg = "{user} pushed tag {tag} in {repo}".format(
                  user=puser_link(data, webbase)
                , repo=repo_link(data["repository"])
                , tag=ref_link(data["ref"], repourl=repoweb)
                )
    elif event == "Note Hook":
        ntype = attrs["noteable_type"]
        if ntype == "Commit":
            objlink = "commit {}".format(commit_linkmsg(data["commit"]))
        else:
            nttypes = { "MergeRequest" : ("merge_request", "merge request")
                      , "Issue"        : ("issue", "issue")
                      , "Snippet"      : ("snippet", "snippet")
                      }
            if ntype not in nttypes:
                raise ValueError("Not a valid noteable_type: '{}'".format(ntype))
            else:
                issuemrsnippet_url = attrs["url"].split("#")[0]
                objlink = "{descr} {link}".format(descr=nttypes[ntype][1], link=issuemrsnippet_link(data[nttypes[ntype][0]], url=issuemrsnippet_url))
        msg = "{user} added [a comment]({noteurl}) on {obj} in {repo}\n{note}".format(
                  user=user_link(data["user"], webbase)
                , noteurl=attrs["url"]
                , obj=objlink
                , repo=repo_link(data["repository"])
                , note="\n".join("> {}".format(ln) for ln in attrs["note"].split("\n")) ## quote
                )
    elif event in ("Issue Hook", "Merge Request Hook"):
        msg = "{user} {verb} {what} [#{iid}: {title}]({url}) for {repo}".format(
                  user=user_link(data["user"], webbase)
                , verb=actionTransl[attrs["action"]]
                , what=" ".join(tok.lower() for tok in event.split(" ")[:-1])
                , iid=attrs["iid"], title=attrs["title"], url=attrs["url"]
                , repo=repo_link(data["repository"])
                )
    elif event == "Wiki Page Hook":
        msg = "{user} {verb} wiki page [{title}]({url}) for {project}".format(
                  user=user_link(data["user"], webbase)
                , verb=actionTransl[attrs["action"]]
                , title=attrs["title"], url=attrs["url"]
                , project="[{name}]({url})".format(name=data["project"]["name"], url=data["project"]["web_url"])
                )
    elif event == "Pipeline Hook":
        pass ## not supported yet
    elif event == "Build Hook":
        pass ## not supported yet

    if msg:
        hook_info = get_hook_info(data)
        if hook_info:
            url, channel = hook_info

            if ( hasattr(config, "GITLAB_IGNORE_ACTIONS") and
                 ( event in config.GITLAB_IGNORE_ACTIONS
                    or data.get("object_kind", None) in config.GITLAB_IGNORE_ACTIONS ) ):
                return "Notification action ignored (as per configuration)"

            post(msg, url, channel)

            return "Notification successfully posted to Mattermost"
        else:
            return "Notification ignored (repository is blacklisted)."
    else:
        return "Not implemented", 400

def post(text, url, channel):
    data = {}
    data['text'] = text
    data['channel'] = channel
    data['username'] = config.USERNAME
    data['icon_url'] = config.ICON_URL

    headers = {'Content-Type': 'application/json'}
    r = requests.post(url, headers=headers, data=json.dumps(data), verify=False)

    if r.status_code is not requests.codes.ok:
        print('Encountered error posting to Mattermost URL %s, status=%d, response_body=%s' % (url, r.status_code, r.json()))

def get_hook_info(data):
    keys_to_try = [
          ## for Github
            ("repository", "full_name")
          , ("organization", "login")
          , ("repository", "owner", "login")
          , ("repository", "owner", "name")
          ## for travis
          , ("repository", "url")
          , ("repository", "name")
          , ("repository", "owner_name")
          ]
    settings = config.MATTERMOST_WEBHOOK_URLS
    for keys in keys_to_try:
        dt = data
        for i,ky in enumerate(keys):
            if ky in dt:
                dt = dt[ky]
                if i == len(keys)-1 and dt in settings:
                    return settings[dt]
            else:
                break
    return config.MATTERMOST_WEBHOOK_URLS["default"]

if __name__ == "__main__":
    app.run(
        host=config.SERVER['address'] or "0.0.0.0",
        port=config.SERVER['port'] or 5000,
        debug=False
    )
