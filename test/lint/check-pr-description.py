#!/usr/bin/env python3
# Copyright (c) 2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import os
import re
import sys
import json
import codecs
from urllib.request import Request, urlopen
from urllib.error import HTTPError

def get_response(req_url):
    req = Request(req_url)
    return urlopen(req)

def retrieve_json(req_url):
    '''
    Retrieve json from github.
    Return None if an error happens.
    '''
    try:
        reader = codecs.getreader('utf-8')
        return json.load(reader(get_response(req_url)))
    except HTTPError as e:
        error_message = e.read()
        print('Warning: unable to retrieve pull information from github: %s' % e)
        print('Detailed error: %s' % error_message)
        return None
    except Exception as e:
        print('Warning: unable to retrieve pull information from github: %s' % e)
        return None

def retrieve_pr_info(pull):
    req_url = "https://api.github.com/repos/bitcoin/bitcoin/pulls/"+pull
    return retrieve_json(req_url)

def main():
    # Get pull request number from Travis environment
    if 'TRAVIS_PULL_REQUEST' in os.environ:
        pull = os.environ['TRAVIS_PULL_REQUEST']
    else:
        assert False, "No pull request number found, PR description could not be checked"

    # Receive pull information from github
    info = retrieve_pr_info(pull)
    if info is None:
        sys.exit(1)

    body = info['body'].strip()

    # Good enough username regex
    gh_username = r"/\B@([a-z0-9](?:-?[a-z0-9]){0,38})/gi"
    assert not bool(re.search(gh_username, body)), "Please remove any GitHub @-prefixed usernames from your PR description"

    html_comment_start = r"/<!--/"
    assert not bool(re.search(html_comment_start, body)), "Please remove the pull request template from your PR description"
    html_comment_end = r"/-->/"
    assert not bool(re.search(html_comment_end, body)), "Please remove the pull request template from your PR description"


if __name__ == '__main__':
    main()
