#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

import argparse
import json
import os
import secrets
import shlex
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

MAX_RUNTIME = timedelta(hours=5, minutes=30)
MIN_CHECK_AGE = timedelta(days=1)
# A full rebuild plus tests takes about 30 minutes.
PR_TIMEOUT = timedelta(minutes=90)
SILENT_CHECK_NAME = "Periodic silent merge check"
RESULTS_FILE = Path("silent-merge-results.json")
IMAGE = "silent-merge-check"
CCACHE_HOST_DIR = Path.home() / ".cache" / "ccache"
CI_SCRIPT = Path(".github/ci-test-each-commit-exec.py")
# The CI script runs git log, so give it a repository.
CONTAINER_SCRIPT = """set -e
mkdir /tmp/work
cd /tmp/work
tar -x
git -c init.defaultBranch=master init -q
git add -A
git -c user.name=ci -c user.email=ci@localhost commit -q -m 'silent merge check'
exec python3 /ci/run.py
"""


def log(msg):
    print(msg, flush=True)


def starts_with_timestamp(line):
    first = line.split(maxsplit=1)[0] if line.strip() else ""
    try:
        datetime.fromisoformat(first.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def run_capture_timestamped(cmd, **kwargs):
    """Run cmd, capturing its combined output with a timestamp on every line.

    Lines that already start with a timestamp (e.g. functional test framework or
    bitcoind output) are left untouched to avoid double-stamping.
    """
    log("+ " + shlex.join(cmd))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1, start_new_session=True, **kwargs)
    lines = []
    for line in proc.stdout:
        line = line.rstrip("\n")
        if not starts_with_timestamp(line):
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            line = f"{timestamp} {line}"
        lines.append(line)
    proc.wait()
    return proc.returncode, "\n".join(lines)


def container_cmd(name, ccache_writable):
    """Return the docker run command for the container that pull request code runs in.

    Pull request code must never run on the host: there it could change the results file, the
    ccache or the scripts that later steps run. The container has no network and no credentials,
    and the ccache is only writable while building master.
    """
    cmd = [
        "docker", "run", "--rm", "--interactive", f"--name=smc-{name}",
        "--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges",
        f"--user={os.getuid()}:{os.getgid()}", "--env=HOME=/tmp",
        f"--mount=type=bind,src={CI_SCRIPT.resolve()},dst=/ci/run.py,readonly",
        "--env=CCACHE_DIR=/ccache",
    ]
    if ccache_writable:
        cmd += [f"--mount=type=bind,src={CCACHE_HOST_DIR},dst=/ccache", "--env=CCACHE_MAXSIZE=500M"]
    else:
        cmd += [
            f"--mount=type=bind,src={CCACHE_HOST_DIR},dst=/ccache,readonly",
            "--env=CCACHE_READONLY=1", "--env=CCACHE_NOSTATS=1", "--env=CCACHE_TEMPDIR=/tmp/ccache-tmp",
        ]
    return cmd


def run_in_container(tree, name, ccache_writable, timeout):
    """Build and test a git tree in a fresh container, killing it after timeout seconds.

    Returns (returncode, output, timed_out).
    """
    timed_out = threading.Event()

    def kill():
        timed_out.set()
        subprocess.run(["docker", "kill", f"smc-{name}"], check=False)

    timer = threading.Timer(timeout, kill)
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / "tree.tar"
        run(["git", "archive", "--format=tar", f"--output={archive}", tree])
        with archive.open("rb") as stdin:
            timer.start()
            try:
                returncode, output = run_capture_timestamped(
                    [*container_cmd(name, ccache_writable), IMAGE, "sh", "-c", CONTAINER_SCRIPT], stdin=stdin)
            finally:
                timer.cancel()
    return returncode, output, timed_out.is_set()


def print_output_group(title, output):
    """Print container output in a collapsed group, ignoring any workflow commands in it."""
    token = secrets.token_hex(16)
    print(f"::group::{title}")
    print(f"::stop-commands::{token}")
    print(output)
    print(f"::{token}::")
    print("::endgroup::", flush=True)


def fmt_duration(td):
    total = int(td.total_seconds())
    d, rem = divmod(total, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    if d:
        return f"{d}d {h}h {m}m" if m else f"{d}d {h}h"
    return f"{h}h {m}m" if m else f"{h}h"


def run(cmd, **kwargs):
    log("+ " + shlex.join(cmd))
    kwargs.setdefault("check", True)
    kwargs.setdefault("text", True)
    try:
        return subprocess.run(cmd, **kwargs)
    except Exception as e:
        sys.exit(str(e))


def gh_api_paginated(url, key=None):
    result = run(["gh", "api", "--paginate", url], stdout=subprocess.PIPE)
    items = []
    for page in result.stdout.strip().splitlines():
        data = json.loads(page)
        items.extend(data.get(key) if key else data)
    return items


def get_open_prs(repo):
    # The list endpoint has no draft query parameter; unknown params are ignored.
    prs = gh_api_paginated(f"repos/{repo}/pulls?state=open&per_page=100")
    return [pr for pr in prs if not pr.get("draft")]


def get_check_runs(repo, head_sha):
    return gh_api_paginated(f"repos/{repo}/commits/{head_sha}/check-runs", key="check_runs")


def has_failing_checks(check_runs):
    return any(
        check.get("conclusion") == "failure" and check.get("name") != SILENT_CHECK_NAME
        for check in check_runs
    )


def latest_passing_check_time(check_runs):
    times = []
    for check in check_runs:
        if check.get("name") == SILENT_CHECK_NAME:
            continue
        if check.get("conclusion") == "success":
            timestamp = check.get("completed_at")
            if timestamp:
                times.append(datetime.fromisoformat(timestamp))
    return max(times) if times else None


def skip_reason(check_runs):
    if has_failing_checks(check_runs):
        return "already has failing check runs"
    latest_pass = latest_passing_check_time(check_runs)
    if latest_pass is None:
        return "has no passing check runs"
    age = datetime.now(tz=latest_pass.tzinfo) - latest_pass
    if age < MIN_CHECK_AGE:
        return f"latest passing check is only {fmt_duration(age)} old (minimum {fmt_duration(MIN_CHECK_AGE)})"
    return None


def append_result(pr_number, head_sha, conclusion):
    results = json.loads(RESULTS_FILE.read_text()) if RESULTS_FILE.exists() else []
    results.append({"pr_number": pr_number, "head_sha": head_sha, "conclusion": conclusion})
    RESULTS_FILE.write_text(json.dumps(results, indent=2))


def get_pr_mergeable(repo, pr_number, retries=5, delay=5):
    """Fetch a PR and poll until GitHub has computed its mergeability.

    Returns the pull request object. If mergeability is still unknown after
    retries, mergeable is set to True.
    """
    # https://docs.github.com/en/rest/guides/using-the-rest-api-to-interact-with-your-git-database?apiVersion=2026-03-10#checking-mergeability-of-pull-requests
    pr_data = {}
    for attempt in range(retries):
        result = run(["gh", "api", f"repos/{repo}/pulls/{pr_number}"], stdout=subprocess.PIPE)
        pr_data = json.loads(result.stdout)
        if pr_data.get("mergeable") is not None:
            return pr_data
        if attempt < retries - 1:
            log(f"PR #{pr_number} mergeability not yet computed, retrying in {delay}s...")
            time.sleep(delay)
    log(f"PR #{pr_number} mergeability still unknown after {retries} attempts, assuming mergeable.")
    pr_data["mergeable"] = True
    return pr_data


def latest_check_time(check_runs):
    times = []
    for check in check_runs:
        if check.get("name") != SILENT_CHECK_NAME:
            continue
        timestamp = check.get("completed_at") or check.get("started_at")
        if timestamp:
            times.append(datetime.fromisoformat(timestamp))
    return max(times) if times else None


def run_baseline():
    log("Building and testing master to fill the ccache")
    returncode, output, timed_out = run_in_container(
        "HEAD^{tree}", "master", ccache_writable=True, timeout=PR_TIMEOUT.total_seconds())
    if returncode != 0 or timed_out:
        print_output_group("CI output for master (failed)", output)
        sys.exit("master failed to build or pass tests, so PR results would be meaningless.")
    run([*container_cmd("master-stats", ccache_writable=True), IMAGE, "ccache", "--show-stats"], check=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", action="store_true",
                        help="Build and test master with a writable ccache instead of testing PRs")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    os.chdir(repo_root)
    CCACHE_HOST_DIR.mkdir(parents=True, exist_ok=True)

    if args.baseline:
        run_baseline()
        return

    repo = os.environ.get("GITHUB_REPOSITORY")
    if not repo:
        sys.exit("GITHUB_REPOSITORY is not set")

    # Count from the start of the job (set by the workflow), so the baseline build is included.
    deadline = float(os.environ.get("SMC_JOB_START", time.time())) + MAX_RUNTIME.total_seconds()

    log("Fetching open PRs...")
    open_prs = get_open_prs(repo)
    log(f"Found {len(open_prs)} open PRs")

    prs = []
    for pr_json in open_prs:
        pr_number = pr_json.get("number")
        head_sha = pr_json.get("head", {}).get("sha")
        # head_sha is only used to order the queue. The decision to test a PR is made later against the latest fetched head.
        check_runs = get_check_runs(repo, head_sha) if head_sha else []
        prs.append(
            {
                "number": pr_number,
                "created_at": pr_json.get("created_at"),
                "latest_silent_check": latest_check_time(check_runs),
            }
        )

    candidate_prs = sorted(
        [pr for pr in prs if pr["latest_silent_check"] is None],
        key=lambda pr: pr["created_at"] or "")

    candidate_prs.extend(sorted(
            [pr for pr in prs if pr["latest_silent_check"] is not None],
            key=lambda pr: pr["latest_silent_check"]))

    if candidate_prs:
        log(f"{len(candidate_prs)} candidate PR(s) found")
        log("Processing PRs that have never been checked first and then by oldest check")

    for pr in candidate_prs:
        if time.time() >= deadline:
            log(f"Reached maximum runtime ({fmt_duration(MAX_RUNTIME)}); stopping before next PR.")
            break
        log(f"Checking PR #{pr['number']}")

        if pr["latest_silent_check"] is not None:
            time_since = datetime.now(tz=pr["latest_silent_check"].tzinfo) - pr["latest_silent_check"]
            log(f"PR #{pr['number']} was last checked {fmt_duration(time_since)} ago")
            print(f"::notice title=Recheck interval PR #{pr['number']}::Last checked {fmt_duration(time_since)} ago")

        pr_data = get_pr_mergeable(repo, pr["number"])
        if pr_data.get("draft"):
            log(f"PR #{pr['number']} is a draft, skipping.")
            continue
        if not pr_data.get("mergeable"):
            log(f"PR #{pr['number']} has merge conflicts, skipping.")
            continue

        # Merge the PR head against current master locally. GitHub's pull/{n}/merge ref can be
        # stale, so we cannot rely on it to test against the latest master.
        head_ref = f"pr-{pr['number']}-head"
        run(["git", "fetch", "origin", f"pull/{pr['number']}/head:{head_ref}"])
        tested_sha = run(["git", "rev-parse", head_ref], stdout=subprocess.PIPE).stdout.strip()
        reason = skip_reason(get_check_runs(repo, tested_sha))
        if reason:
            log(f"PR #{pr['number']} {reason}, skipping.")
            continue

        # Merge without touching the working tree, which stays at the trusted master checkout.
        run(["git", "fetch", "origin", "refs/heads/master:refs/remotes/origin/master"])
        merge_result = run(["git", "merge-tree", "--write-tree", "origin/master", head_ref],
                           stdout=subprocess.PIPE, check=False)
        if merge_result.returncode != 0:
            log(f"PR #{pr['number']} has merge conflicts against current master, skipping.")
            continue
        tree = merge_result.stdout.splitlines()[0]

        timeout = min(PR_TIMEOUT.total_seconds(), deadline - time.time())
        ci_returncode, ci_output, timed_out = run_in_container(
            tree, f"pr-{pr['number']}", ccache_writable=False, timeout=timeout)
        if timed_out and timeout < PR_TIMEOUT.total_seconds():
            log(f"Reached maximum runtime ({fmt_duration(MAX_RUNTIME)}) while testing PR #{pr['number']}; "
                "stopping without a result for it.")
            break
        if timed_out:
            log(f"PR #{pr['number']} did not finish within {fmt_duration(PR_TIMEOUT)}. Output follows (expand group):")
            print_output_group(f"CI output for PR #{pr['number']} (timed out)", ci_output)
            conclusion = "timed_out"
        elif ci_returncode != 0:
            log(f"PR #{pr['number']} CI script failed. Output follows (expand group):")
            print_output_group(f"CI output for PR #{pr['number']} (failed)", ci_output)
            conclusion = "failure"
        else:
            log(f"PR #{pr['number']} CI completed successfully.")
            conclusion = "success"

        append_result(
            pr_number=pr["number"],
            head_sha=tested_sha,
            conclusion=conclusion,
        )


if __name__ == "__main__":
    main()
