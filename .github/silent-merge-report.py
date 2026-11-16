#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

SILENT_CHECK_NAME = "Periodic silent merge check"
RESULTS_FILE = Path("silent-merge-results.json")
SUMMARIES = {
    "success": "CMake build and tests passed.",
    "failure": (
        "CMake build or tests failed when this PR was merged with current master. "
        "To find the failure, open the linked workflow run and expand the collapsed log "
        "group 'CI output for PR #{pr_number} (failed)'. Please rebase and ensure all checks pass."
    ),
    "timed_out": (
        "CMake build and tests did not finish within the time limit when this PR was merged with "
        "current master. To see how far they got, open the linked workflow run and expand the "
        "collapsed log group 'CI output for PR #{pr_number} (timed out)'."
    ),
}


def run(cmd, **kwargs):
    print("+ " + shlex.join(cmd), flush=True)
    kwargs.setdefault("check", True)
    kwargs.setdefault("text", True)
    try:
        return subprocess.run(cmd, **kwargs)
    except Exception as e:
        sys.exit(str(e))


def create_check_run(repo, head_sha, conclusion, summary, run_url):
    # GitHub only displays the most recent check run with a given name in the UI, so posting a new
    # check run each time naturally replaces the old result without any cleanup needed.
    # https://github.blog/changelog/2020-09-14-new-limits-affecting-the-checks-api/
    full_summary = f"{summary}\n\nWorkflow run: {run_url}"
    fields = {
        "name": SILENT_CHECK_NAME,
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": conclusion,
        "output[title]": SILENT_CHECK_NAME,
        "output[summary]": full_summary,
    }
    field_args = [arg for k, v in fields.items() for arg in ("-F", f"{k}={v}")]
    return run(["gh", "api", f"repos/{repo}/check-runs", "-X", "POST", *field_args], check=False).returncode == 0


def is_valid_result(result):
    return (
        isinstance(result, dict)
        and type(result.get("pr_number")) is int and result["pr_number"] > 0
        and isinstance(result.get("head_sha"), str) and re.fullmatch("[0-9a-f]{40}", result["head_sha"]) is not None
        and result.get("conclusion") in SUMMARIES
    )


def main():
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not repo:
        sys.exit("GITHUB_REPOSITORY is not set")

    server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    run_url = f"{server_url}/{repo}/actions/runs/{run_id}"

    if not RESULTS_FILE.exists():
        print("No results file found, nothing to report.")
        return

    results = json.loads(RESULTS_FILE.read_text())
    if not isinstance(results, list):
        sys.exit("Results file does not contain a list")
    print(f"Reporting {len(results)} result(s)...")

    failed = 0
    for result in results:
        if not is_valid_result(result):
            print(f"Skipping invalid result: {result!r:.200}")
            failed += 1
            continue
        pr_number = result["pr_number"]
        conclusion = result["conclusion"]
        print(f"Posting check run for PR #{pr_number} ({conclusion})")
        if not create_check_run(
            repo,
            head_sha=result["head_sha"],
            conclusion=conclusion,
            summary=SUMMARIES[conclusion].format(pr_number=pr_number),
            run_url=run_url,
        ):
            failed += 1

    if failed:
        sys.exit(f"{failed} result(s) were not posted")


if __name__ == "__main__":
    main()
