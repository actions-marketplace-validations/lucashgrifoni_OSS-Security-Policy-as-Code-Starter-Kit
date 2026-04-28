import os
import subprocess
import sys


def test_cli_stdout_stderr_redirected_no_unicode_crash(tmp_path):
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "cp1252"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "oss_policy_kit",
            "evaluate",
            "--target",
            "examples/hardened-repo",
            "--profile",
            "github-level-1",
            "--output-dir",
            str(tmp_path),
            "--summary-only",
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    assert result.returncode != 3, "CLI crashed with Unexpected internal error (likely UnicodeEncodeError)."
