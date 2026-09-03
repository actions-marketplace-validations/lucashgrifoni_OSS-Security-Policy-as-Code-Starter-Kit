# Hashed dependency locks

Every file installed from here is pinned by version and hash, and each `.txt` is generated
from the `.in` beside it. The workflows install them with `--require-hashes`, so a byte that
does not match a recorded hash fails the job rather than running.

## Dependabot cannot edit these files correctly

Dependabot watches this directory (`.github/dependabot.yml`, the second `pip` entry), which
is what surfaces an available update at all — before that entry existed, five of these locks
went nine days without anyone noticing a scanner release. **Its proposed diff is a signal,
not a patch.** Measured on 2026-09-02, its update of `build 1.5.0 -> 1.6.0` also:

- deleted `typing-extensions==4.16.0` and its hashes, leaving a transitive requirement
  unpinned, which fails `--require-hashes` outright;
- rewrote `cyclonedx-python-lib==11.11.0` as `cyclonedx-python-lib[validation]==11.11.0`
  and `jsonschema==4.26.0` as `jsonschema[format-nongpl]==4.26.0`;
- reverted the input paths in the comments back to bare filenames.

The pull request went red in `Package` with `In --require-hashes mode, all requirements must
have their versions pinned with ==`.

## How to take a Dependabot bump

Read the version it proposes, then produce the lock yourself and close its pull request:

```bash
uv pip compile .github/requirements/<name>.in \
  --generate-hashes --python-version 3.12 --python-platform linux \
  --upgrade-package <package> \
  --output-file .github/requirements/<name>.txt
```

`--python-platform linux` is required: the runners are Linux, and resolving on Windows pulls
platform-conditional packages such as `pywin32` that the Linux graph does not contain.
Without `--upgrade-package`, uv keeps every pin already in the output file and the command
appears to do nothing.

Verify before committing. On Linux, `pip install --require-hashes --dry-run -r <file>` is the
same check CI runs. On Windows that dry-run fails for `semgrep.txt` on `pywin32` even for a
lock that is correct — the committed file fails it identically, so use that as the control
rather than reading the error as a defect.
