# curl quick sheet

Use `curl` only against a remote explicitly listed in `contest.md`. Capture a baseline with `curl -i --max-time 10 "$REMOTE"`, then save request method, headers, status, and response body digest.

Keep probes narrow and rate-conscious. Use `--path-as-is` or custom headers only when a challenge hypothesis requires it, and preserve sanitized request/response pairs for replay.
