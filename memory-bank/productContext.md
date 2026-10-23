# Product Context — FTW

## Problem domain
Operators with written authorization need a fast, memory-safe way to check
which TCP ports are open across their own IP ranges.

## UX goals
- Single binary `ftw` with a small, obvious CLI surface.
- YAML target files accept either a `targets:` key or a top-level sequence.
- Results stream to the output file as they arrive; no buffering of the whole scan.
- Output lines are plain text: `<ip>:<port> <status>`
  where status is `open`, `closed`, or `filtered`.

## User flows
1. Operator writes a YAML file listing owned CIDRs / IPs.
2. Runs `ftw --input targets.yml --ports 80,443 --output results.txt`.
3. Reads streamed results; open ports get follow-up authorized review.

## Safety note
Authorized ranges only. The tool does not enforce ownership; the operator is
responsible for staying within ranges they own or have written permission to test.
