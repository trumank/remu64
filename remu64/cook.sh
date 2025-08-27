#!/bin/bash
while :; do cat prompt.md | IS_SANDBOX=1 claude -p --dangerously-skip-permissions; done
