#!/bin/sh
# GitHub Action: inputs in INPUT_* env vars. Otherwise pass args to fors33-verifier.
set -e

if [ -n "$INPUT_URL" ] || [ -n "$INPUT_FILE" ]; then
    set --
    [ -n "$INPUT_URL" ]          && set -- "$@" --url "$INPUT_URL"
    [ -n "$INPUT_FILE" ]         && set -- "$@" --file "$INPUT_FILE"
    [ -n "$INPUT_EXPECTED_HASH" ] && set -- "$@" --expected-hash "$INPUT_EXPECTED_HASH"
    [ -n "$INPUT_RECORD" ]       && set -- "$@" --record "$INPUT_RECORD"
    [ -n "$INPUT_START" ]        && set -- "$@" --start "$INPUT_START"
    [ -n "$INPUT_END" ]          && set -- "$@" --end "$INPUT_END"
    exec fors33-verifier "$@"
fi

case "$1" in
  serve|server) exec python /app/server_url_only.py ;;
  *)            exec fors33-verifier "$@" ;;
esac
