#!/bin/sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
classifier=${CLASSIFIER_CONTAINER:-sanct-classifier-classifier-1}
clamav=${CLAMAV_CONTAINER:-sanct-classifier-clamav-1}
marker="zkmark$(openssl rand -hex 12)"
b64=$(python3 -I "$here/send.py" "$marker")
python3 -I -c 'import time; time.sleep(2)'
status=0
for target in "$classifier:sanct-classif" "$clamav:clamd"; do
  container=${target%%:*}
  comm=${target#*:}
  result=$(docker run --rm --privileged --pid="container:$container" -v "$here:/scan:ro" python:3.14.10-slim-trixie sh -c "
    pid=\$(for p in /proc/[0-9]*; do case \"\$(cat \$p/comm 2>/dev/null)\" in $comm*) basename \$p; break;; esac; done)
    python3 -I /scan/scan.py \$pid '$marker' '$b64'")
  echo "$container:"
  echo "$result"
  if echo "$result" | grep -qv "hits=0"; then
    status=1
  fi
done
if [ "$status" -eq 0 ]; then
  echo "PASS: no plaintext left in memory"
else
  echo "FAIL: plaintext found in memory"
fi
exit "$status"
