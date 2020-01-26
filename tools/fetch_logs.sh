#!/bin/bash

# Set MOS_PORT environment variable to change port from default.

# Fetching logs may produce logs, especially at higher logging levels, so turn file logging off while fetching.
mos call Config.Set '{"config": {"file_logger": {"enable": false } }, "reboot": false, "save": false}' > /dev/null
# FLush everything, especially important for LFS.
mos call FileLog.Flush > /dev/null
while true; do
  f=$(mos call FileLog.Status | jq -r .oldest)
  if [ -z "$f" ]; then
    break
  fi
  echo "Fetching $f..."
  mos get --chunk-size=2048 $f > $(basename $f)
  mos rm "$f"
done
# Re-enable logs.
mos call Config.Set '{"config": {"file_logger": {"enable": true } }, "reboot": false, "save": false}' > /dev/null
