# File-logger

File-logger is a library which implements log file rotation: it maintains max X
log files of max size Y, so that you always have latest logs from the device
persisted on the filesystem. By default there are max 10 files, prefixed with
`log_`, each of max size 4000 bytes.

See [mos.yml](mos.yml) for the possible options. At least you'd have to
enable this lib in your app's `mos.yml`, like this:

Note that for the message to get to file logger it needs to be allowed by `debug.level` and `debug.event_level`.
File logger then examines `file_logger.level` and `file_logger.include` to make final determination.

`file_logger.include` is a list of substrings to match, so a value of `mg_rpc.c,Tick,Tock` will match lines containing any of "Tick, "Tock" or "mg_rpc.c".

```yaml
libs:
  - origin: https://github.com/mongoose-os-libs/file-logger

config_schema:
  - ["file_logger.enable", true]
```
