# wazuh-reportd oracle

The C `wazuh-reportd` (reportd/report.c with shared/report_op.c and the maild
oracle's logging stubs, built by `build.sh` in WSL) against
`src/bin/wazuh-reportd.rs`, both fed the same alerts.log on stdin.

`run.sh <rust wazuh-reportd> <alerts.log>` (as root: both chroot into their
home) compares, for 12 option sets, the report (stderr), stdout, the exit code
and the log lines: no filter, `-f level|group|rule|location`, related entries
(`-r user srcip`, `-r group location`, `-r rule level`), `-s -n <name>`
(alert dump), an invalid filter and `-t`.

2026-10-22, on the dev manager's alerts.log (1,038 alerts): 12/12 identical.
