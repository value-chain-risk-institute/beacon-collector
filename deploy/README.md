# Deploying scheduled mode

Three templates, one per scheduler. Each runs `scheduled.py run` on a timer as an
unprivileged user, with the config and state directory the org owns. Pick one.

- `beacon-scheduled.plist` (macOS launchd): copy to `~/Library/LaunchAgents/`,
  edit the paths, `launchctl load ~/Library/LaunchAgents/works.vcri.beacon-scheduled.plist`.
- `beacon-scheduled.service` + `beacon-scheduled.timer` (systemd): copy to
  `/etc/systemd/system/`, edit `User=` and paths, `systemctl enable --now beacon-scheduled.timer`.
- `crontab.example`: one line for cron.

All three default to every 6 hours. Shorten it for hosts that drift fast; a
collection that changed nothing still seals (a heartbeat is a fact too).
Anchoring runs at write time inside each job and the OTS upgrade pass runs on the
next timer tick, so a Bitcoin-confirmed proof appears within a few hours.

Check: `scheduled.py status`, `scheduled.py verify` (every seal, every chain
link, every anchor, offline).
