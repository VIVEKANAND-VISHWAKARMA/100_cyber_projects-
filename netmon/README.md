# netmon — personal network activity logger (Linux)

Logs, for every app on your laptop, when it connects to the internet, which
domain/IP it talks to, and for how long — across your whole system, not just
the browser.

**What it captures:** process name, remote hostname/IP, port, start/end time, duration.
**What it does NOT capture:** page content, keystrokes, screenshots, or anything
inside the connections themselves — just the metadata of who's talking to whom.
Everything is stored locally in a SQLite file at `~/.local/share/netmon/netmon.db`.
Nothing is sent anywhere.

## Setup

```bash
pip install psutil --break-system-packages
```

## Run it

Foreground (good for testing):
```bash
python3 netmon.py
```
Press Ctrl+C to stop — it flushes cleanly on exit.

If you get a permission error listing connections, run with sudo (needed to see
every process's sockets on some systems):
```bash
sudo python3 netmon.py
```

### Run automatically in the background (recommended)

Copy this folder to your home directory, then install the systemd service:

```bash
cp -r netmon ~/netmon
mkdir -p ~/.config/systemd/user
cp ~/netmon/netmon.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now netmon.service
```

Check it's running:
```bash
systemctl --user status netmon.service
```

If you needed `sudo` above to avoid permission errors, use a system-wide service
under `/etc/systemd/system/` instead and ask me — the user-level one above only
works if your regular user has enough permission to list connections.

## View the log

```bash
python3 netmon-view.py                     # today, full table + summary
python3 netmon-view.py --summary            # just top apps / top domains
python3 netmon-view.py --date 2026-07-23    # a specific day
python3 netmon-view.py --app firefox        # filter by app
python3 netmon-view.py --domain google      # filter by domain
python3 netmon-view.py --export csv today.csv
python3 netmon-view.py --export json today.json
```

## Notes

- Short-lived connections (<1s) are skipped as noise.
- Hostname lookups use reverse DNS and are cached; some IPs won't resolve to a
  friendly name and will show as raw IPs instead.
- The database just grows over time — delete `~/.local/share/netmon/netmon.db`
  any time you want to reset it, or ask me to add automatic old-data cleanup.
- To stop the background service: `systemctl --user stop netmon.service`
- To fully remove it: `systemctl --user disable --now netmon.service`
