# Progress Tracking

`keysas-in` and `keysas-transit` write live progress to JSON files under `/run/`:

| Daemon           | Progress file                         |
|------------------|---------------------------------------|
| keysas-in        | `/run/keysas-in/progress.json`        |
| keysas-transit   | `/run/keysas-transit/progress.json`   |

These directories are created by `make install` and are managed by the respective systemd services. They are on a tmpfs (`/run`) and do not persist across reboots.

## Troubleshooting

If progress is not displayed in the frontend:

1. Check that the directories exist and have correct ownership:
   ```bash
   ls -la /run/keysas-in /run/keysas-transit
   ```
2. Check daemon logs:
   ```bash
   sudo journalctl -u keysas-in.service -f
   sudo journalctl -u keysas-transit.service -f
   ```
3. Check Landlock status in logs — the sandbox must allow write access to `/run/keysas-{in,transit}`.
4. Verify the backend is reading the progress files:
   ```bash
   sudo journalctl -u keysas-backend.service -f
   ```
