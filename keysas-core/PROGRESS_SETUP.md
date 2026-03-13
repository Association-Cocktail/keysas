# Progress Tracking Setup

## Important: Directory Setup

The progress tracking feature requires `/var/lock/keysas/` directory to be created BEFORE starting the services.

The daemons are sandboxed with Landlock and cannot create this directory themselves.

## Setup Instructions

```bash
# Create the progress directory with correct permissions
sudo mkdir -p /var/lock/keysas
sudo chown -R keysas-in:keysas-in /var/lock/keysas/
sudo chmod 755 /var/lock/keysas/

# Verify permissions
ls -la /var/lock/keysas/
# Should show: drwxr-xr-x keysas-in keysas-in

# NOW start the services
sudo systemctl start keysas-in.service keysas-transit.service keysas-out.service keysas-backend.service
```

## Troubleshooting

If progress files are not created:

1. Check directory exists: `ls -la /var/lock/keysas/`
2. Check permissions: `stat /var/lock/keysas/`
3. Check daemon logs: `sudo journalctl -u keysas-transit.service -f`
4. Verify Landlock status in logs

## Progress Files Location

- `/var/lock/keysas/keysas-in-progress.json` - Input daemon progress
- `/var/lock/keysas/keysas-transit-progress.json` - Analysis daemon progress

These files are updated in real-time during file processing.
