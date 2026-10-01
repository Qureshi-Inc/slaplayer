#!/bin/sh
# nginx serves the player; sso.py answers /auth/ (CRCMZ sign-in). Keep it alive.
(while true; do python3 /app/sso.py; echo "sso exited, restarting" >&2; sleep 2; done) &
exec nginx -g 'daemon off;'
