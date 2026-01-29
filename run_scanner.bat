@echo off
echo Setting license environment variables...
set CYBERDUDEBIVASH_LICENSE_KEY=CYBER-2026-ABCD-EFGH-IJKL
set CYBERDUDEBIVASH_EXPIRY_DATE=2027-01-29
set CYBERDUDEBIVASH_HARDWARE_HASH=612A78526A1672F5
echo License settings applied.
python cyberdudebivash-op-model-sentry.py %*
pause