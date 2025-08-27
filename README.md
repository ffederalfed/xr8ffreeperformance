# XR8 Performance Batch

This repo contains a refactored Windows batch script for tuning system performance.

* Unified logging via the `LOG_FILE` variable.
* Optional restore point handled through a dedicated `:HandleRestorePoint` function.
* Script version stored in `SCRIPT_VERSION` for easy reference.

> **Note**: This script targets Windows and cannot be executed in non-Windows environments.
