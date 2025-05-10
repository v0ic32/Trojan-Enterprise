Nim Web Monitor

This tool scans browser history files for accesses to ChatGPT, Claude, and other AI services. It captures the local/external IP and current user, then sends a report to a remote server.

To compile:
nim c -d:release --cpu:amd64 --os:windows monitor.nim

Edit `historyFilePath` and `SERVER_IP:PORT` in the script.