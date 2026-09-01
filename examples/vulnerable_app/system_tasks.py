import os
import subprocess


def ping_host(host):
    """Vulnerable: shell=True lets shell metacharacters in `host` run
    arbitrary commands (CWE-78) -- e.g. host="1; rm -rf ~"."""
    return subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)


def ping_host_safely(host):
    """Safe: the fix for ping_host above -- an argv list, no shell involved."""
    return subprocess.run(["ping", "-c", "1", host], shell=False, capture_output=True)


def list_directory(path):
    """Safe: no subprocess or shell at all."""
    return os.listdir(path)
