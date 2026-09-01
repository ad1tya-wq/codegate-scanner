import subprocess

def ping_host(host):
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout
