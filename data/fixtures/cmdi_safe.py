import subprocess

def ping_host(host):
    result = subprocess.run(["ping", "-c", "1", host], shell=False, capture_output=True)
    return result.stdout
