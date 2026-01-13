import time
import requests
import subprocess
import sys
import os

BASE_URL = "http://localhost:8080"
API_PREFIX = BASE_URL

def wait_for_server():
    print("Waiting for server to start...")
    for _ in range(300):
        try:
            resp = requests.get(f"{API_PREFIX}/health")
            if resp.status_code == 200:
                print("Server is up!")
                return True
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(1)
    print("Server failed to start.")
    return False

def test_init():
    print("Initializing vault...")
    payload = {
        "shares": 3,
        "threshold": 2
    }
    try:
        resp = requests.post(f"{API_PREFIX}/sys/init", json=payload, timeout=10)
    except Exception as e:
        print(f"Init request failed: {e}")
        return None, None

    if resp.status_code != 200:
        print(f"Init failed: {resp.status_code} {resp.text}")
        return None, None

    try:
        json_resp = resp.json()
        data = json_resp['data']
        print(f"Init success. Received {len(data['keys'])} keys.")
        return data['keys'], data['root_token']
    except Exception as e:
        print(f"Failed to parse init response: {resp.text} Error: {e}")
        return None, None

def test_unseal(keys):
    print(f"Unsealing vault with threshold 2...")

    # Key 1
    print("Sending Share 1...")
    resp = requests.post(f"{API_PREFIX}/sys/unseal", json={"key": keys[0]}, timeout=10)
    if resp.status_code != 200:
        print(f"Unseal 1 failed: {resp.status_code} {resp.text}")
        return False
    print(f"Share 1 result: {resp.json()}")

    # Key 2
    print("Sending Share 2...")
    # Increased timeout due to slow key generation in test environment
    resp = requests.post(f"{API_PREFIX}/sys/unseal", json={"key": keys[1]}, timeout=60)
    if resp.status_code != 200:
        print(f"Unseal 2 failed: {resp.status_code} {resp.text}")
        return False

    data = resp.json()['data']
    print(f"Share 2 result: {data}")

    if data['sealed']:
        print("Vault is still sealed after threshold reached!")
        return False

    print("Vault Unsealed!")
    return True

def test_secrets(token):
    headers = {"Authorization": f"Bearer {token}"}

    print("Storing secret...")
    payload = {"data": {"foo": "bar"}}

    try:
        resp = requests.post(f"{API_PREFIX}/secrets/data/test-secret", headers=headers, json=payload, timeout=5)
        if resp.status_code != 200:
            print(f"Store failed: {resp.status_code} {resp.text}")
            return False

        print("Retrieving secret...")
        resp = requests.get(f"{API_PREFIX}/secrets/data/test-secret", headers=headers, timeout=5)
        if resp.status_code != 200:
            print(f"Retrieve failed: {resp.status_code} {resp.text}")
            return False

        data = resp.json()
        print("Secret operations successful!")
        return True
    except Exception as e:
        print(f"Secret test exception: {e}")
        return False

def main():
    print("Starting server...")
    server_process = subprocess.Popen(
        ["cargo", "run", "-p", "secreton-api", "--bin", "api_server"],
        stdout=sys.stdout,
        stderr=sys.stderr
    )

    try:
        if not wait_for_server():
            return 1

        keys, root_token = test_init()
        if not keys:
            return 1

        if not test_unseal(keys):
            return 1

        if not test_secrets(root_token):
            return 1

        print("E2E Test Passed!")
        return 0

    finally:
        server_process.terminate()
        server_process.wait()

if __name__ == "__main__":
    sys.exit(main())
