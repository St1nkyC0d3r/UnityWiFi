import requests
import json
import os
from dotenv import load_dotenv

# Load environment variables (you ain't hacking me today buddy)
load_dotenv()
base_url = os.environ.get("BASE_URL")

url = f"{base_url}/user/register"
payload = {
    "username": "himnij",
    "email": "maxim@maximgil.com",
    "password": "Br*gh!0n07"
}
headers = {"Content-Type": "application/json"}

try:
    response = requests.post(url, headers=headers)
    response.raise_for_status()

    print("Response status code:", response.status_code)
    print("Response JSON:", response.json())

except requests.exceptions.RequestException as e:
    print(f"Error: {e}")
except json.JSONDecodeError:
    print("Invalid JSON response")