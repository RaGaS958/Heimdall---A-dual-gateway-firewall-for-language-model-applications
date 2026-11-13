from fastapi.testclient import TestClient
from heimdall_app import app
import os
import json

client = TestClient(app)

def run():
    print("Testing /trajectory/test-session")
    os.environ["ADMIN_KEY"] = "test-key"
    resp = client.get("/trajectory/test-session", headers={"x-admin-key": "test-key"})
    print("Status:", resp.status_code)
    print("Response:", json.dumps(resp.json(), indent=2))

if __name__ == "__main__":
    run()
