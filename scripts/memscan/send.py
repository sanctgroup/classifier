import base64
import json
import os
import sys
import urllib.request

marker = sys.argv[1]
url = os.environ.get("CLASSIFIER_URL", "http://127.0.0.1:8080/classify")
attachment = f"attachment-secret-{marker}".encode()
payload = {
    "subject": f"Quarterly numbers {marker}",
    "body": f"Hi team, the confidential figure is {marker}. Please do not forward.",
    "spf": "pass",
    "dkim": "pass",
    "dmarc": "pass",
    "attachments": [{"filename": "notes.txt", "content_base64": base64.b64encode(attachment).decode()}],
}
request = urllib.request.Request(
    url,
    data=json.dumps(payload).encode(),
    headers={"Content-Type": "application/json", "X-API-Secret": os.environ["CLASSIFIER_API_SECRET"]},
)
with urllib.request.urlopen(request, timeout=30) as response:
    print(f"response: {json.load(response)['label']}", file=sys.stderr)
print(base64.b64encode(attachment).decode())
