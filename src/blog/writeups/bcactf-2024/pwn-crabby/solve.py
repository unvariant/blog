import requests

headers = {
    "Authorization": "c29tZV9zdXBlcl9zZWNyZXRfa2V5X3RleHRfaGVyZQ=="
}
res = requests.post("http://challs.bcactf.com:30439/flag", headers=headers)
print(res)
print(res.content)