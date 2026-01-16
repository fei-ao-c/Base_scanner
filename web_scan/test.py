import os
import sys
import json

def load_xss_payload():
    """加载默认的xss_payload"""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    xss_payload_path = os.path.join(current_dir, "../payload/xss.json")
    with open(xss_payload_path, 'r',encoding='utf-8') as f:
        xss_payload = json.load(f)
    payload_list = xss_payload['xss_payloads']
    for payload in payload_list:
        print(f"xss_payload: {payload}\n")
    return payload_list
def main():
    xss_payload = load_xss_payload()
    print(xss_payload)
if __name__ == "__main__":
    main()