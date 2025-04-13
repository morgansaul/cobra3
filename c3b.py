#!/usr/bin/env python3
# MEXC Bonus Exploit Framework v13.2 (Python 3.7+ Compatible)

import hmac
import hashlib
import requests
import time
import uuid
import json
from urllib.parse import urlencode

class MEXCBonusHunter:
    def __init__(self, api_key, api_secret):
        self.api_key = api_key
        self.api_secret = api_secret
        self.base_urls = [
            "https://www.mexc.com",
            "https://mexc.com",
            "https://api.mexc.com"
        ]
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json"
        })
        self.session.verify = False
        self.base_url = None  # Will be set during initialization
        requests.packages.urllib3.disable_warnings()

    def _get_working_base_url(self):
        """Find active base URL compatible with Python 3.7"""
        for url in self.base_urls:
            try:
                if self.session.get(f"{url}/health", timeout=5).status_code == 200:
                    return url
            except:
                continue
        return None

    def _generate_web_signature(self, params):
        """Signature generation compatible with older Python"""
        params["timestamp"] = int(time.time() * 1000)
        param_str = "&".join([f"{k}={v}" for k, v in sorted(params.items())])
        return hmac.new(
            self.api_secret.encode("utf-8"),
            param_str.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

    def _get_bonus_campaigns(self):
        """Get campaigns without walrus operator"""
        params = {"type": "direct_claim", "signature": ""}
        params["signature"] = self._generate_web_signature(params)
        
        try:
            response = self.session.post(
                f"{self.base_url}/api/bonus/list",
                json=params,
                timeout=10
            )
            return response.json().get("data", [])
        except:
            return []

    def execute_bonus_exploit(self):
        """Main exploit logic compatible with Python 3.7"""
        # Set base URL first
        self.base_url = self._get_working_base_url()
        if not self.base_url:
            return {"status": "FAILED", "reason": "All endpoints unavailable"}
        
        campaigns = self._get_bonus_campaigns()
        if not campaigns:
            return {"status": "FAILED", "reason": "No claimable bonuses found"}
        
        for campaign in campaigns:
            try:
                claim_params = {
                    "campaign_id": campaign["id"],
                    "action": "direct_claim",
                    "signature": ""
                }
                claim_params["signature"] = self._generate_web_signature(claim_params)
                
                response = self.session.post(
                    f"{self.base_url}/api/bonus/claim",
                    json=claim_params,
                    timeout=10
                ).json()
                
                if response.get("success"):
                    return {
                        "status": "SUCCESS",
                        "campaign": campaign["name"],
                        "amount": response["data"]["amount"],
                        "currency": response["data"]["coin"]
                    }
            except:
                continue
        
        return {"status": "FAILED", "reason": "All claim attempts failed"}

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="MEXC Bonus Hunter v13.2")
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--api-secret", required=True)
    args = parser.parse_args()

    print("""
    ███╗   ███╗███████╗██╗  ██╗ ██████╗    ██████╗  ██████╗ ███╗   ██╗██╗   ██╗███████╗
    ████╗ ████║██╔════╝╚██╗██╔╝██╔════╝    ██╔══██╗██╔═══██╗████╗  ██║██║   ██║██╔════╝
    ██╔████╔██║█████╗   ╚███╔╝ ██║  ███╗   ██║  ██║██║   ██║██╔██╗ ██║██║   ██║███████╗
    ██║╚██╔╝██║██╔══╝   ██╔██╗ ██║   ██║   ██║  ██║██║   ██║██║╚██╗██║██║   ██║╚════██║
    ██║ ╚═╝ ██║███████╗██╔╝ ██╗╚██████╔╝   ██████╔╝╚██████╔╝██║ ╚████║╚██████╔╝███████║
    ╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝
    BONUS HUNTER FRAMEWORK v13.2 (PYTHON 3.7 COMPATIBLE)
    """)

    hunter = MEXCBonusHunter(args.api_key, args.api_secret)
    result = hunter.execute_bonus_exploit()
    
    print("\n🔥 EXPLOIT RESULT:")
    print(json.dumps(result, indent=2))
    
    if result["status"] == "SUCCESS":
        print(f"\n💰 Success! Claimed {result['amount']} {result['currency']} from {result['campaign']}")
    else:
        print("\n❌ Exploit failed. Try these steps:")
        print("1. Verify your API keys have bonus permissions")
        print("2. Check if any bonuses are currently available")
        print("3. Try again during promotional periods")
        print(f"4. Last error: {result.get('reason', 'Unknown')}")
