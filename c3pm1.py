#!/usr/bin/env python3
# MEXC Futures Exploit Framework v11.2 (Connection-Stable)

import hmac
import hashlib
import requests
import time
import json
from urllib.parse import urlencode

class MEXCFuturesAttacker:
    def __init__(self, api_key, api_secret):
        self.api_key = api_key
        self.api_secret = api_secret
        self.base_url = "https://contract.mexc.com/api/v1/private"
        self.session = requests.Session()
        self.session.headers.update({
            'ApiKey': self.api_key,
            'Content-Type': 'application/json',
            'User-Agent': 'MEXC-EXPLOIT/11.2'
        })
        self.session.verify = False  # Bypass SSL verification for testing

    def _generate_signature(self, params):
        """MEXC-compliant signature generation"""
        params['timestamp'] = int(time.time() * 1000)
        query = urlencode(sorted(params.items()))
        return hmac.new(
            self.api_secret.encode('utf-8'),
            query.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

    def _send_api_request(self, endpoint, params):
        """Robust request handler with retries"""
        params['signature'] = self._generate_signature(params)
        
        for attempt in range(3):  # 3 retries
            try:
                response = self.session.post(
                    f"{self.base_url}{endpoint}",
                    json=params,  # Using json parameter instead of data
                    timeout=15
                )
                return {
                    'status': response.status_code,
                    'response': response.json(),
                    'success': response.status_code == 200
                }
            except requests.exceptions.RequestException as e:
                if attempt == 2:  # Final attempt failed
                    return {
                        'error': str(e),
                        'success': False
                    }
                time.sleep(1)  # Wait before retry

    def test_market_order(self, symbol):
        """Test market order execution"""
        params = {
            'symbol': symbol.replace('-', '_'),  # Format: BTC_USDT
            'side': 1,  # 1=buy, 2=sell
            'type': 1,  # 1=market
            'quantity': 0.001,
            'positionType': 1,  # 1=isolated
            'test': True
        }
        return self._send_api_request('/order/test', params)

    def test_leverage_change(self, symbol):
        """Test leverage manipulation"""
        params = {
            'symbol': symbol.replace('-', '_'),
            'leverage': 100,
            'positionType': 1
        }
        return self._send_api_request('/position/change_margin', params)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='MEXC Futures Exploit v11.2')
    parser.add_argument('--api-key', required=True)
    parser.add_argument('--api-secret', required=True)
    parser.add_argument('--symbol', default='BTC-USDT')
    args = parser.parse_args()

    print("""
    ███╗   ███╗███████╗██╗  ██╗ ██████╗    ███████╗██╗   ██╗████████╗ ██████╗ 
    ████╗ ████║██╔════╝╚██╗██╔╝██╔════╝    ██╔════╝██║   ██║╚══██╔══╝██╔═══██╗
    ██╔████╔██║█████╗   ╚███╔╝ ██║  ███╗   █████╗  ██║   ██║   ██║   ██║   ██║
    ██║╚██╔╝██║██╔══╝   ██╔██╗ ██║   ██║   ██╔══╝  ██║   ██║   ██║   ██║   ██║
    ██║ ╚═╝ ██║███████╗██╔╝ ██╗╚██████╔╝   ██║     ╚██████╔╝   ██║   ╚██████╔╝
    ╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝      ╚═════╝    ╚═╝    ╚═════╝ 
    FUTURES EXPLOIT FRAMEWORK v11.2 (STABLE CONNECTION)
    """)

    attacker = MEXCFuturesAttacker(args.api_key, args.api_secret)
    
    print("\n🔹 Testing Market Order (Zero Balance)")
    market_result = attacker.test_market_order(args.symbol)
    print(json.dumps(market_result, indent=2))
    
    print("\n🔹 Testing Max Leverage Change")
    leverage_result = attacker.test_leverage_change(args.symbol)
    print(json.dumps(leverage_result, indent=2))
