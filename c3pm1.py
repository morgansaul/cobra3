#!/usr/bin/env python3
# MEXC Futures Exploit Framework v11.3 (Fully Debugged)

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
        self.base_url = "https://contract.mexc.com"
        self.session = requests.Session()
        self.session.headers.update({
            'ApiKey': self.api_key,
            'Content-Type': 'application/json',
            'User-Agent': 'MEXC-EXPLOIT/11.3'
        })
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()  # Disable all SSL warnings

    def _generate_signature(self, params):
        """Precise signature generation that matches MEXC's requirements"""
        params['timestamp'] = int(time.time() * 1000)
        # MEXC requires EXACT format: key1=value1&key2=value2 (no URL encoding of values)
        query = '&'.join([f"{k}={v}" for k, v in sorted(params.items())])
        return hmac.new(
            self.api_secret.encode('utf-8'),
            query.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

    def _send_request(self, endpoint, params):
        """Robust request handler with precise formatting"""
        try:
            params['signature'] = self._generate_signature(params)
            response = self.session.post(
                f"{self.base_url}{endpoint}",
                json=params,
                timeout=15
            )
            return {
                'status': response.status_code,
                'response': response.json(),
                'success': response.status_code == 200 and response.json().get('success', False)
            }
        except Exception as e:
            return {
                'error': str(e),
                'success': False
            }

    def test_order(self, symbol):
        """Working order test endpoint"""
        params = {
            'symbol': symbol.replace('-', '_').upper(),  # BTC_USDT format
            'price': "10000",  # Required even for market orders
            'vol': "1",  # Note: 'vol' instead of 'quantity'
            'leverage': "20",
            'side': "1",  # 1=open long, 2=open short
            'type': "1",  # 1=market, 2=limit
            'openType': "1",  # 1=isolated
            'positionId': "0",  # Required for MEXC Futures
            'externalOid': f"TEST_{int(time.time())}",  # Unique ID
            'test': True
        }
        return self._send_request('/api/v1/private/order/submit_test', params)

    def change_leverage(self, symbol):
        """Working leverage change endpoint"""
        params = {
            'symbol': symbol.replace('-', '_').upper(),
            'leverage': "100",
            'openType': "1"  # 1=isolated
        }
        return self._send_request('/api/v1/private/position/change_leverage', params)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='MEXC Futures Exploit v11.3')
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
    FUTURES EXPLOIT FRAMEWORK v11.3 (DEBUGGED)
    """)

    attacker = MEXCFuturesAttacker(args.api_key, args.api_secret)
    
    print("\n🔹 Testing Order Submission")
    order_result = attacker.test_order(args.symbol)
    print(json.dumps(order_result, indent=2))
    
    print("\n🔹 Testing Leverage Change")
    leverage_result = attacker.change_leverage(args.symbol)
    print(json.dumps(leverage_result, indent=2))
