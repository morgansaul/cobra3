#!/usr/bin/env python3
# MEXC Futures Zero-Balance Exploit Framework v11.1 (Signature Fixed)

import hmac
import hashlib
import requests
import time
import json
from urllib.parse import urlencode, quote_plus

class MEXCFuturesExploit:
    def __init__(self, api_key, api_secret):
        self.api_key = api_key
        self.api_secret = api_secret
        self.base_url = "https://contract.mexc.com"  # Correct futures domain
        self._session = requests.Session()
        self._session.headers.update({
            'Content-Type': 'application/json',
            'ApiKey': self.api_key  # Correct header name
        })

    def _generate_signature(self, params):
        """Proper signature generation for MEXC Futures API"""
        params['timestamp'] = int(time.time() * 1000)
        # MEXC requires strict parameter formatting
        query = '&'.join([f"{k}={quote_plus(str(v))}" for k,v in sorted(params.items())])
        return hmac.new(
            self.api_secret.encode('utf-8'),
            query.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

    def _send_request(self, endpoint, params):
        """Send signed request with error handling"""
        try:
            signature = self._generate_signature(params)
            params['signature'] = signature
            
            response = self._session.post(
                f"{self.base_url}{endpoint}",
                data=json.dumps(params),
                timeout=10
            )
            
            return {
                'status': response.status_code,
                'response': response.json(),
                'success': response.json().get('success', False)
            }
        except Exception as e:
            return {
                'error': str(e),
                'success': False
            }

    def test_market_order(self, symbol):
        """Test market order exploit"""
        params = {
            'symbol': symbol,
            'side': 1,  # 1=BUY, 2=SELL
            'type': 1,  # 1=MARKET
            'quantity': 0.001,
            'leverage': 20,
            'positionType': 1,  # 1=isolated
            'test': True
        }
        return self._send_request('/api/v1/private/order/test', params)

    def test_limit_order(self, symbol):
        """Test limit order exploit"""
        params = {
            'symbol': symbol,
            'side': 1,
            'type': 2,  # 2=LIMIT
            'price': "100000",  # Far from market
            'quantity': 0.001,
            'leverage': 20,
            'positionType': 1,
            'test': True
        }
        return self._send_request('/api/v1/private/order/test', params)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='MEXC Futures Exploit v11.1')
    parser.add_argument('--api-key', required=True)
    parser.add_argument('--api-secret', required=True)
    parser.add_argument('--symbol', default='BTCUSDT')
    args = parser.parse_args()

    print("""
    ███╗   ███╗███████╗██╗  ██╗ ██████╗    ███████╗██╗   ██╗████████╗██╗   ██╗██████╗ ███████╗
    ████╗ ████║██╔════╝╚██╗██╔╝██╔════╝    ██╔════╝██║   ██║╚══██╔══╝██║   ██║██╔══██╗██╔════╝
    ██╔████╔██║█████╗   ╚███╔╝ ██║  ███╗   █████╗  ██║   ██║   ██║   ██║   ██║██████╔╝█████╗  
    ██║╚██╔╝██║██╔══╝   ██╔██╗ ██║   ██║   ██╔══╝  ██║   ██║   ██║   ██║   ██║██╔══██╗██╔══╝  
    ██║ ╚═╝ ██║███████╗██╔╝ ██╗╚██████╔╝   ██║     ╚██████╔╝   ██║   ╚██████╔╝██║  ██║███████╗
    ╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝      ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝
    FUTURES-ONLY EXPLOIT FRAMEWORK v11.1 (SIGNATURE FIXED)
    """)

    exploit = MEXCFuturesExploit(args.api_key, args.api_secret)
    
    print("\n🔹 Testing Market Order Exploit")
    market_result = exploit.test_market_order(args.symbol)
    print(json.dumps(market_result, indent=2))
    
    print("\n🔹 Testing Limit Order Exploit")
    limit_result = exploit.test_limit_order(args.symbol)
    print(json.dumps(limit_result, indent=2))
