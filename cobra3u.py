import argparse
import requests
import time
import hashlib
import hmac
from urllib.parse import urlencode

class MEXCTester:
    def __init__(self, api_key, api_secret):
        self.base_url = 'https://api.mexc.com'
        self.api_key = api_key.strip()
        self.api_secret = api_secret.strip()
        self.session = requests.Session()
        self.session.headers.update({
            'X-MEXC-APIKEY': self.api_key,
            'Content-Type': 'application/json'
        })
    
    def _sign_request(self, params):
        """Minimal signature generation that works"""
        params['timestamp'] = int(time.time() * 1000)
        query_string = urlencode(params)
        signature = hmac.new(
            self.api_secret.encode('utf-8'),
            query_string.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        params['signature'] = signature
        return params

    def test_order(self, symbol, quantity, price):
        """Direct order placement without symbol validation"""
        try:
            params = {
                'symbol': symbol.upper(),  # Force uppercase but don't validate
                'side': 'BUY',
                'type': 'LIMIT',
                'quantity': str(quantity),
                'price': str(price),
            }
            params = self._sign_request(params)
            
            response = self.session.post(
                f"{self.base_url}/api/v3/order",
                params=params,
                timeout=5
            )
            return response.json()
        except Exception as e:
            return {"error": str(e)}

def main():
    parser = argparse.ArgumentParser(description='MEXC API Symbol Tester')
    parser.add_argument('--api-key', required=True, help='Your API Key')
    parser.add_argument('--api-secret', required=True, help='Your API Secret')
    parser.add_argument('--symbol', required=True, help='Symbol to test')
    parser.add_argument('--quantity', type=float, default=0.001, help='Order quantity')
    parser.add_argument('--price', type=float, default=1.0, help='Order price')
    
    args = parser.parse_args()
    
    tester = MEXCTester(args.api_key, args.api_secret)
    result = tester.test_order(args.symbol, args.quantity, args.price)
    
    print("\nAPI Response:")
    print(result)

if __name__ == "__main__":
    main()
