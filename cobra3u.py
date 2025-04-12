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
        """MEXC-specific signature generation"""
        params['timestamp'] = int(time.time() * 1000)
        params['recvWindow'] = 5000
        
        query_string = urlencode(sorted(params.items()))
        signature = hmac.new(
            self.api_secret.encode('utf-8'),
            query_string.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        params['signature'] = signature
        return params

    def test_order(self, symbol, quantity, price):
        """Place test order"""
        try:
            params = {
                'symbol': symbol.upper(),
                'side': 'BUY',
                'type': 'LIMIT',
                'quantity': str(quantity),
                'price': str(price),
                'newOrderRespType': 'ACK'
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
    parser = argparse.ArgumentParser(description='MEXC API Tester')
    parser.add_argument('--api-key', required=True)
    parser.add_argument('--api-secret', required=True)
    parser.add_argument('--symbol', required=True)
    parser.add_argument('--quantity', type=float, required=True)
    parser.add_argument('--price', type=float, required=True)
    
    args = parser.parse_args()
    
    tester = MEXCTester(args.api_key, args.api_secret)
    result = tester.test_order(args.symbol, args.quantity, args.price)
    
    print("\nAPI Response:")
    print(result)

if __name__ == "__main__":
    main()
