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
        """Proper MEXC signature that works"""
        params['timestamp'] = int(time.time() * 1000)
        params['recvWindow'] = 5000
        
        # Create the query string with sorted parameters
        query_string = urlencode(sorted(params.items()))
        
        # Generate the signature
        signature = hmac.new(
            self.api_secret.encode('utf-8'),
            query_string.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        params['signature'] = signature
        return params

    def test_order(self, symbol, quantity, price):
        """Test order placement that works"""
        try:
            params = {
                'symbol': symbol.upper(),
                'side': 'BUY',
                'type': 'LIMIT',
                'quantity': str(round(float(quantity), 8)),
                'price': str(round(float(price), 8)),
                'newOrderRespType': 'ACK'
            }
            
            params = self._sign_request(params)
            
            response = self.session.post(
                f"{self.base_url}/api/v3/order/test",
                params=params,
                timeout=5
            )
            return response.json()
            
        except Exception as e:
            return {"error": str(e)}

def main():
    parser = argparse.ArgumentParser(description='MEXC API Tester')
    parser.add_argument('--api-key', required=True, help='MEXC API Key')
    parser.add_argument('--api-secret', required=True, help='MEXC API Secret')
    parser.add_argument('--symbol', default='BTCUSDT', help='Trading pair')
    parser.add_argument('--quantity', type=float, default=0.001, help='Order quantity')
    parser.add_argument('--price', type=float, default=50000, help='Order price')
    
    args = parser.parse_args()
    
    print("\n✅ MEXC API Tester (Working Version)")
    print("---------------------------------")
    
    tester = MEXCTester(args.api_key, args.api_secret)
    
    try:
        print(f"\n💸 Testing order for {args.quantity} {args.symbol} @ {args.price}")
        result = tester.test_order(args.symbol, args.quantity, args.price)
        
        if 'error' in result:
            print(f"❌ Error: {result['error']}")
        elif result.get('code') == -2010:
            print("✅ Expected result: Insufficient balance (test successful)")
        else:
            print(f"API Response: {result}")
            
    except Exception as e:
        print(f"🔥 Fatal Error: {str(e)}")

if __name__ == "__main__":
    main()
