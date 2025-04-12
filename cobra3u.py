import argparse
import requests
import time
import hashlib
import hmac
from urllib.parse import urlencode

class MEXCBypassTester:
    def __init__(self, api_key, api_secret):
        self.base_url = 'https://api.mexc.com'
        self.api_key = api_key.strip()
        self.api_secret = api_secret.strip()
        self.session = requests.Session()
        self.session.headers.update({
            'X-MEXC-APIKEY': self.api_key,
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0'  # Bypass potential API filters
        })
    
    def _force_signature(self, params):
        """Aggressive signature that forces through"""
        params['timestamp'] = int(time.time() * 1000)
        params['recvWindow'] = 999999  # Max window to avoid timing issues
        
        # Force signature without parameter validation
        query_string = "&".join([f"{k}={v}" for k,v in params.items()])
        signature = hmac.new(
            self.api_secret.encode('utf-8'),
            query_string.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        params['signature'] = signature
        return params

    def test_symbol(self, symbol, quantity, price):
        """Direct symbol testing with forced parameters"""
        try:
            # Prepare raw parameters
            params = {
                'symbol': symbol.upper(),
                'side': 'BUY',
                'type': 'LIMIT',
                'quantity': str(quantity),
                'price': str(price),
                'newOrderRespType': 'ACK',
                'forceBypass': 'true'  # Experimental flag
            }
            
            # Force the request through
            params = self._force_signature(params)
            response = self.session.post(
                f"{self.base_url}/api/v3/order/test",
                params=params,
                timeout=10
            )
            
            # Return raw response for analysis
            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'response': response.json()
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'debug_info': {
                    'symbol': symbol,
                    'params': params
                }
            }

def main():
    parser = argparse.ArgumentParser(description='MEXC Symbol Bypass Tester')
    parser.add_argument('--api-key', required=True)
    parser.add_argument('--api-secret', required=True)
    parser.add_argument('--symbol', required=True)
    parser.add_argument('--quantity', type=float, default=0.001)
    parser.add_argument('--price', type=float, default=1.0)
    
    args = parser.parse_args()
    
    tester = MEXCBypassTester(args.api_key, args.api_secret)
    result = tester.test_symbol(args.symbol, args.quantity, args.price)
    
    print("\n=== RAW API RESPONSE ===")
    print(result)

if __name__ == "__main__":
    main()
