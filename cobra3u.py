import argparse
import requests
import time
import hashlib
import hmac
from urllib.parse import urlencode

class MEXCValidTester:
    def __init__(self, api_key, api_secret):
        self.base_url = 'https://api.mexc.com'
        self.api_key = api_key.strip()
        self.api_secret = api_secret.strip()
        self.session = requests.Session()
        self.session.headers.update({
            'X-MEXC-APIKEY': self.api_key,
            'Content-Type': 'application/json'
        })
    
    def _proper_signature(self, params):
        """Correct signature that complies with API rules"""
        params['timestamp'] = int(time.time() * 1000)
        params['recvWindow'] = 5000  # Valid window per API docs
        
        # Create and sign the query string
        query_string = urlencode(sorted(params.items()))
        signature = hmac.new(
            self.api_secret.encode('utf-8'),
            query_string.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        params['signature'] = signature
        return params

    def test_symbol(self, symbol):
        """Proper symbol testing that won't get blocked"""
        try:
            # First verify the symbol exists
            params = self._proper_signature({})
            response = self.session.get(
                f"{self.base_url}/api/v3/exchangeInfo",
                params=params
            )
            data = response.json()
            
            # Check if symbol exists
            valid_symbols = [s['symbol'] for s in data.get('symbols', [])]
            if symbol.upper() in valid_symbols:
                return {
                    'status': 'valid',
                    'symbol': symbol,
                    'permissions': next(
                        (s['permissions'] for s in data['symbols'] 
                        if s['symbol'] == symbol.upper()
                    )
                }
            return {
                'status': 'invalid',
                'valid_symbols_sample': valid_symbols[:5]
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'debug': {
                    'timestamp': int(time.time() * 1000),
                    'api_status': response.status_code if 'response' in locals() else None
                }
            }

def main():
    parser = argparse.ArgumentParser(description='MEXC Symbol Validator')
    parser.add_argument('--api-key', required=True)
    parser.add_argument('--api-secret', required=True)
    parser.add_argument('--symbol', required=True)
    
    args = parser.parse_args()
    
    tester = MEXCValidTester(args.api_key, args.api_secret)
    result = tester.test_symbol(args.symbol)
    
    print("\n=== SYMBOL VALIDATION RESULT ===")
    print(result)

if __name__ == "__main__":
    main()
