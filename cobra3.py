import argparse
import requests
import time
import hashlib
import hmac
import json
from urllib.parse import urlencode

class MEXCNegativeBalanceTester:
    def __init__(self, base_url, api_key=None, api_secret=None):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.api_secret = api_secret
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'X-MEXC-APIKEY': api_key,
            'Accept': 'application/json'
        })
    
    def _generate_signature(self, params):
        """Generate MEXC-compatible signature"""
        query_string = urlencode(sorted(params.items()))
        return hmac.new(
            self.api_secret.encode('utf-8'),
            query_string.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
    
    def get_balance(self, currency='USDT'):
        """Get account balance with proper MEXC auth"""
        endpoint = '/api/v3/account'
        params = {
            'timestamp': int(time.time() * 1000),
            'recvWindow': 5000
        }
        params['signature'] = self._generate_signature(params)
        
        response = self.session.get(
            self.base_url + endpoint,
            params=params
        )
        
        if response.status_code == 200:
            balances = response.json().get('balances', [])
            for balance in balances:
                if balance['asset'] == currency:
                    return float(balance['free'])
        print(f"[-] Balance check failed: {response.text}")
        return 0.0
    
    def place_test_order(self, symbol, side, quantity, price):
        """Place test order with MEXC-compatible auth"""
        endpoint = '/api/v3/order/test'
        params = {
            'symbol': symbol,
            'side': side.upper(),
            'type': 'LIMIT',
            'quantity': quantity,
            'price': price,
            'timestamp': int(time.time() * 1000),
            'recvWindow': 5000
        }
        params['signature'] = self._generate_signature(params)
        
        response = self.session.post(
            self.base_url + endpoint,
            params=params  # MEXC v3 uses query params for POST
        )
        return response.json()
    
    def test_negative_balance(self, symbol='BTCUSDT', test_quantity=0.001, test_price=84400):
        print("[*] Starting MEXC-specific negative balance test")
        
        # Verify API connectivity
        print("[*] Verifying API access...")
        try:
            initial_balance = self.get_balance()
            print(f"[+] Initial USDT balance: {initial_balance}")
        except Exception as e:
            print(f"[-] API connection failed: {str(e)}")
            return False
        
        print(f"[*] Attempting to place buy order for {test_quantity} {symbol.split('USDT')[0]} at {test_price} USDT")
        try:
            order_result = self.place_test_order(
                symbol=symbol,
                side='BUY',
                quantity=test_quantity,
                price=test_price
            )
            
            if 'code' in order_result:
                print(f"[-] Order rejected: {order_result.get('msg', 'No error message')}")
                if order_result.get('code') == -2010:  # Insufficient balance
                    print("[+] Exchange properly validated balance")
                    return False
                else:
                    print("[?] Unexpected error - may need investigation")
                    return False
            else:
                print("[!] WARNING: Exchange accepted order exceeding balance!")
                return True
        except Exception as e:
            print(f"[-] Order placement failed: {str(e)}")
            return False

def main():
    parser = argparse.ArgumentParser(description='MEXC Negative Balance Scanner')
    parser.add_argument('--base-url', default='https://api.mexc.com', help='MEXC API URL')
    parser.add_argument('--api-key', required=True, help='MEXC API key')
    parser.add_argument('--api-secret', required=True, help='MEXC API secret')
    parser.add_argument('--symbol', default='BTCUSDT', help='Trading pair')
    parser.add_argument('--quantity', type=float, default=0.001, help='Test quantity')
    parser.add_argument('--price', type=float, default=84400, help='Test price')
    
    args = parser.parse_args()
    
    print("\nMEXC Negative Balance Vulnerability Scanner")
    print("---------------------------------------")
    
    scanner = MEXCNegativeBalanceTester(
        base_url=args.base_url,
        api_key=args.api_key,
        api_secret=args.api_secret
    )
    
    vulnerability_found = scanner.test_negative_balance(
        symbol=args.symbol,
        test_quantity=args.quantity,
        test_price=args.price
    )
    
    if vulnerability_found:
        print("\n[!] POTENTIAL VULNERABILITY DETECTED")
        print("[!] Further manual verification required")
    else:
        print("\n[-] No negative balance vulnerability detected")

if __name__ == "__main__":
    main()
