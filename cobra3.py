import argparse
import requests
import time
import hashlib
import hmac
from urllib.parse import urlencode

class MEXCNegativeBalanceTester:
    def __init__(self, base_url, api_key=None, api_secret=None):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.api_secret = api_secret
        self.session = requests.Session()
        self.session.headers.update({
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-MEXC-APIKEY': api_key  # MEXC uses different header
        })
    
    def _sign_request(self, params):
        """MEXC-specific request signing"""
        if not self.api_secret:
            return params
            
        params['timestamp'] = int(time.time() * 1000)
        query_string = urlencode(sorted(params.items()))
        signature = hmac.new(
            self.api_secret.encode('utf-8'),
            query_string.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        params['signature'] = signature
        return params
    
    def get_balance(self, currency='USDT'):
        """MEXC balance endpoint"""
        endpoint = '/api/v3/account'
        params = {}
        params = self._sign_request(params)
        
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
        """MEXC test order endpoint"""
        endpoint = '/api/v3/order/test'
        params = {
            'symbol': symbol,
            'side': side.upper(),
            'type': 'LIMIT',
            'quantity': quantity,
            'price': price,
            'recvWindow': 5000
        }
        params = self._sign_request(params)
        
        response = self.session.post(
            self.base_url + endpoint,
            json=params  # MEXC expects JSON body
        )
        return response.json()
    
    def test_negative_balance(self, symbol='BTCUSDT', test_quantity=0.01, test_price=84400):
        print("[*] Starting MEXC-specific negative balance test")
        
        # First verify API connectivity
        print("[*] Verifying API access...")
        initial_balance = self.get_balance()
        if initial_balance is None:
            print("[-] Failed to connect to API - check credentials")
            return False
        
        print(f"[+] Initial USDT balance: {initial_balance}")
        
        print(f"[*] Attempting to place buy order for {test_quantity} {symbol.split('USDT')[0]} at {test_price} USDT")
        order_result = self.place_test_order(
            symbol=symbol,
            side='BUY',
            quantity=test_quantity,
            price=test_price
        )
        
        if 'code' in order_result:
            print(f"[-] Order rejected: {order_result.get('msg', 'No error message')}")
            if order_result.get('code') == -2010:  # MEXC's insufficient balance code
                print("[+] Exchange properly validated balance")
                return False
            else:
                print("[?] Unexpected error - may need investigation")
                return False
        else:
            print("[!] WARNING: Exchange accepted order exceeding balance!")
            return True

def main():
    parser = argparse.ArgumentParser(description='MEXC Negative Balance Scanner')
    parser.add_argument('--base-url', default='https://api.mexc.com', help='MEXC API URL')
    parser.add_argument('--api-key', required=True, help='MEXC API key')
    parser.add_argument('--api-secret', required=True, help='MEXC API secret')
    parser.add_argument('--symbol', default='BTCUSDT', help='Trading pair')
    parser.add_argument('--quantity', type=float, default=0.01, help='Test quantity (smaller for MEXC)')
    parser.add_argument('--price', type=float, default=10000, help='Test price')
    
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
