import argparse
import requests
import time
import hashlib
import hmac
from urllib.parse import urlencode

class MEXCNegativeBalanceTester:
    def __init__(self, base_url, api_key, api_secret):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.api_secret = api_secret
        self.session = requests.Session()
        self.session.headers.update({
            'X-MEXC-APIKEY': api_key,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
    
    def _generate_signature(self, params):
        """Generate proper MEXC signature"""
        query_string = urlencode(sorted(params.items()))
        return hmac.new(
            self.api_secret.encode('utf-8'),
            query_string.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
    
    def get_balance(self):
        """Get account balance with proper MEXC auth"""
        endpoint = '/api/v3/account'
        params = {
            'timestamp': int(time.time() * 1000),
            'recvWindow': 60000  # Increased window for reliability
        }
        params['signature'] = self._generate_signature(params)
        
        response = self.session.get(
            self.base_url + endpoint,
            params=params
        )
        
        if response.status_code == 200:
            return response.json()
        print(f"[-] Balance check failed (HTTP {response.status_code}): {response.text}")
        return None
    
    def place_test_order(self, symbol, quantity, price):
        """Place test order with correct MEXC auth"""
        endpoint = '/api/v3/order/test'
        params = {
            'symbol': symbol,
            'side': 'BUY',
            'type': 'LIMIT',
            'quantity': quantity,
            'price': price,
            'timestamp': int(time.time() * 1000),
            'recvWindow': 60000
        }
        params['signature'] = self._generate_signature(params)
        
        response = self.session.post(
            self.base_url + endpoint,
            params=params  # MEXC uses query params for POST requests
        )
        return response.json()
    
    def test_negative_balance(self, symbol='BTCUSDT', quantity=0.001, price=84400):
        print("[*] Starting enhanced MEXC negative balance test")
        
        # Verify API connectivity
        print("[*] Verifying API credentials...")
        balance_data = self.get_balance()
        if not balance_data:
            print("[-] Failed to authenticate with MEXC API")
            print("[!] Please verify:")
            print("    1. API key permissions (enable trading)")
            print("    2. API key is not expired")
            print("    3. Server time is synchronized (current timestamp: {})".format(int(time.time() * 1000)))
            return False
        
        usdt_balance = next((float(b['free']) for b in balance_data['balances'] if b['asset'] == 'USDT'), 0.0)
        print(f"[+] Initial USDT balance: {usdt_balance}")
        
        required_funds = quantity * price
        print(f"[*] Attempting to buy {quantity} {symbol} at {price} USDT (requires {required_funds} USDT)")
        
        order_result = self.place_test_order(
            symbol=symbol,
            quantity=quantity,
            price=price
        )
        
        if 'code' in order_result:
            print(f"[-] Order rejected: {order_result.get('msg')}")
            if order_result.get('code') == -2010:
                print("[+] Exchange properly validated insufficient balance")
                return False
            print("[?] Check error code {} at MEXC API docs".format(order_result.get('code')))
            return False
        
        print("[!] WARNING: Exchange accepted order exceeding balance!")
        print("[*] Verifying actual balance impact...")
        
        new_balance = self.get_balance()
        if new_balance:
            new_usdt = next((float(b['free']) for b in new_balance['balances'] if b['asset'] == 'USDT'), 0.0)
            if new_usdt < 0:
                print(f"[!] CRITICAL: Negative balance confirmed: {new_usdt} USDT")
                return True
            print(f"[*] New USDT balance: {new_usdt} (no negative balance)")
        return False

def main():
    parser = argparse.ArgumentParser(description='MEXC Balance Test')
    parser.add_argument('--api-key', required=True, help='MEXC API key')
    parser.add_argument('--api-secret', required=True, help='MEXC API secret')
    parser.add_argument('--symbol', default='BTCUSDT', help='Trading pair')
    parser.add_argument('--quantity', type=float, default=0.001, help='Order quantity')
    parser.add_argument('--price', type=float, default=84400, help='Order price')
    
    args = parser.parse_args()
    
    tester = MEXCNegativeBalanceTester(
        base_url='https://api.mexc.com',
        api_key=args.api_key,
        api_secret=args.api_secret
    )
    
    print("\nMEXC Negative Balance Test")
    print("-------------------------")
    if tester.test_negative_balance(
        symbol=args.symbol,
        quantity=args.quantity,
        price=args.price
    ):
        print("\n[!] VULNERABILITY FOUND: Negative balance possible")
    else:
        print("\n[-] No vulnerability detected")

if __name__ == "__main__":
    main()
