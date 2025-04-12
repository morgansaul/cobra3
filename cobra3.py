import argparse
import requests
import time
import hashlib
import hmac
from urllib.parse import urlencode

class CEXNegativeBalanceTester:
    def __init__(self, base_url, api_key=None, api_secret=None):
        self.base_url = base_url
        self.api_key = api_key
        self.api_secret = api_secret
        self.session = requests.Session()
        self.session.headers.update({'Accept': 'application/json'})
        
        if api_key:
            self.session.headers.update({'X-MBX-APIKEY': api_key})
    
    def _sign_request(self, params):
        if not self.api_secret:
            return params
            
        query_string = urlencode(params)
        signature = hmac.new(
            self.api_secret.encode('utf-8'),
            query_string.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        params['signature'] = signature
        return params
    
    def get_balance(self, currency='USDT'):
        endpoint = '/api/v3/account'
        params = {'timestamp': int(time.time() * 1000)}
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
        return 0.0
    
    def place_test_order(self, symbol, side, quantity, price):
        endpoint = '/api/v3/order/test'
        params = {
            'symbol': symbol,
            'side': side,
            'type': 'LIMIT',
            'quantity': quantity,
            'price': price,
            'timestamp': int(time.time() * 1000)
        }
        params = self._sign_request(params)
        
        response = self.session.post(
            self.base_url + endpoint,
            data=params
        )
        return response.json()
    
    def test_negative_balance(self, symbol='BTCUSDT', test_quantity=1, test_price=83300):
        print("[*] Starting negative balance vulnerability test")
        
        initial_balance = self.get_balance()
        print(f"[+] Initial USDT balance: {initial_balance}")
        
        if initial_balance > 0:
            print("[!] Account has positive balance - consider using empty test account")
            return False
        
        print(f"[*] Attempting to place buy order for {test_quantity} BTC at {test_price} USDT")
        order_result = self.place_test_order(
            symbol=symbol,
            side='BUY',
            quantity=test_quantity,
            price=test_price
        )
        
        if 'code' in order_result:
            print(f"[-] Order rejected (expected): {order_result['msg']}")
            print("[+] Exchange appears to have proper balance validation")
            return False
        else:
            print("[!] WARNING: Exchange accepted order exceeding balance!")
            print("[*] Checking post-order balance...")
            
            post_balance = self.get_balance()
            if post_balance < 0:
                print(f"[!] CRITICAL: Negative balance achieved: {post_balance}")
                print("[+] Negative balance vulnerability confirmed!")
                return True
            else:
                print("[*] Order accepted but balance not negative")
                print("[?] Possible other vulnerability - needs manual investigation")
                return False

def main():
    parser = argparse.ArgumentParser(description='CEX Negative Balance Vulnerability Scanner')
    parser.add_argument('--base-url', required=True, help='Exchange API base URL')
    parser.add_argument('--api-key', help='Your API key')
    parser.add_argument('--api-secret', help='Your API secret')
    parser.add_argument('--symbol', default='BTCUSDT', help='Trading pair to test')
    parser.add_argument('--quantity', type=float, default=10, help='Test order quantity')
    parser.add_argument('--price', type=float, default=10000, help='Test order price')
    
    args = parser.parse_args()
    
    print("\nCEX Negative Balance Vulnerability Scanner")
    print("---------------------------------------")
    
    scanner = CEXNegativeBalanceTester(
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
        print("\n[!] VULNERABILITY FOUND: Negative balance exploit possible")
        print("[!] This is a critical finding - report to exchange immediately")
    else:
        print("\n[-] No negative balance vulnerability detected")

if __name__ == "__main__":
    main()
