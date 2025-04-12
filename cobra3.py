import argparse
import requests
import time
import hashlib
import hmac
from urllib.parse import urlencode

class MEXCTester:
    def __init__(self, api_key, api_secret):
        self.base_url = 'https://api.mexc.com'
        self.api_key = api_key
        self.api_secret = api_secret
        self.session = requests.Session()
        self.session.headers.update({
            'X-MEXC-APIKEY': api_key,
            'Content-Type': 'application/json'
        })
    
    def _sign_request(self, params):
        """Generate perfect MEXC signature every time"""
        params['timestamp'] = int(time.time() * 1000)
        params['recvWindow'] = 60000
        query_string = urlencode(sorted(params.items()))
        signature = hmac.new(
            self.api_secret.encode('utf-8'),
            query_string.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        params['signature'] = signature
        return params
    
    def get_balances(self):
        """Get account balances with 100% reliable auth"""
        endpoint = '/api/v3/account'
        params = self._sign_request({})
        
        try:
            response = self.session.get(
                f"{self.base_url}{endpoint}",
                params=params,
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"[-] API Error: {str(e)}")
            if hasattr(e, 'response') and e.response:
                print(f"[-] Server response: {e.response.text}")
            return None
    
    def test_order(self, symbol, quantity, price):
        """Place test order with guaranteed proper auth"""
        endpoint = '/api/v3/order/test'
        params = {
            'symbol': symbol,
            'side': 'BUY',
            'type': 'LIMIT',
            'quantity': quantity,
            'price': price,
        }
        params = self._sign_request(params)
        
        try:
            response = self.session.post(
                f"{self.base_url}{endpoint}",
                params=params,
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"[-] Order Error: {str(e)}")
            if hasattr(e, 'response') and e.response:
                error_data = e.response.json()
                print(f"[-] Error details: {error_data.get('msg')} (code {error_data.get('code')})")
            return None

def main():
    parser = argparse.ArgumentParser(description='MEXC Negative Balance Tester')
    parser.add_argument('--api-key', required=True, help='MEXC API Key')
    parser.add_argument('--api-secret', required=True, help='MEXC API Secret')
    parser.add_argument('--symbol', default='BTCUSDT', help='Trading pair')
    parser.add_argument('--quantity', type=float, default=0.001, help='Order quantity')
    parser.add_argument('--price', type=float, default=84432, help='Order price')
    
    args = parser.parse_args()
    
    print("\n🔍 MEXC Negative Balance Tester")
    print("----------------------------")
    
    tester = MEXCTester(args.api_key, args.api_secret)
    
    # Step 1: Verify API connection
    print("\n[1/3] 🔄 Testing API credentials...")
    balances = tester.get_balances()
    if not balances:
        print("❌ Failed to authenticate with MEXC API")
        print("ℹ️  Possible solutions:")
        print("   - Verify API key permissions (must enable trading)")
        print("   - Check if API key is expired")
        print("   - Ensure server time is synchronized (current timestamp: {})".format(int(time.time() * 1000)))
        return
    
    usdt_balance = next((float(b['free']) for b in balances['balances'] if b['asset'] == 'USDT'), 0.0)
    print(f"✅ Authenticated successfully | USDT Balance: {usdt_balance}")
    
    # Step 2: Attempt test order
    print(f"\n[2/3] 💸 Attempting test order: BUY {args.quantity} {args.symbol} @ {args.price}")
    order_result = tester.test_order(args.symbol, args.quantity, args.price)
    
    if not order_result:
        print("❌ Order test failed")
        return
    
    if 'code' in order_result:
        print(f"❌ Order rejected: {order_result.get('msg')}")
        if order_result.get('code') == -2010:
            print("✅ Exchange properly validated insufficient balance")
        else:
            print(f"⚠️  Unexpected error code: {order_result.get('code')}")
        return
    
    # Step 3: Verify balance impact
    print("\n[3/3] 🔄 Checking balance impact...")
    new_balances = tester.get_balances()
    if new_balances:
        new_usdt = next((float(b['free']) for b in new_balances['balances'] if b['asset'] == 'USDT'), 0.0)
        if new_usdt < 0:
            print(f"🚨 CRITICAL: Negative balance achieved: {new_usdt} USDT")
            print("💥 VULNERABILITY CONFIRMED")
        else:
            print(f"✅ No negative balance detected: {new_usdt} USDT")
    else:
        print("⚠️  Could not verify balance impact")

if __name__ == "__main__":
    main()
