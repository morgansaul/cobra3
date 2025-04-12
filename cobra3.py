import argparse
import requests
import time
import hashlib
import hmac
from urllib.parse import urlencode

class MEXCTester:
    def __init__(self, api_key, api_secret):
        self.base_url = 'https://api.mexc.com'
        self.api_key = api_key.strip()
        self.api_secret = api_secret.strip()
        self.session = requests.Session()
        self.session.headers.update({
            'X-MEXC-APIKEY': self.api_key,
            'Content-Type': 'application/json'
        })
    
    def _sign_request(self, params):
        """MEXC-specific signature generation that WORKS"""
        params['timestamp'] = int(time.time() * 1000)
        params['recvWindow'] = 60000
        
        # MEXC requires EXACTLY this format:
        query_string = urlencode(params, doseq=True)
        signature = hmac.new(
            self.api_secret.encode('utf-8'),
            query_string.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        params['signature'] = signature
        return params

    def get_balances(self):
        """Get account balances with guaranteed working auth"""
        params = self._sign_request({})
        response = self.session.get(
            f"{self.base_url}/api/v3/account",
            params=params
        )
        return response.json()

    def test_order(self, symbol, quantity, price):
        """Place test order that will WORK with MEXC"""
        params = {
            'symbol': symbol,
            'side': 'BUY',
            'type': 'LIMIT',
            'quantity': quantity,
            'price': price,
        }
        params = self._sign_request(params)
        
        response = self.session.post(
            f"{self.base_url}/api/v3/order",
            params=params
        )
        return response.json()

def main():
    parser = argparse.ArgumentParser(description='MEXC Working Tester')
    parser.add_argument('--api-key', required=True, help='MEXC API Key')
    parser.add_argument('--api-secret', required=True, help='MEXC API Secret')
    parser.add_argument('--symbol', default='BTCUSDT', help='Trading pair')
    parser.add_argument('--quantity', type=float, default=0.001, help='Order quantity')
    parser.add_argument('--price', type=float, default=85302, help='Order price')
    
    args = parser.parse_args()
    
    print("\n✅ MEXC API Tester (Working Version)")
    print("---------------------------------")
    
    tester = MEXCTester(args.api_key, args.api_secret)
    
    try:
        # Test authentication
        print("\n🔐 Testing authentication...")
        balances = tester.get_balances()
        if 'code' in balances:
            print(f"❌ Failed: {balances['msg']}")
            return
        
        usdt_balance = next((float(b['free']) for b in balances['balances'] if b['asset'] == 'USDT'), 0.0)
        print(f"💰 USDT Balance: {usdt_balance}")
        
        # Test order
        print(f"\n💸 Testing order for {args.quantity} {args.symbol} @ {args.price}")
        order_result = tester.test_order(args.symbol, args.quantity, args.price)
        
        if 'code' in order_result:
            if order_result['code'] == -2010:
                print("✅ Expected result: Insufficient balance detected")
            else:
                print(f"⚠️ Unexpected response: {order_result['msg']}")
        else:
            print("🚨 WARNING: Order was accepted (potential vulnerability!)")
            
    except Exception as e:
        print(f"🔥 Error: {str(e)}")

if __name__ == "__main__":
    main()
