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
        """MEXC-specific signature generation"""
        params['timestamp'] = int(time.time() * 1000)
        params['recvWindow'] = 60000
        
        query_string = urlencode(params, doseq=True)
        signature = hmac.new(
            self.api_secret.encode('utf-8'),
            query_string.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        params['signature'] = signature
        return params

    def get_balances(self):
        """Get account balances"""
        params = self._sign_request({})
        response = self.session.get(
            f"{self.base_url}/api/v3/account",
            params=params
        )
        return response.json()

    def test_order(self, symbol, quantity, price):
        """Place test order with proper symbol validation"""
        symbol = symbol.upper().strip()  # Normalize symbol format
        
        try:
            # Get all valid symbols
            info = self.session.get(f"{self.base_url}/api/v3/exchangeInfo").json()
            valid_symbols = [s['symbol'] for s in info.get('symbols', [])]
            
            if symbol not in valid_symbols:
                print(f"❌ Invalid symbol. First 5 valid symbols: {valid_symbols[:5]}")
                return {"code": -1121, "msg": "Invalid symbol"}

            # Prepare order
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
            data = response.json()
            
            # Handle API response
            if 'code' in data and data['code'] != 200:
                print(f"⚠️ API Error: {data.get('msg', 'Unknown error')}")
            return data
            
        except Exception as e:
            print(f"🔥 Request Failed: {str(e)}")
            return {"error": str(e)}

def main():
    parser = argparse.ArgumentParser(description='MEXC API Tester')
    parser.add_argument('--api-key', required=True, help='MEXC API Key')
    parser.add_argument('--api-secret', required=True, help='MEXC API Secret')
    parser.add_argument('--symbol', default='BTCUSDT', help='Trading pair (e.g. BTCUSDT)')
    parser.add_argument('--quantity', type=float, default=0.001, help='Order quantity')
    parser.add_argument('--price', type=float, default=50000, help='Order price')
    
    args = parser.parse_args()
    
    print("\n✅ MEXC API Tester (Working Version)")
    print("---------------------------------")
    
    tester = MEXCTester(args.api_key, args.api_secret)
    
    try:
        # Test authentication
        print("\n🔐 Testing authentication...")
        balances = tester.get_balances()
        if 'code' in balances:
            print(f"❌ Auth Failed: {balances['msg']}")
            return
        
        usdt_balance = next((float(b['free']) for b in balances['balances'] if b['asset'] == 'USDT'), 0.0)
        print(f"💰 USDT Balance: {usdt_balance}")
        
        # Test order
        print(f"\n💸 Testing order for {args.quantity} {args.symbol} @ {args.price}")
        order_result = tester.test_order(args.symbol, args.quantity, args.price)
        
        if 'error' in order_result:
            print(f"❌ Order Failed: {order_result['error']}")
        elif order_result.get('code') == -2010:
            print("✅ Expected result: Insufficient balance")
        elif 'orderId' in order_result:
            print("🚨 WARNING: Order was accepted!")
        else:
            print(f"⚠️ API Response: {order_result}")
            
    except Exception as e:
        print(f"🔥 Fatal Error: {str(e)}")

if __name__ == "__main__":
    main()
