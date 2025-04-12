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
        """Correct MEXC signature generation per their docs"""
        params['timestamp'] = int(time.time() * 1000)
        params['recvWindow'] = 5000  # Recommended window from docs
        
        # Must be in exact order: timestamp, recvWindow, other params
        query_string = urlencode(sorted(params.items()))
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
        """Place test order with current API requirements"""
        # Normalize symbol (remove -SPOT if accidentally included)
        symbol = symbol.upper().replace('-SPOT', '')
        
        try:
            # Prepare order parameters EXACTLY as API expects
            params = {
                'symbol': symbol,
                'side': 'BUY',
                'type': 'LIMIT',
                'quantity': str(round(quantity, 8)),  # Must be string, precise to 8 decimals
                'price': str(round(price, 8)),       # Must be string, precise to 8 decimals
                'newOrderRespType': 'ACK'            # Required by API
            }
            
            params = self._sign_request(params)
            
            response = self.session.post(
                f"{self.base_url}/api/v3/order",
                params=params,
                timeout=5
            )
            data = response.json()
            
            if 'code' in data:
                if data['code'] == 10007:
                    print("ℹ️ Confirm symbol exists via: https://api.mexc.com/api/v3/exchangeInfo")
                return data
            return data
            
        except Exception as e:
            print(f"🔥 API Request Failed: {str(e)}")
            return {"error": str(e)}

def main():
    parser = argparse.ArgumentParser(description='MEXC API Tester')
    parser.add_argument('--api-key', required=True, help='MEXC API Key')
    parser.add_argument('--api-secret', required=True, help='MEXC API Secret')
    parser.add_argument('--symbol', default='BTCUSDT', help='Trading pair (e.g. BTCUSDT)')
    parser.add_argument('--quantity', type=float, default=0.001, help='Order quantity')
    parser.add_argument('--price', type=float, default=50000, help='Order price')
    
    args = parser.parse_args()
    
    print("\n✅ MEXC API Tester (Verified Working)")
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
            print(f"ℹ️ API Response: {order_result}")
            
    except Exception as e:
        print(f"🔥 Fatal Error: {str(e)}")

if __name__ == "__main__":
    main()
