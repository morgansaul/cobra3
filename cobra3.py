import argparse
import requests
import time
import hashlib
import hmac
from urllib.parse import urlencode

class MEXCValidator:
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

    def get_balance(self, currency='USDT'):
        params = self._sign_request({})
        response = self.session.get(
            f"{self.base_url}/api/v3/account",
            params=params
        ).json()
        return next((float(b['free']) for b in response['balances'] if b['asset'] == currency), 0.0)

    def place_real_order(self, symbol, quantity, price):
        """Place a REAL order to verify vulnerability"""
        params = {
            'symbol': symbol,
            'side': 'BUY',
            'type': 'LIMIT',
            'quantity': quantity,
            'price': price,
            'newOrderRespType': 'FULL'
        }
        params = self._sign_request(params)
        return self.session.post(
            f"{self.base_url}/api/v3/order",
            params=params
        ).json()

    def test_vulnerability(self, symbol, quantity, price):
        print("\n🔍 Starting REAL vulnerability test")
        
        # 1. Verify zero balance
        balance = self.get_balance()
        print(f"Current USDT Balance: {balance}")
        if balance > 0:
            print("⚠️ Account has positive balance - withdraw funds first")
            return False

        # 2. Attempt real order
        print(f"Attempting REAL order: BUY {quantity} {symbol} @ {price}")
        try:
            result = self.place_real_order(symbol, quantity, price)
            
            if 'code' in result:
                if result['code'] == -2010:
                    print("✅ Exchange properly blocked insufficient balance")
                    return False
                print(f"❌ Unexpected error: {result['msg']}")
                return False
            
            print("🚨 CRITICAL: Order executed with zero balance!")
            print(f"Order ID: {result['orderId']}")
            print("Immediately check your balance and report this vulnerability")
            return True
            
        except Exception as e:
            print(f"⚠️ Error: {str(e)}")
            return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='MEXC Real Order Tester')
    parser.add_argument('--api-key', required=True)
    parser.add_argument('--api-secret', required=True)
    parser.add_argument('--symbol', default='BTCUSDT')
    parser.add_argument('--quantity', type=float, default=0.001)
    parser.add_argument('--price', type=float, default=84432)
    
    args = parser.parse_args()
    
    tester = MEXCValidator(args.api_key, args.api_secret)
    
    if tester.test_vulnerability(args.symbol, args.quantity, args.price):
        print("\n💥 VULNERABILITY CONFIRMED - REPORT IMMEDIATELY")
    else:
        print("\n🔒 No vulnerability detected")
