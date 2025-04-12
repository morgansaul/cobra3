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
        """MEXC-compatible signature generation"""
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

    def get_balance(self, currency='USDT'):
        """Get account balance"""
        params = self._sign_request({})
        response = self.session.get(
            f"{self.base_url}/api/v3/account",
            params=params
        ).json()
        return next((float(b['free']) for b in response['balances'] if b['asset'] == currency), 0.0)

    def get_valid_symbols(self):
        """Get list of valid trading symbols"""
        response = self.session.get(f"{self.base_url}/api/v3/exchangeInfo").json()
        return [s['symbol'] for s in response['symbols']]

    def place_real_order(self, symbol, quantity, price):
        """Place a real order with MEXC's exact symbol requirements"""
        params = {
            'symbol': symbol.upper().replace('-', ''),  # MEXC format
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

    def test_vulnerability(self, quantity, price):
        print("\n🔍 Starting vulnerability test")
        
        # 1. Verify valid symbols
        valid_symbols = self.get_valid_symbols()
        btc_symbol = next((s for s in valid_symbols if 'BTCUSDT' in s), None)
        if not btc_symbol:
            print("❌ No valid BTC trading pair found")
            return False
        print(f"Using trading pair: {btc_symbol}")

        # 2. Verify zero balance
        balance = self.get_balance()
        print(f"Current USDT Balance: {balance}")
        if balance > 0:
            print("⚠️ Account has positive balance - withdraw funds first")
            return False

        # 3. Attempt real order
        print(f"Attempting order: BUY {quantity} {btc_symbol} @ {price}")
        try:
            result = self.place_real_order(btc_symbol, quantity, price)
            
            if 'code' in result:
                if result['code'] == -2010:
                    print("✅ Exchange properly blocked insufficient balance")
                    return False
                print(f"❌ Error: {result['msg']} (code {result['code']})")
                return False
            
            print("🚨 CRITICAL: Order executed with zero balance!")
            print(f"Order ID: {result['orderId']}")
            return True
            
        except Exception as e:
            print(f"⚠️ Exception: {str(e)}")
            return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='MEXC Vulnerability Tester')
    parser.add_argument('--api-key', required=True)
    parser.add_argument('--api-secret', required=True)
    parser.add_argument('--quantity', type=float, default=0.001)
    parser.add_argument('--price', type=float, default=84432)
    
    args = parser.parse_args()
    
    tester = MEXCTester(args.api_key, args.api_secret)
    
    if tester.test_vulnerability(args.quantity, args.price):
        print("\n💥 VULNERABILITY CONFIRMED - REPORT IMMEDIATELY")
    else:
        print("\n🔒 No vulnerability detected")
