import argparse
import requests
import time
import hashlib
import hmac
import sys
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
    
    def _debug_print_request(self, method, endpoint, params):
        """Print debug information for request signing"""
        print("\n🔧 DEBUG: Request Details")
        print(f"URL: {method} {self.base_url}{endpoint}")
        print("Params before signing:")
        for k, v in sorted(params.items()):
            print(f"  {k}: {v}")
        
        query_string = urlencode(sorted(params.items()))
        print(f"\nQuery String: {query_string}")
        
        signing_key = self.api_secret.encode('utf-8')
        print(f"Signing Key: {signing_key}")
        
        signature = hmac.new(
            signing_key,
            query_string.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        print(f"Generated Signature: {signature}")
        return signature
    
    def _make_request(self, method, endpoint, params=None):
        """Ultra-reliable request handler with debug output"""
        params = params or {}
        params['timestamp'] = int(time.time() * 1000)
        params['recvWindow'] = 50000
        
        # Generate signature with debug output
        signature = self._debug_print_request(method, endpoint, params)
        params['signature'] = signature
        
        try:
            if method == 'GET':
                response = self.session.get(
                    f"{self.base_url}{endpoint}",
                    params=params,
                    timeout=30
                )
            else:
                response = self.session.post(
                    f"{self.base_url}{endpoint}",
                    params=params,
                    timeout=30
                )
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            error_info = {
                'error': str(e),
                'request_url': e.request.url if hasattr(e, 'request') else None,
                'status_code': e.response.status_code if hasattr(e, 'response') else None,
                'response_text': e.response.text if hasattr(e, 'response') else None
            }
            return {'error': error_info}

    def get_balances(self):
        """Get account balances with debug output"""
        print("\n🔍 Starting balance check...")
        result = self._make_request('GET', '/api/v3/account')
        
        if 'error' in result:
            print("\n❌ Balance Check Failed")
            self._print_error_details(result['error'])
            return None
        
        print("\n✅ Balance Check Successful")
        return result

    def test_order(self, symbol, quantity, price):
        """Place test order with full debug output"""
        print(f"\n💸 Attempting test order: {quantity} {symbol} @ {price}")
        params = {
            'symbol': symbol,
            'side': 'BUY',
            'type': 'LIMIT',
            'quantity': quantity,
            'price': price,
        }
        result = self._make_request('POST', '/api/v3/order/test', params)
        
        if 'error' in result:
            print("\n❌ Order Placement Failed")
            self._print_error_details(result['error'])
            return None
        
        return result
    
    def _print_error_details(self, error):
        """Print detailed error information"""
        if isinstance(error, dict):
            print(f"HTTP Status: {error.get('status_code', 'Unknown')}")
            print(f"Error Message: {error.get('error', 'Unknown error')}")
            print(f"Request URL: {error.get('request_url', 'Unknown')}")
            print("Raw Response:")
            print(error.get('response_text', 'None'))
        else:
            print(f"Error: {error}")

def main():
    parser = argparse.ArgumentParser(description='MEXC Ultimate Tester')
    parser.add_argument('--api-key', required=True, help='MEXC API Key')
    parser.add_argument('--api-secret', required=True, help='MEXC API Secret')
    parser.add_argument('--symbol', default='BTCUSDT', help='Trading pair')
    parser.add_argument('--quantity', type=float, default=0.001, help='Order quantity')
    parser.add_argument('--price', type=float, default=84432, help='Order price')
    parser.add_argument('--debug', action='store_true', help='Enable verbose debug output')
    
    args = parser.parse_args()
    
    print("\n🔐 MEXC Ultimate API Tester")
    print("-------------------------")
    print(f"Timestamp: {int(time.time() * 1000)}")
    print(f"System Time: {time.ctime()}")
    
    tester = MEXCTester(args.api_key, args.api_secret)
    
    # Verify API connection
    balances = tester.get_balances()
    if not balances:
        print("\n🛑 Cannot proceed without successful authentication")
        sys.exit(1)
    
    usdt_balance = next((float(b['free']) for b in balances['balances'] if b['asset'] == 'USDT'), 0.0)
    print(f"Current USDT Balance: {usdt_balance}")
    
    # Attempt test order
    order_result = tester.test_order(args.symbol, args.quantity, args.price)
    if not order_result:
        sys.exit(1)
    
    if 'code' in order_result:
        print(f"\nℹ️ Order Response: {order_result.get('msg')}")
        if order_result.get('code') == -2010:
            print("✅ Normal behavior: Insufficient balance detected")
        else:
            print(f"⚠️ Unexpected error code: {order_result.get('code')}")

if __name__ == "__main__":
    main()
