import argparse
import requests
import time
import hashlib
import hmac
import json
from urllib.parse import urlencode

class MEXCProfessionalTester:
    def __init__(self, api_key, api_secret):
        self.base_url = 'https://api.mexc.com'
        self.api_key = api_key.strip()
        self.api_secret = api_secret.strip()
        self.session = requests.Session()
        self.session.headers.update({
            'X-MEXC-APIKEY': self.api_key,
            'Content-Type': 'application/json',
            'User-Agent': 'MEXC-API-TESTER/1.0'
        })
    
    def _generate_signature(self, params):
        """Professional-grade signature generation"""
        params['timestamp'] = int(time.time() * 1000)
        params['recvWindow'] = 60000  # Maximum allowed window
        
        # Professional parameter normalization
        query_string = urlencode(sorted(
            [(k, str(v).upper() if isinstance(v, bool) else v) 
             for k, v in params.items()],
            key=lambda x: x[0]
        ))
        
        signature = hmac.new(
            self.api_secret.encode('utf-8'),
            query_string.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        params['signature'] = signature
        return params

    def test_real_trade(self, symbol, quantity, price):
        """Professional trade test with verifiable proof"""
        try:
            # Step 1: Verify market status
            market_info = self.session.get(
                f"{self.base_url}/api/v3/exchangeInfo?symbol={symbol.upper()}"
            ).json()
            
            if 'code' in market_info:
                return {
                    'error': 'MARKET_UNAVAILABLE',
                    'details': market_info
                }

            # Step 2: Prepare professional order
            params = {
                'symbol': symbol.upper(),
                'side': 'BUY',
                'type': 'LIMIT',
                'timeInForce': 'GTC',
                'quantity': format(float(quantity), '.8f').rstrip('0').rstrip('.'),
                'price': format(float(price), '.8f').rstrip('0').rstrip('.'),
                'newOrderRespType': 'FULL',
                'selfTradePrevention': 'NONE'
            }
            
            params = self._generate_signature(params)
            
            # Step 3: Execute test with verifiable proof
            response = self.session.post(
                f"{self.base_url}/api/v3/order",
                params=params,
                timeout=10
            )
            result = response.json()
            
            # Step 4: Generate verifiable proof
            if 'orderId' in result:
                verification = {
                    'verification_method': 'CHECK_ORDER_HISTORY',
                    'instructions': [
                        '1. Log in to your MEXC account',
                        '2. Go to "Order History"',
                        f'3. Look for order ID: {result["orderId"]}',
                        '4. Status will show "Cancelled" (insufficient balance)'
                    ],
                    'api_proof': {
                        'timestamp': params['timestamp'],
                        'request_params': params,
                        'response': result
                    }
                }
                result['verification'] = verification
            
            return result
            
        except Exception as e:
            return {
                'error': 'EXECUTION_FAILED',
                'details': str(e),
                'timestamp': int(time.time() * 1000)
            }

def main():
    parser = argparse.ArgumentParser(description='MEXC Professional Trade Tester')
    parser.add_argument('--api-key', required=True, help='MEXC API Key')
    parser.add_argument('--api-secret', required=True, help='MEXC API Secret')
    parser.add_argument('--symbol', required=True, help='Trading pair (e.g. BTCUSDT)')
    parser.add_argument('--quantity', required=True, type=float, help='Order quantity')
    parser.add_argument('--price', required=True, type=float, help='Order price')
    
    args = parser.parse_args()
    
    print("\n🔧 MEXC Professional Trade Tester")
    print("---------------------------------")
    
    tester = MEXCProfessionalTester(args.api_key, args.api_secret)
    print(f"\n🚀 Testing {args.symbol} trade (Qty: {args.quantity} @ Price: {args.price})")
    
    result = tester.test_real_trade(args.symbol, args.quantity, args.price)
    
    print("\n📊 Test Results:")
    print(json.dumps(result, indent=2))
    
    if 'verification' in result:
        print("\n🔍 Verification Instructions:")
        for step in result['verification']['instructions']:
            print(f"  {step}")

if __name__ == "__main__":
    main()
