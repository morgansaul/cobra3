#!/usr/bin/env python3
# MEXC Futures Ghost Trading Framework v12.3 (Multi-Endpoint)

import hmac
import hashlib
import requests
import time
import uuid
import json
from urllib.parse import urlencode

class MEXCRobustTrader:
    def __init__(self, api_key, api_secret):
        self.api_key = api_key
        self.api_secret = api_secret
        self.endpoints = [
            "https://contract.mexc.com",  # Primary
            "https://futures.mexc.com",   # Failover 1
            "https://api.mexc.com"        # Failover 2
        ]
        self.timeout = 8  # Reduced timeout for faster failover
        self.max_retries = 3

    def _generate_signature(self, params):
        """Optimized signature generation"""
        params['timestamp'] = int(time.time() * 1000)
        query = urlencode(sorted(params.items()))
        return hmac.new(
            self.api_secret.encode('utf-8'),
            query.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

    def _try_endpoint(self, endpoint, params):
        """Attempt a single endpoint with error handling"""
        try:
            response = requests.post(
                f"{endpoint}/api/v1/private/order/submit",
                json=params,
                headers={
                    'ApiKey': self.api_key,
                    'Content-Type': 'application/json',
                    'X-Request-ID': str(uuid.uuid4())
                },
                timeout=self.timeout,
                verify=False
            )
            return response.json() if response.content else None
        except:
            return None

    def execute_trade(self, symbol):
        """Multi-endpoint execution with smart retries"""
        params = {
            'symbol': symbol.replace('-', '_').upper(),
            'price': str(round(time.time() % 10000, 2)),
            'vol': '1',
            'side': '1',
            'type': '1',
            'openType': '1',
            'externalOid': f'MEXC_{int(time.time())}',
            'signature': ''  # Will be set per attempt
        }

        for attempt in range(self.max_retries):
            for endpoint in self.endpoints:
                start_time = time.time()
                params['signature'] = self._generate_signature(params)
                result = self._try_endpoint(endpoint, params)
                
                if result:
                    elapsed = time.time() - start_time
                    if result.get('success'):
                        return {
                            'status': 'SUCCESS',
                            'endpoint': endpoint,
                            'execution_time': f"{elapsed:.2f}s",
                            'order_id': result.get('data', {}).get('orderId')
                        }
                    return {
                        'status': 'API_ERROR',
                        'endpoint': endpoint,
                        'execution_time': f"{elapsed:.2f}s",
                        'code': result.get('code'),
                        'message': result.get('message')
                    }

                time.sleep(1)  # Brief pause between attempts

        return {
            'status': 'CONNECTION_FAILED',
            'attempts': self.max_retries,
            'last_error': 'All endpoints timed out'
        }

if __name__ == "__main__":
    import argparse
    import warnings
    warnings.filterwarnings("ignore")  # Disable SSL warnings
    
    parser = argparse.ArgumentParser(description='MEXC Ghost Trader v12.3')
    parser.add_argument('--api-key', required=True)
    parser.add_argument('--api-secret', required=True)
    parser.add_argument('--symbol', default='BTC-USDT')
    args = parser.parse_args()

    print("""
    ███╗   ███╗███████╗██╗  ██╗ ██████╗    ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
    ████╗ ████║██╔════╝╚██╗██╔╝██╔════╝    ██╔══██╗██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
    ██╔████╔██║█████╗   ╚███╔╝ ██║  ███╗   ██║  ██║███████║██║   ██║███████╗   ██║   
    ██║╚██╔╝██║██╔══╝   ██╔██╗ ██║   ██║   ██║  ██║██╔══██║██║   ██║╚════██║   ██║   
    ██║ ╚═╝ ██║███████╗██╔╝ ██╗╚██████╔╝   ██████╔╝██║  ██║╚██████╔╝███████║   ██║   
    ╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   
    GHOST TRADING FRAMEWORK v12.3 (MULTI-ENDPOINT)
    """)

    trader = MEXCRobustTrader(args.api_key, args.api_secret)
    print(f"\n⚡ Executing Ghost Trade on {args.symbol}...")
    
    result = trader.execute_trade(args.symbol)
    print("\n🔥 TRADE EXECUTION REPORT:")
    print(json.dumps(result, indent=2))
    
    if result['status'] == 'SUCCESS':
        print(f"\n💀 Order {result['order_id']} placed via {result['endpoint']}!")
    else:
        print("\n❌ Execution failed. Try these steps:")
        print("1. Check your internet connection/firewall")
        print("2. Test API connectivity: ping contract.mexc.com")
        print("3. Contact MEXC support if all endpoints fail")
