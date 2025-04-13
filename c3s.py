#!/usr/bin/env python3
# Universal Exchange Exploit Framework v12.0

import hmac
import hashlib
import requests
import time
import json
import logging
from urllib.parse import urlencode, quote
from collections import OrderedDict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

class UniversalExploitFramework:
    def __init__(self, api_key, api_secret, base_url, endpoints, param_order, headers):
        """
        Args:
            base_url:   Exchange API base URL (e.g., "https://api.exchange.com")
            endpoints:  Dict of endpoint paths (e.g., {"order": "/api/orders"})
            param_order: List defining signature parameter order
            headers:    Dict of required HTTP headers
        """
        self.api_key = api_key
        self.api_secret = api_secret
        self.base_url = base_url.rstrip('/')
        self.endpoints = endpoints
        self.param_order = param_order
        self._session = requests.Session()
        self._session.headers.update(headers)
        self.timeout = 30

    def _generate_signature(self, params):
        """Universal signature generation"""
        params['timestamp'] = int(time.time() * 1000)
        
        # Enforce parameter order from config
        ordered_params = OrderedDict()
        for param in self.param_order:
            if param in params:
                ordered_params[param] = params[param]
        
        query = urlencode(ordered_params, quote_via=quote)
        return hmac.new(
            self.api_secret.encode(),
            query.encode(),
            hashlib.sha256
        ).hexdigest()

    def _api_request(self, endpoint_key, params=None, method='POST'):
        """Universal API request handler"""
        endpoint = self.endpoints.get(endpoint_key)
        if not endpoint:
            return {"error": f"Unknown endpoint: {endpoint_key}"}
        
        params = params or {}
        if method == 'POST':
            params['signature'] = self._generate_signature(params)
            try:
                response = self._session.post(
                    f"{self.base_url}{endpoint}",
                    json=params,
                    timeout=self.timeout
                )
                return response.json()
            except Exception as e:
                return {"error": str(e)}
        else:
            params['signature'] = self._generate_signature(params)
            try:
                response = self._session.get(
                    f"{self.base_url}{endpoint}",
                    params=params,
                    timeout=self.timeout
                )
                return response.json()
            except Exception as e:
                return {"error": str(e)}

    def execute_attack(self, symbol):
        """Execute standard attack sequence"""
        results = {}
        
        # 1. Leverage manipulation
        results['leverage'] = self._api_request(
            'leverage',
            {'symbol': symbol, 'leverage': 100}
        )
        
        # 2. Place test order
        results['order'] = self._api_request(
            'order',
            {'symbol': symbol, 'side': 'BUY', 'type': 'MARKET', 'quantity': 1}
        )
        
        # 3. Verify position
        results['position'] = self._api_request(
            'position',
            {'symbol': symbol},
            method='GET'
        )
        
        return results

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Universal Exchange Exploit Framework')
    
    # Required credentials
    parser.add_argument('--api-key', required=True, help='Exchange API key')
    parser.add_argument('--api-secret', required=True, help='Exchange API secret')
    
    # Exchange configuration
    parser.add_argument('--base-url', required=True, help='Exchange API base URL')
    parser.add_argument('--leverage-endpoint', required=True, help='Leverage change endpoint path')
    parser.add_argument('--order-endpoint', required=True, help='Order placement endpoint path')
    parser.add_argument('--position-endpoint', required=True, help='Position check endpoint path')
    
    # Signature configuration
    parser.add_argument('--param-order', required=True, 
                        help='Comma-separated parameter order for signatures (e.g., "symbol,leverage,timestamp")')
    
    # Target parameters
    parser.add_argument('--symbol', default='BTCUSDT', help='Trading pair symbol')
    
    args = parser.parse_args()

    # Configure exchange
    exploit = UniversalExploitFramework(
        api_key=args.api_key,
        api_secret=args.api_secret,
        base_url=args.base_url,
        endpoints={
            'leverage': args.leverage_endpoint,
            'order': args.order_endpoint,
            'position': args.position_endpoint
        },
        param_order=[p.strip() for p in args.param_order.split(',')],
        headers={'X-MBX-APIKEY': args.api_key}
    )

    # Execute attack
    try:
        print(f"\n⚡ Targeting {args.base_url} with symbol {args.symbol}")
        results = exploit.execute_attack(args.symbol)
        print("\n🔥 EXPLOIT RESULTS 🔥")
        print(json.dumps(results, indent=2))
    except Exception as e:
        print(f"\n⛔ EXECUTION FAILED: {str(e)}")
