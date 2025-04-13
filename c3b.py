#!/usr/bin/env python3
# Bybit API Security Testing Tool (For Authorized Testing Only)

import hmac
import hashlib
import requests
import time
import json
import logging
from urllib.parse import urlencode, quote
from collections import OrderedDict
from typing import Dict, Optional, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

class BybitSecurityTester:
    def __init__(self, api_key: str, api_secret: str, testnet: bool = True):
        """
        Initialize Bybit API tester with proper authentication
        
        Args:
            api_key: Your Bybit API key
            api_secret: Your Bybit API secret
            testnet: Whether to use testnet (default: True for safety)
        """
        self.api_key = api_key
        self.api_secret = api_secret
        self.base_url = "https://api-testnet.bybit.com" if testnet else "https://api.bybit.com"
        self._session = requests.Session()
        self.timeout = 30
        self.recv_window = "5000"
        
        # Required headers for Bybit API
        self._session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-BAPI-API-KEY': self.api_key,
            'X-BAPI-RECV-WINDOW': self.recv_window,
            'X-BAPI-SIGN-TYPE': '2'
        })

    def _generate_signature(self, params: Dict) -> str:
        """Generate Bybit-compatible HMAC signature"""
        timestamp = str(int(time.time() * 1000))
        
        # Prepare parameter string
        param_str = ""
        if params:
            ordered_params = OrderedDict(sorted(params.items()))
            param_str = urlencode(ordered_params, quote_via=quote)
        
        # Create signature payload
        signature_payload = f"{timestamp}{self.api_key}{self.recv_window}{param_str}"
        
        return hmac.new(
            self.api_secret.encode('utf-8'),
            signature_payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

    def _api_request(
        self,
        endpoint: str,
        params: Optional[Dict] = None,
        method: str = 'GET'
    ) -> Dict:
        """
        Make authenticated API request to Bybit
        
        Args:
            endpoint: API endpoint path (e.g., "/v5/order/create")
            params: Dictionary of request parameters
            method: HTTP method (GET/POST)
        
        Returns:
            Dictionary containing API response or error
        """
        params = params or {}
        timestamp = str(int(time.time() * 1000))
        
        try:
            # Add required authentication headers
            self._session.headers.update({
                'X-BAPI-TIMESTAMP': timestamp,
                'X-BAPI-SIGN': self._generate_signature(params)
            })
            
            url = f"{self.base_url}{endpoint}"
            
            if method.upper() == 'POST':
                response = self._session.post(
                    url,
                    json=params,
                    timeout=self.timeout
                )
            else:
                response = self._session.get(
                    url,
                    params=params,
                    timeout=self.timeout
                )
            
            # Parse response
            response_data = response.json()
            
            # Check for API errors
            if 'retCode' in response_data and response_data['retCode'] != 0:
                logging.error(f"API Error {response_data['retCode']}: {response_data.get('retMsg', 'Unknown error')}")
                return {
                    'error': True,
                    'code': response_data['retCode'],
                    'message': response_data.get('retMsg')
                }
                
            return response_data
            
        except json.JSONDecodeError:
            logging.error(f"Invalid JSON response: {response.text}")
            return {'error': 'Invalid JSON response'}
        except Exception as e:
            logging.error(f"Request failed: {str(e)}")
            return {'error': str(e)}

    def test_leverage(self, symbol: str, leverage: int = 10) -> Dict:
        """Test leverage change functionality"""
        return self._api_request(
            "/v5/position/set-leverage",
            {
                'category': 'linear',
                'symbol': symbol,
                'buyLeverage': str(leverage),
                'sellLeverage': str(leverage)
            },
            method='POST'
        )

    def test_order(
        self,
        symbol: str,
        side: str = 'Buy',
        qty: Union[str, float] = '0.001'
    ) -> Dict:
        """Test order placement"""
        return self._api_request(
            "/v5/order/create",
            {
                'category': 'linear',
                'symbol': symbol,
                'side': side,
                'orderType': 'Market',
                'qty': str(qty)
            },
            method='POST'
        )

    def test_position(self, symbol: str) -> Dict:
        """Test position query"""
        return self._api_request(
            "/v5/position/list",
            {'category': 'linear', 'symbol': symbol},
            method='GET'
        )

    def run_security_tests(self, symbol: str) -> Dict:
        """Execute complete test sequence with safety checks"""
        results = {}
        
        # 1. Test leverage change
        logging.info(f"Testing leverage change for {symbol}")
        results['leverage'] = self.test_leverage(symbol)
        time.sleep(1)  # Rate limit protection
        
        # 2. Test market order
        logging.info(f"Testing order placement for {symbol}")
        results['order'] = self.test_order(symbol)
        time.sleep(1)
        
        # 3. Test position query
        logging.info(f"Testing position query for {symbol}")
        results['position'] = self.test_position(symbol)
        
        return results

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Bybit API Security Testing Tool (Authorized Use Only)',
        epilog='WARNING: Only use with explicit permission from Bybit'
    )
    
    # Required credentials
    parser.add_argument('--api-key', required=True, help='Bybit API key')
    parser.add_argument('--api-secret', required=True, help='Bybit API secret')
    
    # Testing parameters
    parser.add_argument('--symbol', default='BTCUSDT', help='Trading pair symbol')
    parser.add_argument('--prod', action='store_true', help='Use production API (DANGER)')
    
    args = parser.parse_args()

    # Initialize tester
    tester = BybitSecurityTester(
        api_key=args.api_key,
        api_secret=args.api_secret,
        testnet=not args.prod
    )

    # Execute tests
    try:
        print(f"\n🔒 Starting authorized security tests for {args.symbol}")
        print(f"🌐 Using {'PRODUCTION' if args.prod else 'TESTNET'} environment")
        
        results = tester.run_security_tests(args.symbol)
        
        print("\n🔍 TEST RESULTS:")
        print(json.dumps(results, indent=2))
        
    except Exception as e:
        print(f"\n❌ TEST FAILED: {str(e)}")
        logging.exception("Critical error during testing")
