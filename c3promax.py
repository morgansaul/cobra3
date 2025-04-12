#!/usr/bin/env python3
# MEXC Security Testing Framework v8.9 (Robust Edition)

import hmac
import hashlib
import requests
import socket
import ssl
import argparse
import json
import asyncio
import websockets
import os
import dns.resolver
from urllib.parse import urlparse
from base64 import b64encode
from jwt import encode as jwt_encode
from cryptography.hazmat.primitives.asymmetric import ec

class MEXCSecurityTester:
    def __init__(self, api_key, api_secret):
        self.api_key = api_key
        self.api_secret = api_secret
        self.base_domain = "mexc.com"
        self._resolve_endpoints()
        self._session = requests.Session()
        self._session.verify = False
        self.private_key = ec.generate_private_key(ec.SECP256R1())

    def _resolve_endpoints(self):
        """Resolve all endpoints with proper DNS lookup"""
        try:
            # Resolve API endpoint
            answers = dns.resolver.resolve(f'api.{self.base_domain}', 'A')
            self.api_url = f"https://{answers[0].address}"
            
            # Resolve WebSocket endpoint
            answers = dns.resolver.resolve(f'ws.{self.base_domain}', 'A')
            self.ws_url = f"wss://{answers[0].address}/ws"
        except Exception as e:
            print(f"DNS Resolution Failed: {e}")
            self.api_url = f"https://api.{self.base_domain}"
            self.ws_url = f"wss://ws.{self.base_domain}/ws"

    def _generate_jwt(self):
        return jwt_encode(
            {"test": "security_scan"},
            key=self.private_key,
            algorithm="ES256"
        )

    async def _test_websocket(self):
        """Test WebSocket with connection validation"""
        try:
            async with websockets.connect(
                self.ws_url,
                timeout=10,
                ping_interval=None
            ) as ws:
                # Send valid ping first
                await ws.send(json.dumps({"op": "ping"}))
                response = await asyncio.wait_for(ws.recv(), timeout=5)
                return f"WebSocket Connected: {response[:100]}..."
        except Exception as e:
            return f"WebSocket Failed: {str(e)}"

    def _test_http(self):
        """Test basic HTTP connectivity"""
        try:
            response = self._session.get(
                f"{self.api_url}/api/v3/time",
                timeout=5
            )
            return f"HTTP {response.status_code}: {response.text[:100]}..."
        except Exception as e:
            return f"HTTP Failed: {str(e)}"

    def _test_https(self):
        """Test HTTPS with certificate verification"""
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((urlparse(self.api_url).hostname, 443)) as sock:
                with ctx.wrap_socket(sock, server_hostname=urlparse(self.api_url).hostname) as ssock:
                    cert = ssock.getpeercert()
                    return f"HTTPS OK - Cert Valid Until: {cert['notAfter']}"
        except Exception as e:
            return f"HTTPS Failed: {str(e)}"

    def _generate_test_vectors(self):
        """Generate safe test patterns"""
        return {
            'sql_injection': ["' OR 1=1-- -", "admin'--"],
            'xss': ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
            'path_traversal': ["../../../etc/passwd", "%2e%2e%2fetc%2fpasswd"],
            'prototype_pollution': ["__proto__[test]=true", "constructor[prototype][test]=true"]
        }

    def run_tests(self, symbol, qty, price):
        """Run all security tests"""
        results = {
            'connectivity': {
                'dns_resolution': self._resolve_endpoints(),
                'http_test': self._test_http(),
                'https_test': self._test_https(),
                'websocket_test': asyncio.get_event_loop().run_until_complete(self._test_websocket())
            },
            'test_vectors': self._generate_test_vectors(),
            'jwt_test': self._generate_jwt()[:50] + "...",
            'config': {
                'symbol': symbol,
                'quantity': qty,
                'price': price
            }
        }
        return results

def main():
    parser = argparse.ArgumentParser(description='MEXC Security Scanner v8.9')
    parser.add_argument('--api-key', required=True)
    parser.add_argument('--api-secret', required=True)
    parser.add_argument('--symbol', default='BTCUSDT')
    parser.add_argument('--quantity', type=float, default=0.001)
    parser.add_argument('--price', type=float, default=90000)
    args = parser.parse_args()
    
    print(f"""
    ███╗   ███╗███████╗██╗  ██╗ ██████╗ 
    ████╗ ████║██╔════╝╚██╗██╔╝██╔════╝ 
    ██╔████╔██║█████╗   ╚███╔╝ ██║  ███╗
    ██║╚██╔╝██║██╔══╝   ██╔██╗ ██║   ██║
    ██║ ╚═╝ ██║███████╗██╔╝ ██╗╚██████╔╝
    ╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ 
    SECURITY TESTING FRAMEWORK v8.9
    Testing {args.symbol} at {args.price}
    """)
    
    try:
        tester = MEXCSecurityTester(args.api_key, args.api_secret)
        results = tester.run_tests(args.symbol, args.quantity, args.price)
        
        print("\n🔍 SECURITY TEST RESULTS 🔍")
        print(json.dumps(results, indent=2))
    except Exception as e:
        print(f"\n❌ Framework Error: {str(e)}")

if __name__ == "__main__":
    main()
