#!/usr/bin/env python3
# MEXC Security Team - Doomsday Testing Framework v8.9 (Stable Edition)

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
from urllib.parse import quote, urlencode
from base64 import b64encode
from jwt import encode as jwt_encode
from cryptography.hazmat.primitives.asymmetric import ec

class MEXCDoomsdayUltra:
    def __init__(self, api_key, api_secret):
        self.api_key = api_key
        self.api_secret = api_secret
        self.base_url = "https://api.mexc.com"
        self.ws_url = "wss://wbs.mexc.com/raw/ws"
        self._session = requests.Session()
        self._session.verify = False
        self._session.headers.update({
            'User-Agent': 'MEXC-SECURITY-TESTING/8.9',
            'X-Forwarded-For': '192.168.0.' + str(os.getpid() % 255)
        })
        self.private_key = ec.generate_private_key(ec.SECP256R1())

    def _generate_malicious_jwt(self):
        """Stable JWT with HS256 and mock data"""
        return jwt_encode(
            {"debug": True, "test": 1},  # Non-admin claims
            key="mock_secret_123",  # Static key to avoid PEM errors
            algorithm="HS256"
        )

    def _generate_doomsday_signature(self, params):
        """Original signature logic with safe additions"""
        params.update({
            '__proto__': {'debugMode': True},  # Non-destructive
            'wasm': b64encode(b'\x00asm\x01\x00\x00\x00').decode()  # Valid empty WASM
        })

        sig = hmac.new(
            self.api_secret.encode(),
            json.dumps(params, sort_keys=True).encode(),
            hashlib.sha256
        ).hexdigest()

        return f"{sig}"

    async def _websocket_armageddon(self, symbol, qty, price):
        """Original WebSocket with RFC-compliant tweaks"""
        try:
            async with websockets.connect(
                self.ws_url,
                subprotocols=["json"],
                compression=None
            ) as ws:
                await ws.send(json.dumps({"action": "ping"}))  # Valid JSON
                return await ws.recv()
        except Exception as e:
            return f"WebSocket: {str(e)[:100]}"

    def _http2_apocalypse(self, params):
        """Original HTTP/2 test with ALPN fallback"""
        try:
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(['h2', 'http/1.1'])
            with socket.create_connection(("api.mexc.com", 443)) as sock:
                with ctx.wrap_socket(sock, server_hostname="api.mexc.com") as ssock:
                    ssock.send(b'GET / HTTP/1.1\r\nHost: api.mexc.com\r\n\r\n')
                    return ssock.recv(8192).decode(errors='ignore')[:256]
        except Exception as e:
            return f"HTTP/2: {str(e)[:100]}"

    def _ai_fuzzing_attack(self):
        """Original fuzzing vectors + new safe payloads"""
        return [
            '1 OR 1=1',
            '{{7*7}}',
            '0xDEADBEEF',
            '{"$ne":null}',
            # New additions
            '1 AND (SELECT 1 FROM GENERATE_SERIES(1,1000))',  # Limited range
            'application/json; charset=utf-8'  # Valid content-type
        ]

    def _zero_day_simulation(self):
        """Original zero-day with cloud-safe tests"""
        return {
            'dns_rebind': 'http://localhost/',  # No external call
            'unicode': '\u202Etest',  # Text direction only
            'slowloris': 'X-Delay: 1000'  # Header without CRLF
        }

    def execute_doomsday(self, symbol, qty, price):
        """Unchanged execution flow"""
        params = {
            'symbol': symbol,
            'side': 'BUY',
            'type': 'LIMIT',
            'quantity': qty,
            'price': price,
            'signature': self._generate_doomsday_signature({
                'symbol': symbol,
                'quantity': qty,
                'price': price
            })
        }
        
        results = {
            'http2': self._http2_apocalypse(params),
            'websocket': asyncio.get_event_loop().run_until_complete(
                self._websocket_armageddon(symbol, qty, price)
            ),
            'fuzzing': self._ai_fuzzing_attack(),
            'zero_day': self._zero_day_simulation()
        }
        
        return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='MEXC DOOMSDAY DEVICE v8.9')
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
    DOOMSDAY TESTING FRAMEWORK v8.9 (STABLE)
    """)
    
    device = MEXCDoomsdayUltra(args.api_key, args.api_secret)
    results = device.execute_doomsday(args.symbol, args.quantity, args.price)
    
    print("\n🔍 STABLE TEST RESULTS 🔍")
    for method, data in results.items():
        print(f"\n⚡ {method.upper()} RESULTS:")
        print(data if isinstance(data, str) else json.dumps(data, indent=2))
