import os
from imapclient import IMAPClient
from imapclient.exceptions import LoginError
import sys
import re
from email import message_from_bytes
from email.header import decode_header
from email.utils import parsedate_to_datetime
from datetime import datetime, date
import json
import csv
import hashlib
from pathlib import Path
import base64
import mimetypes
import getpass
import socket
import logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import AI analyzer if available
try:
    from ai_expense_analyzer import analyze_with_ai as ai_analyze, summarize_openai_usage
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    summarize_openai_usage = None
    print("Warning: AI analyzer not available")

# Import OAuth helpers if available
try:
    from oauth_client import start_oauth_flow as start_google_oauth_flow
    GOOGLE_OAUTH_AVAILABLE = True
except ImportError:
    start_google_oauth_flow = None
    GOOGLE_OAUTH_AVAILABLE = False

try:
    from oauth_microsoft import start_microsoft_oauth_flow
    MICROSOFT_OAUTH_AVAILABLE = True
except ImportError:
    start_microsoft_oauth_flow = None
    MICROSOFT_OAUTH_AVAILABLE = False

OAUTH_AVAILABLE = GOOGLE_OAUTH_AVAILABLE or MICROSOFT_OAUTH_AVAILABLE


def autodetect_imap_server(email: str):
    """Return (server, port) tuple based on email domain if possible."""
    if not email or "@" not in email:
        return None, None

    domain = email.split("@", 1)[1].lower()

    known_providers = {
        "gmail.com": ("imap.gmail.com", 993),
        "googlemail.com": ("imap.gmail.com", 993),
        "outlook.com": ("imap-mail.outlook.com", 993),
        "hotmail.com": ("imap-mail.outlook.com", 993),
        "live.com": ("imap-mail.outlook.com", 993),
        "office365.com": ("outlook.office365.com", 993),
        "me.com": ("imap.mail.me.com", 993),
        "mac.com": ("imap.mail.me.com", 993),
        "icloud.com": ("imap.mail.me.com", 993),
        "yahoo.com": ("imap.mail.yahoo.com", 993),
        "yahoo.de": ("imap.mail.yahoo.com", 993),
        "gmx.de": ("imap.gmx.net", 993),
        "gmx.net": ("imap.gmx.net", 993),
        "web.de": ("imap.web.de", 993),
        "t-online.de": ("secureimap.t-online.de", 993),
        "protonmail.com": ("127.0.0.1", 1143),  # Bridge usually required
    }

    if domain in known_providers:
        return known_providers[domain]

    # Fallback guess: imap.<domain>
    return f"imap.{domain}", 993

def prompt_imap_credentials():
    auth_choice = input("Authentication method (1=IMAP password, 2=OAuth - experimental, default 1): ").strip()
    auth_method = 'oauth' if auth_choice == '2' else 'password'

    username = None
    imap_server = None
    imap_port = 993

    # Determine server/port
    if len(sys.argv) > 1:
        server_arg = sys.argv[1]
        match = re.match(r"([^:]+)(?::(\d+))?", server_arg)
        if match:
            imap_server = match.group(1)
            imap_port = int(match.group(2)) if match.group(2) else 993
        else:
            imap_server = server_arg
            imap_port = 993
        print(f"Using server: {imap_server}, port: {imap_port}")

    if auth_method == 'oauth':
        username = input("Email for OAuth: ").strip()
        if not username:
            print("Email is required for OAuth authentication.")
            raise SystemExit(1)

        if imap_server is None:
            detected_server, detected_port = autodetect_imap_server(username)
            if detected_server:
                imap_server = detected_server
                imap_port = detected_port or 993
            else:
                imap_server = input("IMAP server (could not auto-detect): ").strip()
                while not imap_server:
                    imap_server = input("IMAP server: ").strip()
                port_str = input(f"IMAP port (default {imap_port}): ").strip()
                imap_port = int(port_str) if port_str else imap_port

        if not OAUTH_AVAILABLE:
            print("OAuth support requires oauth libraries."
                  " For Gmail: install google-auth, google-auth-oauthlib"
                  " For Microsoft: install msal")
            raise SystemExit(1)

        # Determine which OAuth provider to use based on email domain
        domain = username.split("@", 1)[1].lower() if "@" in username else ""
        use_microsoft = domain in ("outlook.com", "hotmail.com", "live.com", "office365.com") or "outlook" in domain.lower()

        oauth_function = None
        if use_microsoft and MICROSOFT_OAUTH_AVAILABLE:
            oauth_function = start_microsoft_oauth_flow
            print("Using Microsoft OAuth for authentication...")
        elif GOOGLE_OAUTH_AVAILABLE:
            oauth_function = start_google_oauth_flow
            print("Using Google OAuth for authentication...")
        elif MICROSOFT_OAUTH_AVAILABLE:
            oauth_function = start_microsoft_oauth_flow
            print("Using Microsoft OAuth for authentication...")

        if not oauth_function:
            print(f"No OAuth provider available for {username}.")
            print("Install google-auth-oauthlib for Gmail or msal for Microsoft accounts.")
            raise SystemExit(1)

        try:
            oauth_result = oauth_function(username, imap_server=imap_server, imap_port=imap_port)
        except NotImplementedError as e:
            print(str(e))
            raise SystemExit(1)
        except Exception as e:
            print(f"OAuth flow failed: {e}")
            raise SystemExit(1)

        if not isinstance(oauth_result, dict):
            print("OAuth flow did not return connection details.")
            raise SystemExit(1)

        imap_server = oauth_result.get('imap_server', imap_server)
        imap_port = oauth_result.get('imap_port', imap_port)
        access_token = oauth_result.get('access_token')

        if not access_token:
            print("OAuth flow did not return an access token.")
            raise SystemExit(1)

        return auth_method, imap_server, imap_port, username, access_token

    # Password-based flow
    if imap_server is None:
        server_input = input("IMAP server (enter email for auto-detection): ").strip()

        if server_input and "@" in server_input:
            username = server_input
            detected_server, detected_port = autodetect_imap_server(username)
            if detected_server:
                imap_server = detected_server
                imap_port = detected_port or 993
                print(f"Auto-detected IMAP server: {imap_server} (port {imap_port})")
                override = input("Press Enter to accept or type a different IMAP server: ").strip()
                if override:
                    imap_server = override
            else:
                print("Could not auto-detect IMAP server. Please enter it manually.")

        if imap_server is None:
            imap_server = server_input if server_input and "@" not in server_input else ""
            while not imap_server:
                imap_server = input("IMAP server: ").strip()

        port_str = input(f"IMAP port (default {imap_port}): ").strip()
        imap_port = int(port_str) if port_str else imap_port

    if not username:
        username = input("Email: ").strip()

    username = username.strip()

    if auth_method == 'oauth':
        # In OAuth branch, we returned earlier.
        raise RuntimeError("Unexpected fall-through in OAuth authentication flow")

    password = None

    if username.lower().endswith(("@gmail.com", "@googlemail.com")):
        env_app_password = os.getenv("GOOGLE_APP_PASSWORD", "").strip()
        if env_app_password:
            print("Using Google App Password from environment (GOOGLE_APP_PASSWORD).")
            password = env_app_password
        else:
            print(
                "Google accounts with 2-step verification require an App Password. "
                "You can create one at https://myaccount.google.com/apppasswords."
            )
    elif username.lower().endswith(("@outlook.com", "@hotmail.com", "@live.com")) or "outlook" in username.lower():
        env_app_password = os.getenv("MICROSOFT_APP_PASSWORD", "").strip()
        if env_app_password:
            print("Using Microsoft App Password from environment (MICROSOFT_APP_PASSWORD).")
            password = env_app_password
        else:
            print(
                "Microsoft accounts with 2-step verification require an App Password. "
                "You can create one at https://account.live.com/proofs/manage."
            )

    if not password:
        password = getpass.getpass("Password: ")

    return auth_method, imap_server, imap_port, username, password

def decode_mime_header(header_value):
    """Decode MIME encoded email headers."""
    if not header_value:
        return ""
    decoded_parts = decode_header(header_value)
    decoded_str = []
    for part, encoding in decoded_parts:
        if isinstance(part, bytes):
            if encoding is not None:
                try:
                    part = part.decode(encoding)
                except:
                    part = part.decode('utf-8', errors='replace')
            else:
                part = part.decode('utf-8', errors='replace')
        decoded_str.append(str(part))
    return ''.join(decoded_str)

def get_email_body(msg):
    """Extract plain text body from email."""
    body = ""
    
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))
            
            # Skip attachments
            if "attachment" in content_disposition:
                continue
            
            try:
                if content_type == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        body = payload.decode(charset, errors='replace')
                        break  # Prefer plain text
                elif content_type == "text/html" and not body:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        # Store HTML as fallback
                        body = payload.decode(charset, errors='replace')
            except Exception as e:
                print(f"Error decoding body part: {e}")
                continue
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or 'utf-8'
                body = payload.decode(charset, errors='replace')
        except Exception as e:
            print(f"Error decoding message: {e}")
    
    return body[:5000]  # Limit to first 5000 chars for AI processing

def extract_attachments(msg, output_dir, email_date, email_subject, email_from='', ai_api_key=None, ai_provider='anthropic'):
    """Extract PDF attachments from email and save them, filtering with AI."""
    attachments = []
    
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    if not msg.is_multipart():
        return attachments
    
    for part in msg.walk():
        content_disposition = str(part.get("Content-Disposition", ""))
        
        if "attachment" in content_disposition or part.get_filename():
            filename = part.get_filename()
            if filename:
                filename = decode_mime_header(filename)
                
                # Generate safe filename
                safe_filename = sanitize_filename(filename)
                
                # Add date prefix
                date_prefix = email_date.strftime('%Y%m%d') if email_date else 'unknown'
                safe_filename = f"{date_prefix}_{safe_filename}"
                
                # Get file extension
                ext = Path(filename).suffix.lower()
                
                # Only save PDF files
                if ext == '.pdf':
                    filepath = os.path.join(output_dir, safe_filename)
                    
                    # Avoid overwriting - add counter if needed
                    counter = 1
                    base_path = filepath
                    while os.path.exists(filepath):
                        name_part = Path(base_path).stem
                        filepath = os.path.join(output_dir, f"{name_part}_{counter}{ext}")
                        counter += 1
                    
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            with open(filepath, 'wb') as f:
                                f.write(payload)
                            
                            # Use AI to verify this PDF is an invoice/receipt
                            email_info = {
                                'subject': email_subject,
                                'from': email_from,
                                'has_attachments': True
                            }
                            
                            is_invoice = True  # Default to keeping the PDF
                            if ai_api_key:
                                is_invoice = classify_pdf_with_ai(
                                    filepath, 
                                    email_info, 
                                    ai_api_key, 
                                    ai_provider
                                )
                            
                            if is_invoice:
                                attachments.append({
                                    'filename': safe_filename,
                                    'filepath': filepath,
                                    'size': len(payload),
                                    'type': ext
                                })
                                print(f"  ✓ Saved attachment: {safe_filename}")
                            else:
                                # Delete non-invoice PDFs
                                os.remove(filepath)
                                print(f"  ✗ Removed non-invoice PDF: {safe_filename}")
                    except Exception as e:
                        print(f"  Error saving attachment {filename}: {e}")
    
    return attachments

def sanitize_filename(filename):
    """Remove invalid characters from filename."""
    # Remove or replace invalid characters
    sanitized = re.sub(r'[\\/:*?"<>|]', '_', filename)
    sanitized = re.sub(r'[\r\n\t]', '', sanitized)
    sanitized = ''.join(c for c in sanitized if c.isprintable())
    # Limit length
    if len(sanitized) > 200:
        ext = Path(sanitized).suffix
        sanitized = sanitized[:200-len(ext)] + ext
    return sanitized

def search_expense_emails(server, year=2025, search_all_folders=False):
    """Search for emails that might contain expense information."""
    
    # Expense-related keywords (German and English)
    keywords = [
        'Rechnung', 'Invoice', 'Quittung', 'Receipt', 'Beleg',
        'Zahlung', 'Payment', 'Bezahlung', 'Bestellung', 'Order',
        'Kauf', 'Purchase', 'Lieferung', 'Delivery', 'Zahlungsbestätigung',
        'Buchung', 'Booking', 'Reservation', 'Reservierung',
        'Ticket', 'Abrechnung', 'Bill', 'Gebühr', 'Fee'
    ]
    
    # Determine which folders to search
    if search_all_folders:
        # Get all folders
        folder_list = server.list_folders()
        folders = [folder_name for flags, delimiter, folder_name in folder_list]
    else:
        # Default: only INBOX
        folders = ['INBOX']
    
    all_messages = {}
    
    for folder in folders:
        # Skip spam, trash, drafts
        folder_lower = folder.lower()
        if any(skip in folder_lower for skip in ['spam', 'trash', 'papierkorb', 'entwurf', 'draft', 'junk']):
            continue
        
        try:
            server.select_folder(folder, readonly=True)
            print(f"\nSearching folder: {folder}")
            
            # Search for emails from the specified year
            search_criteria = ['SINCE', date(year, 1, 1).strftime('%d-%b-%Y')]
            
            # Get all messages from the year
            messages = server.search(search_criteria)
            
            if not messages:
                continue
            
            total_in_folder = len(messages)
            print(f"  Found {total_in_folder} messages from {year} (before filtering)")
            
            print(f"  Filtering for expense-related emails...")
            
            # Fetch and filter
            fetch_results = server.fetch(messages, ['RFC822', 'INTERNALDATE'])
            
            expense_count = 0
            for uid in messages:
                if uid not in fetch_results or b'RFC822' not in fetch_results[uid]:
                    continue
                
                raw_message = fetch_results[uid][b'RFC822']
                internal_date = fetch_results[uid].get(b'INTERNALDATE')
                
                msg = message_from_bytes(raw_message)
                
                # Check if email contains expense keywords
                subject = decode_mime_header(msg.get('Subject', ''))
                from_header = decode_mime_header(msg.get('From', ''))
                
                # Quick keyword check
                if any(keyword.lower() in subject.lower() or keyword.lower() in from_header.lower() 
                       for keyword in keywords):
                    
                    message_id = msg.get('Message-ID', '').strip()
                    msg_hash = hashlib.md5(message_id.encode('utf-8')).hexdigest() if message_id else None
                    
                    # Avoid duplicates
                    if msg_hash and msg_hash in all_messages:
                        continue
                    
                    expense_count += 1
                    if msg_hash:
                        all_messages[msg_hash] = {
                            'uid': uid,
                            'folder': folder,
                            'date': internal_date,
                            'message': msg,
                            'hash': msg_hash
                        }
                    
            print(f"  Found {expense_count} expense-related emails")
            
        except Exception as e:
            print(f"  Error searching folder {folder}: {e}")
            continue
    
    return list(all_messages.values())

def prepare_for_ai_analysis(email_data):
    """Prepare email data for AI analysis."""
    msg = email_data['message']
    
    subject = decode_mime_header(msg.get('Subject', ''))
    from_header = decode_mime_header(msg.get('From', ''))
    to_header = decode_mime_header(msg.get('To', ''))
    date_header = msg.get('Date', '')
    body = get_email_body(msg)
    
    # Parse date
    try:
        msg_date = parsedate_to_datetime(date_header)
        date_str = msg_date.strftime('%Y-%m-%d')
    except:
        msg_date = email_data['date']
        date_str = msg_date.strftime('%Y-%m-%d') if msg_date else 'unknown'
    
    # Check for attachments
    has_pdf = False
    has_image = False
    attachment_count = 0
    
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_filename():
                attachment_count += 1
                filename = part.get_filename().lower()
                if filename.endswith('.pdf'):
                    has_pdf = True
                elif filename.endswith(('.png', '.jpg', '.jpeg', '.gif', '.tiff')):
                    has_image = True
    
    return {
        'subject': subject,
        'from': from_header,
        'to': to_header,
        'date': date_str,
        'date_obj': msg_date,
        'body': body[:2000],  # Limit body for AI
        'has_attachments': attachment_count > 0,
        'has_pdf': has_pdf,
        'has_image': has_image,
        'attachment_count': attachment_count,
        'folder': email_data['folder']
    }

def analyze_expense_ai(email_info, api_key, provider='anthropic', has_attachments=False):
    """
    Analyze email with AI to extract expense information.
    """
    if not AI_AVAILABLE:
        return None, None
    
    try:
        result, usage = ai_analyze(email_info, api_key, provider, has_attachments)
        if result:
            vendor = result.get('vendor', 'Unknown')
            amount = result.get('amount', 0)
            currency = result.get('currency', 'EUR')
            category = result.get('category', 'Unknown')
            is_expense = result.get('is_expense', False)
            
            # Show what AI extracted
            print(f"  AI: {vendor} - {amount} {currency} - {category}")
            
            # Debug: show the is_expense flag
            if not is_expense:
                print(f"  ⚠️  AI result has is_expense=False (vendor='{vendor}', amount={amount}, currency='{currency}', has_attachments={has_attachments})")
        
        return result, usage
    except Exception as e:
        print(f"  AI analysis error: {e}")
        return None, None

def classify_pdf_with_ai(pdf_path, email_info, api_key, provider='openai'):
    """
    Use AI to classify if a PDF is likely an invoice/receipt based on filename and email context.
    Returns True if the PDF appears to be an invoice/receipt, False otherwise.
    """
    if not AI_AVAILABLE:
        return True  # If no AI, assume all PDFs are valid
    
    try:
        filename = Path(pdf_path).name
        
        # Quick filename-based rejection for obvious non-invoices
        filename_lower = filename.lower()
        reject_patterns = [
            'agb', 'terms', 'conditions', 'widerruf', 'cancellation', 'privacy',
            'datenschutz', 'policy', 'richtlinie', 'impressum', 'imprint',
            'anleitung', 'manual', 'guide', 'handbuch', 'contract', 'vertrag'
        ]
        
        for pattern in reject_patterns:
            if pattern in filename_lower:
                print(f"    ✗ PDF rejected: {filename} (matched pattern: {pattern})")
                return False
        
        if provider == 'openai':
            from openai import OpenAI
            client = OpenAI(api_key=api_key)
            
            prompt = f"""Analyze this email and PDF filename to determine if the PDF is a business invoice or receipt.

Email context:
- Subject: {email_info['subject']}
- From: {email_info['from']}
- PDF filename: {filename}

REJECT these types of PDFs (answer NO):
- Terms & Conditions (AGB, Terms, Conditions)
- Cancellation policies (Widerrufsbelehrung, Cancellation)
- Privacy policies (Datenschutz, Privacy Policy)
- User manuals (Anleitung, Manual, Guide)
- Contracts (Vertrag, Contract)
- General legal documents

ACCEPT these types (answer YES):
- Invoices (Invoice, Rechnung, Factura)
- Receipts (Receipt, Beleg, Quittung)
- Bills (Bill, Statement)
- Order confirmations with prices

Answer with just YES if this is an invoice/receipt, or NO otherwise."""

            response = client.responses.create(
                model="gpt-5-mini",
                input=prompt,
                max_output_tokens=20
            )
            
            if response.status == "completed" and response.output:
                for item in response.output:
                    if hasattr(item, 'type') and item.type == 'message':
                        if hasattr(item, 'content') and item.content:
                            for content_item in item.content:
                                if hasattr(content_item, 'type') and content_item.type == 'output_text':
                                    answer = content_item.text.strip().upper()
                                    is_invoice = 'YES' in answer
                                    status = "✓" if is_invoice else "✗"
                                    print(f"    {status} PDF AI: {filename} -> {'Invoice/Receipt' if is_invoice else 'Not an invoice'}")
                                    return is_invoice
            
            return True  # Default to yes if parsing fails
            
        else:
            # Anthropic flow - use cheaper model
            import anthropic  # type: ignore[import-not-found]
            client = anthropic.Anthropic(api_key=api_key)
            
            prompt = f"""Analyze this email and PDF filename to determine if the PDF is a business invoice or receipt.

Email context:
- Subject: {email_info['subject']}
- From: {email_info['from']}
- PDF filename: {filename}

REJECT: Terms & Conditions, Cancellation policies, Privacy policies, Manuals, Contracts, Legal documents
ACCEPT: Invoices, Receipts, Bills, Order confirmations with prices

Answer with just YES or NO."""

            message = client.messages.create(
                model="claude-3-5-haiku-20241022",
                max_tokens=10,
                messages=[{"role": "user", "content": prompt}]
            )
            
            answer = message.content[0].text.strip().upper()
            is_invoice = 'YES' in answer
            status = "✓" if is_invoice else "✗"
            print(f"    {status} PDF AI: {filename} -> {'Invoice/Receipt' if is_invoice else 'Not an invoice'}")
            return is_invoice
            
    except Exception as e:
        print(f"  PDF classification error (defaulting to YES): {e}")
        return True  # If AI fails, assume it's an invoice

def classify_expense_with_ai(email_info, api_key, provider='anthropic'):
    """
    Use AI to quickly classify if an email is truly an expense (Stage 2).
    This is a lightweight check before doing full extraction.
    """
    if not AI_AVAILABLE:
        return True  # If no AI, assume keyword match is good enough
    
    try:
        # Import the AI module
        if provider == 'anthropic':
            import anthropic  # type: ignore[import-not-found]
            client = anthropic.Anthropic(api_key=api_key)
            
            prompt = f"""Is this email a business expense receipt/invoice?

Subject: {email_info['subject']}
From: {email_info['from']}
Has attachments: {email_info['has_attachments']}
Body preview: {email_info.get('body', '')[:300]}

IMPORTANT: Only answer YES if this is:
- An actual invoice or receipt (with payment/billing information)
- An order confirmation showing you purchased something
- A payment confirmation or billing statement

Answer NO if this is:
- Marketing emails (promotions, deals, offers, newsletters)  
- Booking reminders without payment info
- Shipping/delivery notifications without prices
- Account notifications or alerts
- Survey requests or review reminders
- Order status updates (without payment details)

Answer with just YES or NO."""

            message = client.messages.create(
                model="claude-3-5-haiku-20241022",  # Faster, cheaper model for classification
                max_tokens=10,
                messages=[{"role": "user", "content": prompt}]
            )
            
            answer = message.content[0].text.strip().upper()
            return 'YES' in answer
            
        elif provider == 'openai':
            from openai import OpenAI
            client = OpenAI(api_key=api_key)
            
            response = client.responses.create(
                model="gpt-5-mini",  # Faster, cheaper model
                input=f"""Is this email a business expense receipt/invoice?

Subject: {email_info['subject']}
From: {email_info['from']}
Has attachments: {email_info['has_attachments']}
Body preview: {email_info.get('body', '')[:300]}

IMPORTANT: Only answer YES if this is:
- An actual invoice or receipt (with payment/billing information)
- An order confirmation showing you purchased something
- A payment confirmation or billing statement

Answer NO if this is:
- Marketing emails (promotions, deals, offers, newsletters)
- Booking reminders without payment info
- Shipping/delivery notifications without prices
- Account notifications or alerts
- Survey requests or review reminders
- Order status updates (without payment details)

Answer with just YES or NO.""",
                max_output_tokens=20  # Minimum is 16
            )
            usage_summary = None
            if summarize_openai_usage:
                usage_summary = summarize_openai_usage("gpt-5-mini", getattr(response, "usage", None))
                if usage_summary:
                    input_tokens = usage_summary.get("input_tokens", 0)
                    output_tokens = usage_summary.get("output_tokens", 0)
                    total_tokens = usage_summary.get("total_tokens", 0)
                    cost_display = usage_summary.get("estimated_cost_usd")
                    cost_text = f"${cost_display:.6f}" if cost_display is not None else "n/a"
                    print(
                        f"  OpenAI usage (gpt-5-mini): input={input_tokens}, output={output_tokens}, "
                        f"total={total_tokens}, est. cost={cost_text}"
                    )

            if response.status == "completed" and response.output:
                for item in response.output:
                    if hasattr(item, 'type') and item.type == 'message':
                        if hasattr(item, 'content') and item.content:
                            for content_item in item.content:
                                if hasattr(content_item, 'type') and content_item.type == 'output_text':
                                    answer = content_item.text.strip().upper()
                                    return 'YES' in answer
            
            return True  # Default to yes if parsing fails
            
    except Exception as e:
        print(f"  Classification error (defaulting to YES): {e}")
        return True  # If AI fails, assume it's an expense

def main():
    # Configuration
    EXPENSE_DIR = 'expenses_2025'
    ATTACHMENTS_DIR = os.path.join(EXPENSE_DIR, 'attachments')
    os.makedirs(ATTACHMENTS_DIR, exist_ok=True)
    
    # Set up logging to file - capture all stdout
    log_file = os.path.join(EXPENSE_DIR, 'expense_collector.log')
    
    # Create a custom stream that writes to both console and file
    class DualOutput:
        def __init__(self, log_file_path):
            self.terminal = sys.stdout
            self.log = open(log_file_path, 'w', encoding='utf-8')
        
        def write(self, message):
            self.terminal.write(message)
            self.log.write(message)
            self.log.flush()
        
        def flush(self):
            self.terminal.flush()
            self.log.flush()
    
    # Redirect stdout to capture all print statements
    dual_output = DualOutput(log_file)
    sys.stdout = dual_output
    
    # Set up logging to suppress HTTP noise
    logging.basicConfig(level=logging.WARNING)
    logging.getLogger('httpx').setLevel(logging.WARNING)
    logging.getLogger('httpcore').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('openai').setLevel(logging.WARNING)
    logging.getLogger('anthropic').setLevel(logging.WARNING)
    
    print("="*60)
    print("Email Expense Collector")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)
    
    # Get year with validation
    while True:
        year_input = input("Year to search (default 2025): ").strip()
        if not year_input:
            year = 2025
            break
        try:
            year = int(year_input)
            if 2000 <= year <= 2100:
                break
            else:
                print("  ⚠️  Please enter a valid year between 2000 and 2100")
        except ValueError:
            print(f"  ⚠️  '{year_input}' is not a valid year. Please enter a number (e.g., 2025)")
    
    # Get AI API key (optional for now)
    while True:
        use_ai_input = input("Use AI for analysis? (y/n, default n): ").strip().lower()
        if use_ai_input in ['y', 'n', '']:
            use_ai = use_ai_input == 'y'
            break
        print("  ⚠️  Please enter 'y' for yes or 'n' for no")
    
    ai_api_key = None
    ai_provider = 'anthropic'
    
    if use_ai:
        if not AI_AVAILABLE:
            print("AI analysis not available. Install: pip install anthropic openai")
            use_ai = False
        else:
            # Try to load from environment variables
            anthropic_key = os.getenv('ANTHROPIC_API_KEY')
            openai_key = os.getenv('OPENAI_API_KEY')
            default_provider = os.getenv('AI_PROVIDER', 'anthropic')
            
            if anthropic_key or openai_key:
                print(f"\nAPI key(s) found in .env file:")
                if anthropic_key:
                    print("  ✓ Anthropic Claude")
                if openai_key:
                    print("  ✓ OpenAI GPT")

                available_providers = {}
                if anthropic_key:
                    available_providers['anthropic'] = anthropic_key
                if openai_key:
                    available_providers['openai'] = openai_key

                preferred_provider = os.getenv('AI_PROVIDER', 'anthropic').strip().lower()
                if preferred_provider not in available_providers:
                    preferred_provider = next(iter(available_providers.keys()))

                ai_provider = preferred_provider
                ai_api_key = available_providers[ai_provider]
                print(f"Using {ai_provider.title()} API key from .env (set AI_PROVIDER to change this default)")
            
            # If no env key or user declined, ask for manual input
            if not ai_api_key:
                while True:
                    provider_choice = input("Choose AI provider (1=Anthropic Claude, 2=OpenAI GPT, default 1): ").strip()
                    if provider_choice in ['1', '2', '']:
                        ai_provider = 'openai' if provider_choice == '2' else 'anthropic'
                        break
                    print("  ⚠️  Please enter '1' for Anthropic or '2' for OpenAI")
                
                ai_api_key = input(f"Enter {ai_provider.title()} API key: ").strip()
                
            if not ai_api_key:
                use_ai = False
                print("Skipping AI analysis")
    
    # Connect to email with error handling
    auth_method, imap_server, imap_port, username, credential = prompt_imap_credentials()

    try:
        with IMAPClient(imap_server, port=imap_port, ssl=True) as server:
            try:
                if auth_method == 'oauth':
                    server.oauth2_login(username, credential)
                else:
                    server.login(username, credential)
            except LoginError as e:
                print(f"Login failed: {e}")
                if username.lower().endswith('@gmail.com'):
                    print("\nGmail with 2-step verification requires an App Password for IMAP access.")
                    print("Create one at https://myaccount.google.com/apppasswords and use it instead of your normal password.")
                else:
                    print("Please verify your username/password or check if IMAP access is enabled for this account.")
                return
            except (socket.gaierror, socket.timeout, ConnectionError) as e:
                print(f"Network error while connecting: {e}")
                print("No internet connection!")
                return
            except Exception as e:
                print(f"Unexpected error during login: {e}")
                print("No internet connection!")
                return

            # Ask about folder selection with validation
            while True:
                search_all = input("Search all folders? (y/n, default n - INBOX only): ").strip().lower()
                if search_all in ['y', 'n', '']:
                    search_all_folders = (search_all == 'y')
                    break
                print("  ⚠️  Please enter 'y' for yes or 'n' for no")
            
            if search_all_folders:
                print("Searching all folders...")
            else:
                print("Searching INBOX only...")

            print(f"\nSearching for expense emails from {year}...")
            try:
                messages = search_expense_emails(server, year, search_all_folders)
            except Exception:
                print("No internet connection!")
                return

            if not messages:
                print(f"\nNo expense-related emails found for {year}")
                return

            print(f"\n{'='*60}")
            print(f"Found {len(messages)} potential expense emails")
            print(f"{'='*60}\n")

            # Process each message
            expense_records = []
            skipped_by_ai = 0

            csv_file_path = Path(EXPENSE_DIR) / f"expenses_{year}.csv"
            csv_writer = None
            csv_file_handle = None

            def write_record(record: dict) -> None:
                nonlocal csv_writer, csv_file_handle
                if csv_file_handle is None:
                    csv_file_path.parent.mkdir(parents=True, exist_ok=True)
                    csv_file_handle = csv_file_path.open("w", newline="", encoding="utf-8-sig")
                    csv_writer = csv.DictWriter(csv_file_handle, fieldnames=record.keys())
                    csv_writer.writeheader()
                if csv_writer is None:
                    raise RuntimeError("CSV writer was not initialised correctly.")
                csv_writer.writerow(record)
                csv_file_handle.flush()

            for idx, email_data in enumerate(messages, 1):
                msg = email_data['message']
                email_info = prepare_for_ai_analysis(email_data)

                print(f"\n[{idx}/{len(messages)}] Processing: {email_info['subject'][:60]}")
                print(f"  Date: {email_info['date']}")
                print(f"  From: {email_info['from'][:50]}")
                print(f"  Attachments: {email_info['attachment_count']}")
                
                # Show body snippet for context
                body_snippet = email_info['body'][:150].replace('\n', ' ').strip()
                if body_snippet:
                    print(f"  Body: {body_snippet}...")

                subject_prefix = email_info['subject'].lstrip()
                if subject_prefix.lower().startswith('re:'):
                    print("  ✗ Skipping reply email (subject starts with 'Re:')")
                    continue

                # Stage 2: AI Classification (if AI is enabled)
                # Quick check: Is this REALLY an expense?
                is_expense = True
                if use_ai and ai_api_key:
                    print("  Classifying with AI...")
                    is_expense = classify_expense_with_ai(email_info, ai_api_key, ai_provider)
                    if not is_expense:
                        print("  ✗ AI classified as NOT an expense - skipping")
                        skipped_by_ai += 1
                        continue
                    else:
                        print("  ✓ AI confirmed as expense")

                # Extract attachments
                attachments = extract_attachments(
                    msg,
                    ATTACHMENTS_DIR,
                    email_info['date_obj'],
                    email_info['subject'],
                    email_info['from'],
                    ai_api_key if use_ai else None,
                    ai_provider
                )

                # Stage 3: AI Extraction (only if confirmed expense)
                if use_ai and ai_api_key and is_expense:
                    has_pdf_attachments = len(attachments) > 0
                    ai_result, usage_summary = analyze_expense_ai(email_info, ai_api_key, ai_provider, has_pdf_attachments)
                    # Usage is already logged inside analyze_expense_ai(), no need to log again here
                else:
                    ai_result, usage_summary = None, None

                if not ai_result:
                    ai_result = {
                        'is_expense': True,
                        'vendor': 'Manual Review Needed',
                        'amount': 0.0,
                        'currency': 'EUR',
                        'category': 'Uncategorized',
                        'description': email_info['subject'],
                        'confidence': 0.0
                    }

                # Create expense record
                record = {
                    'date': email_info['date'],
                    'subject': email_info['subject'],
                    'from': email_info['from'],
                    'is_expense': ai_result.get('is_expense', True),
                    'vendor': ai_result.get('vendor', 'Unknown'),
                    'amount': ai_result.get('amount', 0.0),
                    'currency': ai_result.get('currency', 'EUR'),
                    'category': ai_result.get('category', 'Uncategorized'),
                    'description': ai_result.get('description', email_info['subject']),
                    'confidence': ai_result.get('confidence', 0.0),
                    'has_attachments': len(attachments) > 0,
                    'attachment_files': ', '.join([a['filename'] for a in attachments]),
                    'folder': email_info['folder']
                }
                
                # Only save to CSV if it's confirmed as an expense
                if record['is_expense']:
                    expense_records.append(record)
                    write_record(record)
                else:
                    print("  ✗ Skipped (not an expense)")

            if csv_file_handle is not None:
                csv_file_handle.close()
            csv_file = str(csv_file_path)

            print(f"\n{'='*60}")
            print("✓ Export complete!")
            print(f"{'='*60}")
            print(f"Keyword matches found: {len(messages)}")
            if use_ai:
                print(f"AI confirmed as expenses: {len(expense_records)}")
                print(f"AI rejected (not expenses): {skipped_by_ai}")
            else:
                print(f"Total expense emails: {len(expense_records)}")
            print(f"CSV report: {csv_file}")
            print(f"Attachments saved to: {ATTACHMENTS_DIR}")
            if use_ai:
                print(f"\n💡 Tip: The AI filtered out {skipped_by_ai} false positives from keyword matching!")
            else:
                print("\n💡 Tip: Enable AI analysis to automatically extract vendor, amount, and category data.")

    except Exception:
        print("No internet connection!")
        return

if __name__ == "__main__":
    main()
