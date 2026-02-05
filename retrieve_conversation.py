import os
from imapclient import IMAPClient
from imapclient.exceptions import LoginError
import sys
import re
from email import message_from_bytes
from email.header import decode_header
from email.utils import parsedate_to_datetime
import html2text
from datetime import datetime
import hashlib
import getpass
import socket
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

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
    }

    if domain in known_providers:
        return known_providers[domain]

    # Fallback guess: imap.<domain>
    return f"imap.{domain}", 993


def prompt_imap_credentials():
    """Prompt for IMAP credentials with OAuth or password authentication."""
    
    # Check for env variables first
    env_server = os.getenv("IMAP_SERVER", "").strip()
    env_port = os.getenv("IMAP_PORT", "").strip()
    env_username = os.getenv("IMAP_USERNAME", "").strip()
    
    username = None
    imap_server = None
    imap_port = 993

    # Check for server[:port] as first argument
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
    elif env_server:
        # Use env variables
        imap_server = env_server
        imap_port = int(env_port) if env_port else 993
        username = env_username if env_username else None
        print(f"Using server from .env: {imap_server}, port: {imap_port}")
        if username:
            print(f"Using username from .env: {username}")

    auth_choice = input("Authentication method (1=IMAP password, 2=OAuth, default 1): ").strip()
    auth_method = 'oauth' if auth_choice == '2' else 'password'

    if auth_method == 'oauth':
        if not username:
            username = input("Email for OAuth: ").strip()
        if not username:
            print("Email is required for OAuth authentication.")
            raise SystemExit(1)

        if imap_server is None:
            detected_server, detected_port = autodetect_imap_server(username)
            if detected_server:
                imap_server = detected_server
                imap_port = detected_port or 993
                print(f"Auto-detected IMAP server: {imap_server} (port {imap_port})")
            else:
                imap_server = input("IMAP server (could not auto-detect): ").strip()
                while not imap_server:
                    imap_server = input("IMAP server: ").strip()
                port_str = input(f"IMAP port (default {imap_port}): ").strip()
                imap_port = int(port_str) if port_str else imap_port

        if not OAUTH_AVAILABLE:
            print("OAuth support requires oauth libraries.")
            print(" For Gmail: install google-auth, google-auth-oauthlib")
            print(" For Microsoft: install msal")
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
        server_input = input("IMAP server (or enter email for auto-detection): ").strip()

        if server_input and "@" in server_input:
            username = server_input
            detected_server, detected_port = autodetect_imap_server(username)
            if detected_server:
                imap_server = detected_server
                imap_port = detected_port or 993
                print(f"Auto-detected IMAP server: {imap_server} (port {imap_port})")
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

    password = None

    if username.lower().endswith(("@gmail.com", "@googlemail.com")):
        env_app_password = os.getenv("GOOGLE_APP_PASSWORD", "").strip()
        if env_app_password:
            print("Using Google App Password from environment (GOOGLE_APP_PASSWORD).")
            password = env_app_password
        else:
            print(
                "Google accounts with 2-step verification require an App Password. "
                "Create one at https://myaccount.google.com/apppasswords"
            )
    elif username.lower().endswith(("@outlook.com", "@hotmail.com", "@live.com")) or "outlook" in username.lower():
        env_app_password = os.getenv("MICROSOFT_APP_PASSWORD", "").strip()
        if env_app_password:
            print("Using Microsoft App Password from environment (MICROSOFT_APP_PASSWORD).")
            password = env_app_password
        else:
            print(
                "Microsoft accounts with 2-step verification require an App Password. "
                "Create one at https://account.live.com/proofs/manage"
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

def extract_email_address(header_value):
    """Extract just the email address from a header like 'Name <email@domain.com>'."""
    if not header_value:
        return ""
    # Pattern to match email addresses
    match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', header_value)
    if match:
        return match.group(0).lower()
    return header_value.lower()

def get_message_hash(msg):
    """Generate a unique hash for an email message based on Message-ID."""
    # Use Message-ID header as the primary unique identifier
    message_id = msg.get('Message-ID', '').strip()
    if message_id:
        return hashlib.md5(message_id.encode('utf-8')).hexdigest()
    
    # Fallback: hash based on date, subject, from (without body to avoid quoted content issues)
    date = msg.get('Date', '')
    subject = msg.get('Subject', '')
    from_header = msg.get('From', '')
    
    hash_input = f"{date}|{subject}|{from_header}"
    return hashlib.md5(hash_input.encode('utf-8')).hexdigest()

def strip_quoted_text(text):
    """Remove quoted/replied text from email body to get only new content."""
    if not text:
        return text
    
    lines = text.split('\n')
    new_lines = []
    
    for i, line in enumerate(lines):
        stripped = line.strip()
        
        # Stop at common quote introduction patterns
        if (re.match(r'^On .+wrote:?\s*$', stripped, re.IGNORECASE) or
            re.match(r'^Am .+schrieb.+:?\s*$', stripped, re.IGNORECASE) or
            re.match(r'^\d{4}-\d{2}-\d{2}.+wrote:?\s*$', stripped, re.IGNORECASE) or
            re.match(r'^From:.+$', stripped) and i > 0 and re.match(r'^(Sent|Gesendet|Date|To|An|Subject|Betreff):', lines[i+1].strip() if i+1 < len(lines) else '', re.IGNORECASE) or
            re.match(r'^Von:.+$', stripped) and i > 0 and re.match(r'^(Gesendet|An|Betreff|Sent|To|Subject):', lines[i+1].strip() if i+1 < len(lines) else '', re.IGNORECASE) or
            re.match(r'^_{3,}$', stripped) or
            re.match(r'^-{3,}\s*(Original|Forwarded)\s*(Message|Nachricht)', stripped, re.IGNORECASE)):
            # Everything from here is quoted, stop processing
            break
        
        # Skip standard quote markers
        if (stripped.startswith('>') or 
            stripped.startswith('|') or
            line.startswith('    >')):
            continue
        
        # Stop at signature separators
        if stripped in ['--', '___'] or (re.match(r'^-{2,}$', stripped) and len(stripped) <= 4):
            break
        
        # Skip lines that look like email headers in quotes
        if re.match(r'^(From|Von|Sent|Gesendet|To|An|Subject|Betreff|Date|Datum):\s*.+$', stripped, re.IGNORECASE):
            # Check if this is part of a quoted message (look at surrounding context)
            if i > 0 or i < len(lines) - 5:  # Not at the very start
                break
        
        # Skip empty lines at the start
        if not new_lines and not stripped:
            continue
            
        new_lines.append(line)
    
    result = '\n'.join(new_lines).strip()
    
    # Additional cleanup: remove common email footers/disclaimers
    result = re.sub(r'\n+Sent from my \w+.*$', '', result, flags=re.IGNORECASE | re.MULTILINE)
    result = re.sub(r'\n+Get Outlook for \w+.*$', '', result, flags=re.IGNORECASE | re.MULTILINE)
    
    # Remove trailing whitespace and multiple blank lines
    result = re.sub(r'\n{3,}', '\n\n', result)
    
    return result.strip()

def get_text_from_email(msg):
    """Extract plain text content from email, converting HTML if necessary."""
    text_content = []
    html_content = []
    
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
                        text_content.append(payload.decode(charset, errors='replace'))
                elif content_type == "text/html":
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        html_content.append(payload.decode(charset, errors='replace'))
            except Exception as e:
                print(f"Error decoding part: {e}")
                continue
    else:
        content_type = msg.get_content_type()
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or 'utf-8'
                if content_type == "text/plain":
                    text_content.append(payload.decode(charset, errors='replace'))
                elif content_type == "text/html":
                    html_content.append(payload.decode(charset, errors='replace'))
        except Exception as e:
            print(f"Error decoding message: {e}")
    
    # Prefer plain text, but convert HTML if that's all we have
    if text_content:
        full_text = '\n\n'.join(text_content)
    elif html_content:
        h = html2text.HTML2Text()
        h.ignore_links = False
        h.ignore_images = True
        h.ignore_emphasis = False
        h.body_width = 0  # Don't wrap lines
        full_text = '\n\n'.join([h.handle(html) for html in html_content])
    else:
        return ""
    
    # Strip quoted/replied content to get only the new message
    return strip_quoted_text(full_text)


def get_attachments_from_email(msg):
    """Extract attachment info from email."""
    attachments = []
    
    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = str(part.get("Content-Disposition", ""))
            
            if "attachment" in content_disposition:
                filename = part.get_filename()
                if filename:
                    filename = decode_mime_header(filename)
                    attachments.append({
                        'filename': filename,
                        'part': part
                    })
    
    return attachments


def save_attachments(msg, attachments_dir, msg_index):
    """Save all attachments from an email to the specified directory."""
    saved_files = []
    attachments = get_attachments_from_email(msg)
    
    for att in attachments:
        filename = att['filename']
        part = att['part']
        
        # Sanitize filename
        safe_filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
        # Prefix with message index to avoid collisions
        safe_filename = f"{msg_index:03d}_{safe_filename}"
        
        filepath = os.path.join(attachments_dir, safe_filename)
        
        try:
            payload = part.get_payload(decode=True)
            if payload:
                with open(filepath, 'wb') as f:
                    f.write(payload)
                saved_files.append(safe_filename)
                print(f"    Saved: {safe_filename}")
        except Exception as e:
            print(f"    Error saving {filename}: {e}")
    
    return saved_files

def search_emails_by_sender(server, sender_email, folders=None, is_gmail=False):
    """Search for all emails from or to a specific sender across folders."""
    messages = {}  # Use dict to deduplicate by hash
    
    # Folders to skip (drafts shouldn't be included in conversations)
    skip_folders = {'[Gmail]/Drafts', 'Drafts', '[Gmail]/Spam', 'Spam', 'Junk', '[Gmail]/Trash', 'Trash'}
    # German folder names
    skip_folders.update({'Entwürfe', 'Papierkorb'})
    
    if folders is None:
        # Get all folders
        folder_list = server.list_folders()
        folders = [folder_name for flags, delimiter, folder_name in folder_list]
    
    for folder in folders:
        # Skip draft and spam folders
        if folder in skip_folders or 'draft' in folder.lower() or 'entwürf' in folder.lower():
            print(f"Skipping folder: {folder}")
            continue
        
        try:
            server.select_folder(folder, readonly=True)
            print(f"Searching in folder: {folder}")
            
            # Search for emails FROM the sender
            from_results = server.search(['FROM', sender_email])
            
            # Search for emails TO the sender
            to_results = server.search(['TO', sender_email])
            
            # Combine and deduplicate UIDs
            all_uids = list(set(from_results + to_results))
            
            if all_uids:
                print(f"  Found {len(all_uids)} messages")
                # Only fetch X-GM-LABELS for Gmail servers (it's a Gmail extension)
                fetch_items = ['RFC822', 'INTERNALDATE', 'FLAGS']
                if is_gmail:
                    fetch_items.append('X-GM-LABELS')
                fetch_results = server.fetch(all_uids, fetch_items)
                
                for uid in all_uids:
                    if uid not in fetch_results or b'RFC822' not in fetch_results[uid]:
                        continue
                    
                    # Skip drafts - check for \Draft flag
                    flags = fetch_results[uid].get(b'FLAGS', ())
                    if b'\\Draft' in flags:
                        print(f"  Skipping draft message (uid: {uid})")
                        continue
                    
                    # Also check Gmail labels for drafts (Gmail only)
                    if is_gmail:
                        gm_labels = fetch_results[uid].get(b'X-GM-LABELS', ())
                        is_draft = any(
                            label in (b'\\Draft', '\\Draft', b'\\\\Draft', '\\\\Draft')
                            or (isinstance(label, (bytes, str)) and 'draft' in str(label).lower())
                            for label in gm_labels
                        )
                        if is_draft:
                            print(f"  Skipping draft message (uid: {uid}, labels: {gm_labels})")
                            continue
                    
                    raw_message = fetch_results[uid][b'RFC822']
                    internal_date = fetch_results[uid].get(b'INTERNALDATE')
                    
                    msg = message_from_bytes(raw_message)
                    
                    # Generate hash to detect duplicates
                    msg_hash = get_message_hash(msg)
                    
                    # Only add if we haven't seen this message before
                    if msg_hash not in messages:
                        messages[msg_hash] = {
                            'uid': uid,
                            'folder': folder,
                            'date': internal_date,
                            'message': msg,
                            'hash': msg_hash
                        }
                    else:
                        print(f"  Skipping duplicate message (hash: {msg_hash[:8]}...)")
        except Exception as e:
            print(f"  Error searching folder {folder}: {e}")
            continue
    
    return list(messages.values())

def format_conversation_to_markdown(messages, sender_email, output_file, my_email, attachments_dir=None, download_attachments=False):
    """Format conversation messages into a markdown file."""
    # Sort messages by date (chronologically)
    messages.sort(key=lambda x: x['date'] if x['date'] else datetime.min)
    
    total_attachments = 0
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"# Email Conversation with {sender_email}\n\n")
        f.write(f"**Total Messages:** {len(messages)} (after deduplication)\n\n")
        f.write(f"**Your Email:** {my_email}\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        if attachments_dir:
            f.write(f"**Attachments Folder:** {attachments_dir}\n\n")
        f.write("---\n\n")
        
        for idx, msg_data in enumerate(messages, 1):
            msg = msg_data['message']
            
            # Extract headers
            subject = decode_mime_header(msg.get('Subject', '(No Subject)'))
            from_header = decode_mime_header(msg.get('From', ''))
            to_header = decode_mime_header(msg.get('To', ''))
            date_header = msg.get('Date', '')
            
            # Determine direction (sent vs received)
            from_email = extract_email_address(from_header).lower()
            direction = "📤 SENT" if from_email == my_email.lower() else "📥 RECEIVED"
            
            # Parse date
            try:
                msg_date = parsedate_to_datetime(date_header)
                date_str = msg_date.strftime('%Y-%m-%d %H:%M:%S')
            except:
                date_str = date_header or 'Unknown date'
            
            # Write message header
            f.write(f"## Message {idx} {direction}\n\n")
            f.write(f"**Date:** {date_str}\n\n")
            f.write(f"**From:** {from_header}\n\n")
            f.write(f"**To:** {to_header}\n\n")
            f.write(f"**Subject:** {subject}\n\n")
            f.write(f"**Folder:** {msg_data['folder']}\n\n")
            
            # Handle attachments
            attachments = get_attachments_from_email(msg)
            if attachments:
                f.write(f"**Attachments:** {len(attachments)} file(s)\n\n")
                if download_attachments and attachments_dir:
                    print(f"  Saving {len(attachments)} attachment(s) from message {idx}...")
                    saved = save_attachments(msg, attachments_dir, idx)
                    total_attachments += len(saved)
                    for filename in saved:
                        f.write(f"  - [{filename}]({attachments_dir}/{filename})\n")
                else:
                    for att in attachments:
                        f.write(f"  - {att['filename']}\n")
                f.write("\n")
            
            # Extract and write body
            body = get_text_from_email(msg)
            if body:
                f.write("**Message:**\n\n")
                f.write("```\n")
                f.write(body.strip())
                f.write("\n```\n\n")
            else:
                f.write("*(No text content)*\n\n")
            
            f.write("---\n\n")
    
    if download_attachments:
        print(f"  Total attachments saved: {total_attachments}")

def main():
    auth_method, imap_server, imap_port, username, credential = prompt_imap_credentials()
    
    sender_email = input("Enter sender email address to search for: ").strip().lower()
    
    # Ask if user wants to search specific folders or all folders
    search_all = input("Search all folders? (y/n, default y): ").strip().lower()
    folders = None
    
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
                    print("Create one at https://myaccount.google.com/apppasswords")
                    print("Or use OAuth (option 2) for a smoother experience.")
                else:
                    print("Please verify your username/password or check if IMAP access is enabled.")
                return
            except (socket.gaierror, socket.timeout, ConnectionError) as e:
                print(f"Network error while connecting: {e}")
                return
        
            if search_all != 'n':
                print("Searching all folders...")
            else:
                folder_list = server.list_folders()
                folder_names = [folder_name for flags, delimiter, folder_name in folder_list]
                print("\nAvailable folders:")
                for idx, name in enumerate(folder_names):
                    print(f"[{idx}] {name}")
                selected = input("Enter comma-separated numbers of folders to search: ")
                try:
                    indices = [int(i.strip()) for i in selected.split(',') if i.strip().isdigit()]
                    folders = [folder_names[i] for i in indices if 0 <= i < len(folder_names)]
                except Exception:
                    print("Invalid input. Searching all folders.")
                    folders = None
            
            # Detect if this is a Gmail server (for Gmail-specific features)
            is_gmail = 'gmail' in imap_server.lower() or 'google' in imap_server.lower()
            
            messages = search_emails_by_sender(server, sender_email, folders, is_gmail=is_gmail)
            
            if not messages:
                print(f"\nNo messages found with sender: {sender_email}")
                return
            
            print(f"\nFound {len(messages)} unique messages total (after deduplication).")
            
            # Ask if user wants to download attachments
            download_attachments = input("Download attachments? (y/n, default n): ").strip().lower() == 'y'
            
            # Generate output filename
            safe_email = re.sub(r'[^\w\.-]', '_', sender_email)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"conversation_{safe_email}_{timestamp}.md"
            
            # Create attachments directory if needed
            attachments_dir = None
            if download_attachments:
                attachments_dir = f"conversation_{safe_email}_{timestamp}_attachments"
                os.makedirs(attachments_dir, exist_ok=True)
                print(f"Attachments will be saved to: {attachments_dir}")
            
            print(f"Generating markdown file: {output_file}")
            format_conversation_to_markdown(messages, sender_email, output_file, username, 
                                           attachments_dir=attachments_dir, 
                                           download_attachments=download_attachments)
            
            print(f"\nConversation exported to: {output_file}")
    except Exception as e:
        print(f"Error: {e}")
        return


if __name__ == "__main__":
    main()
