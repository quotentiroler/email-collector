import os
from imapclient import IMAPClient
import sys
import re
from email import message_from_bytes
from email.header import decode_header
from email.utils import parsedate_to_datetime
import html2text
from datetime import datetime
import hashlib

def prompt_imap_credentials():
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
    else:
        imap_server = input("IMAP server (e.g. xmail.mwn.de): ").strip()
        port_str = input("IMAP port (default 993): ").strip()
        imap_port = int(port_str) if port_str else 993
    username = input("Username: ").strip()
    import getpass
    password = getpass.getpass("Password: ")
    return imap_server, imap_port, username, password

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

def search_emails_by_sender(server, sender_email, folders=None):
    """Search for all emails from or to a specific sender across folders."""
    messages = {}  # Use dict to deduplicate by hash
    
    if folders is None:
        # Get all folders
        folder_list = server.list_folders()
        folders = [folder_name for flags, delimiter, folder_name in folder_list]
    
    for folder in folders:
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
                fetch_results = server.fetch(all_uids, ['RFC822', 'INTERNALDATE'])
                
                for uid in all_uids:
                    if uid not in fetch_results or b'RFC822' not in fetch_results[uid]:
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

def format_conversation_to_markdown(messages, sender_email, output_file, my_email):
    """Format conversation messages into a markdown file."""
    # Sort messages by date (chronologically)
    messages.sort(key=lambda x: x['date'] if x['date'] else datetime.min)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"# Email Conversation with {sender_email}\n\n")
        f.write(f"**Total Messages:** {len(messages)} (after deduplication)\n\n")
        f.write(f"**Your Email:** {my_email}\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
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

def main():
    imap_server, imap_port, username, password = prompt_imap_credentials()
    
    sender_email = input("Enter sender email address to search for: ").strip().lower()
    
    # Ask if user wants to search specific folders or all folders
    search_all = input("Search all folders? (y/n, default y): ").strip().lower()
    folders = None
    
    with IMAPClient(imap_server, port=imap_port, ssl=True) as server:
        server.login(username, password)
        
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
        
        messages = search_emails_by_sender(server, sender_email, folders)
        
        if not messages:
            print(f"\nNo messages found with sender: {sender_email}")
            return
        
        print(f"\nFound {len(messages)} unique messages total (after deduplication).")
        
        # Generate output filename
        safe_email = re.sub(r'[^\w\.-]', '_', sender_email)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = f"conversation_{safe_email}_{timestamp}.md"
        
        print(f"Generating markdown file: {output_file}")
        format_conversation_to_markdown(messages, sender_email, output_file, username)
        
        print(f"\nConversation exported to: {output_file}")

if __name__ == "__main__":
    main()
