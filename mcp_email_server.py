"""
MCP Email Server
Exposes email tools via the Model Context Protocol using FastMCP.

Run with:
    fastmcp run mcp_email_server.py
    
Or for development:
    python mcp_email_server.py
"""

import os
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from pathlib import Path
from typing import Optional
from contextlib import contextmanager

from fastmcp import FastMCP, Context
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Create the MCP server
mcp = FastMCP(
    name="Email Tools",
    instructions="""
    Email management tools for reading, searching, and sending emails.
    Supports OAuth authentication for Gmail and Microsoft accounts.
    Can extract text from PDF attachments.
    """
)

# ============================================================================
# Configuration & Helpers
# ============================================================================

def get_imap_config() -> dict:
    """Get IMAP configuration from environment."""
    return {
        "server": os.getenv("IMAP_SERVER", ""),
        "port": int(os.getenv("IMAP_PORT", "993")),
        "username": os.getenv("IMAP_USERNAME", ""),
    }


def get_smtp_config() -> dict:
    """Get SMTP configuration from environment."""
    return {
        "server": os.getenv("SMTP_SERVER", ""),
        "port": int(os.getenv("SMTP_PORT", "587")),
        "username": os.getenv("SMTP_USERNAME", os.getenv("IMAP_USERNAME", "")),
    }


@contextmanager
def get_imap_connection():
    """Context manager for IMAP connection with OAuth or password auth."""
    from imapclient import IMAPClient
    
    config = get_imap_config()
    if not config["server"] or not config["username"]:
        raise ValueError("IMAP_SERVER and IMAP_USERNAME must be set in .env")
    
    # Try Microsoft OAuth first for Outlook/Hotmail
    username = config["username"].lower()
    access_token = None
    
    if any(domain in username for domain in ["@outlook.com", "@hotmail.com", "@live.com"]):
        try:
            from oauth_microsoft import start_microsoft_oauth_flow
            result = start_microsoft_oauth_flow(
                config["username"],
                imap_server=config["server"],
                imap_port=config["port"]
            )
            access_token = result.get("access_token")
        except Exception:
            pass
    elif "@gmail.com" in username or "@googlemail.com" in username:
        try:
            from oauth_client import start_oauth_flow
            result = start_oauth_flow(
                config["username"],
                imap_server=config["server"],
                imap_port=config["port"]
            )
            access_token = result.get("access_token")
        except Exception:
            pass
    
    with IMAPClient(config["server"], port=config["port"], ssl=True) as server:
        if access_token:
            server.oauth2_login(config["username"], access_token)
        else:
            # Fall back to app password
            password = os.getenv("MICROSOFT_APP_PASSWORD") or os.getenv("GOOGLE_APP_PASSWORD")
            if not password:
                raise ValueError("No OAuth token or app password available")
            server.login(config["username"], password)
        
        yield server


# ============================================================================
# Email Reading Tools
# ============================================================================

@mcp.tool
def list_folders() -> list[str]:
    """List all email folders/mailboxes in the account."""
    with get_imap_connection() as server:
        folders = server.list_folders()
        return [folder_name for flags, delimiter, folder_name in folders]


@mcp.tool
def search_emails(
    query: str,
    folder: str = "INBOX",
    limit: int = 20
) -> list[dict]:
    """
    Search emails in a folder.
    
    Args:
        query: Search term (searches in FROM, SUBJECT, and BODY)
        folder: Folder to search in (default: INBOX)
        limit: Maximum number of results to return
        
    Returns:
        List of matching emails with basic info (subject, from, date)
    """
    from email import message_from_bytes
    from email.header import decode_header
    from email.utils import parsedate_to_datetime
    
    def decode_mime_header(header_value):
        if not header_value:
            return ""
        decoded_parts = decode_header(header_value)
        result = []
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                part = part.decode(encoding or 'utf-8', errors='replace')
            result.append(str(part))
        return ''.join(result)
    
    results = []
    
    with get_imap_connection() as server:
        server.select_folder(folder, readonly=True)
        
        # Search in subject and from
        from_results = server.search(['FROM', query])
        subject_results = server.search(['SUBJECT', query])
        
        # Combine and deduplicate
        all_uids = list(set(from_results + subject_results))[:limit]
        
        if all_uids:
            fetch_results = server.fetch(all_uids, ['RFC822', 'INTERNALDATE'])
            
            for uid in all_uids:
                if uid not in fetch_results or b'RFC822' not in fetch_results[uid]:
                    continue
                
                raw_msg = fetch_results[uid][b'RFC822']
                msg = message_from_bytes(raw_msg)
                
                try:
                    date = parsedate_to_datetime(msg.get('Date', ''))
                    date_str = date.strftime('%Y-%m-%d %H:%M')
                except:
                    date_str = msg.get('Date', 'Unknown')
                
                results.append({
                    "uid": uid,
                    "subject": decode_mime_header(msg.get('Subject', '(No Subject)')),
                    "from": decode_mime_header(msg.get('From', '')),
                    "date": date_str,
                    "folder": folder
                })
    
    return results


@mcp.tool
def retrieve_conversation(
    sender_email: str,
    download_attachments: bool = False,
    output_dir: str = None
) -> dict:
    """
    Retrieve all emails from/to a specific sender and save as markdown.
    
    Args:
        sender_email: Email address of the sender to search for
        download_attachments: Whether to also download PDF/file attachments
        output_dir: Directory to save the output (default: current directory)
        
    Returns:
        Dict with path to generated markdown file and summary
    """
    from email import message_from_bytes
    from email.header import decode_header
    from email.utils import parsedate_to_datetime
    import hashlib
    import html2text
    
    def decode_mime_header(header_value):
        if not header_value:
            return ""
        decoded_parts = decode_header(header_value)
        result = []
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                part = part.decode(encoding or 'utf-8', errors='replace')
            result.append(str(part))
        return ''.join(result)
    
    def extract_email_address(header_value):
        if not header_value:
            return ""
        match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', header_value)
        return match.group(0).lower() if match else header_value.lower()
    
    def get_message_hash(msg):
        message_id = msg.get('Message-ID', '').strip()
        if message_id:
            return hashlib.md5(message_id.encode('utf-8')).hexdigest()
        date = msg.get('Date', '')
        subject = msg.get('Subject', '')
        from_header = msg.get('From', '')
        hash_input = f"{date}|{subject}|{from_header}"
        return hashlib.md5(hash_input.encode('utf-8')).hexdigest()
    
    def get_text_from_email(msg):
        text_content = []
        html_content = []
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                if "attachment" in content_disposition:
                    continue
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        if content_type == "text/plain":
                            text_content.append(payload.decode(charset, errors='replace'))
                        elif content_type == "text/html":
                            html_content.append(payload.decode(charset, errors='replace'))
                except Exception:
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
            except Exception:
                pass
        
        if text_content:
            return '\n\n'.join(text_content)
        elif html_content:
            h = html2text.HTML2Text()
            h.ignore_links = False
            h.body_width = 0
            return '\n\n'.join([h.handle(html) for html in html_content])
        return ""
    
    def get_attachments_from_email(msg):
        attachments = []
        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = str(part.get("Content-Disposition", ""))
                if "attachment" in content_disposition:
                    filename = part.get_filename()
                    if filename:
                        attachments.append({
                            'filename': decode_mime_header(filename),
                            'part': part
                        })
        return attachments
    
    config = get_imap_config()
    sender_email = sender_email.lower().strip()
    messages = {}
    
    skip_folders = {'Drafts', 'Junk', 'Trash', 'Deleted', 'Spam', 'Outbox'}
    
    with get_imap_connection() as server:
        folder_list = server.list_folders()
        folders = [folder_name for flags, delimiter, folder_name in folder_list]
        
        for folder in folders:
            if folder in skip_folders or 'draft' in folder.lower():
                continue
            
            try:
                server.select_folder(folder, readonly=True)
                
                from_results = server.search(['FROM', sender_email])
                to_results = server.search(['TO', sender_email])
                all_uids = list(set(from_results + to_results))
                
                if all_uids:
                    fetch_results = server.fetch(all_uids, ['RFC822', 'INTERNALDATE', 'FLAGS'])
                    
                    for uid in all_uids:
                        if uid not in fetch_results or b'RFC822' not in fetch_results[uid]:
                            continue
                        
                        flags = fetch_results[uid].get(b'FLAGS', ())
                        if b'\\Draft' in flags:
                            continue
                        
                        raw_message = fetch_results[uid][b'RFC822']
                        internal_date = fetch_results[uid].get(b'INTERNALDATE')
                        msg = message_from_bytes(raw_message)
                        msg_hash = get_message_hash(msg)
                        
                        if msg_hash not in messages:
                            messages[msg_hash] = {
                                'uid': uid,
                                'folder': folder,
                                'date': internal_date,
                                'message': msg,
                                'hash': msg_hash
                            }
            except Exception:
                continue
    
    if not messages:
        return {"error": f"No messages found with {sender_email}"}
    
    # Sort by date
    sorted_messages = sorted(messages.values(), key=lambda x: x['date'] if x['date'] else datetime.min)
    
    # Generate output
    safe_email = re.sub(r'[^\w\.-]', '_', sender_email)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    base_dir = Path(output_dir) if output_dir else Path(__file__).parent
    output_file = base_dir / f"conversation_{safe_email}_{timestamp}.md"
    
    attachments_dir = None
    if download_attachments:
        attachments_dir = base_dir / f"conversation_{safe_email}_{timestamp}_attachments"
        attachments_dir.mkdir(parents=True, exist_ok=True)
    
    my_email = config['username'].lower()
    total_attachments = 0
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"# Email Conversation with {sender_email}\n\n")
        f.write(f"**Total Messages:** {len(sorted_messages)} (after deduplication)\n\n")
        f.write(f"**Your Email:** {my_email}\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        if attachments_dir:
            f.write(f"**Attachments Folder:** {attachments_dir.name}\n\n")
        f.write("---\n\n")
        
        for idx, msg_data in enumerate(sorted_messages, 1):
            msg = msg_data['message']
            
            subject = decode_mime_header(msg.get('Subject', '(No Subject)'))
            from_header = decode_mime_header(msg.get('From', ''))
            to_header = decode_mime_header(msg.get('To', ''))
            date_header = msg.get('Date', '')
            
            from_email = extract_email_address(from_header)
            direction = "📤 SENT" if from_email == my_email else "📥 RECEIVED"
            
            try:
                msg_date = parsedate_to_datetime(date_header)
                date_str = msg_date.strftime('%Y-%m-%d %H:%M:%S')
            except:
                date_str = date_header or 'Unknown date'
            
            f.write(f"## Message {idx} {direction}\n\n")
            f.write(f"**Date:** {date_str}\n\n")
            f.write(f"**From:** {from_header}\n\n")
            f.write(f"**To:** {to_header}\n\n")
            f.write(f"**Subject:** {subject}\n\n")
            f.write(f"**Folder:** {msg_data['folder']}\n\n")
            
            attachments = get_attachments_from_email(msg)
            if attachments:
                f.write(f"**Attachments:** {len(attachments)} file(s)\n\n")
                if download_attachments and attachments_dir:
                    for att in attachments:
                        filename = att['filename']
                        safe_filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
                        safe_filename = f"{idx:03d}_{safe_filename}"
                        filepath = attachments_dir / safe_filename
                        try:
                            payload = att['part'].get_payload(decode=True)
                            if payload:
                                filepath.write_bytes(payload)
                                total_attachments += 1
                                f.write(f"  - [{safe_filename}]({attachments_dir.name}/{safe_filename})\n")
                        except Exception:
                            f.write(f"  - {filename} (failed to save)\n")
                else:
                    for att in attachments:
                        f.write(f"  - {att['filename']}\n")
                f.write("\n")
            
            body = get_text_from_email(msg)
            if body:
                f.write("**Message:**\n\n```\n")
                f.write(body.strip())
                f.write("\n```\n\n")
            else:
                f.write("*(No text content)*\n\n")
            
            f.write("---\n\n")
    
    return {
        "output_file": str(output_file),
        "total_messages": len(sorted_messages),
        "attachments_saved": total_attachments if download_attachments else 0,
        "attachments_dir": str(attachments_dir) if attachments_dir else None
    }


@mcp.tool
def get_email_by_uid(uid: int, folder: str = "INBOX") -> dict:
    """
    Get a specific email by its UID.
    
    Args:
        uid: The unique ID of the email
        folder: The folder containing the email
        
    Returns:
        Full email content including body and attachment info
    """
    from email import message_from_bytes
    from email.header import decode_header
    from email.utils import parsedate_to_datetime
    import html2text
    
    def decode_mime_header(header_value):
        if not header_value:
            return ""
        decoded_parts = decode_header(header_value)
        result = []
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                part = part.decode(encoding or 'utf-8', errors='replace')
            result.append(str(part))
        return ''.join(result)
    
    with get_imap_connection() as server:
        server.select_folder(folder, readonly=True)
        fetch_results = server.fetch([uid], ['RFC822'])
        
        if uid not in fetch_results or b'RFC822' not in fetch_results[uid]:
            raise ValueError(f"Email with UID {uid} not found in {folder}")
        
        raw_msg = fetch_results[uid][b'RFC822']
        msg = message_from_bytes(raw_msg)
        
        # Extract body
        text_content = []
        html_content = []
        attachments = []
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                
                if "attachment" in content_disposition:
                    filename = part.get_filename()
                    if filename:
                        attachments.append(decode_mime_header(filename))
                    continue
                
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        if content_type == "text/plain":
                            text_content.append(payload.decode(charset, errors='replace'))
                        elif content_type == "text/html":
                            html_content.append(payload.decode(charset, errors='replace'))
                except Exception:
                    continue
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or 'utf-8'
                if msg.get_content_type() == "text/plain":
                    text_content.append(payload.decode(charset, errors='replace'))
                elif msg.get_content_type() == "text/html":
                    html_content.append(payload.decode(charset, errors='replace'))
        
        # Prefer plain text, convert HTML if needed
        if text_content:
            body = '\n\n'.join(text_content)
        elif html_content:
            h = html2text.HTML2Text()
            h.ignore_links = False
            h.body_width = 0
            body = '\n\n'.join([h.handle(html) for html in html_content])
        else:
            body = "(No text content)"
        
        try:
            date = parsedate_to_datetime(msg.get('Date', ''))
            date_str = date.strftime('%Y-%m-%d %H:%M:%S')
        except:
            date_str = msg.get('Date', 'Unknown')
        
        return {
            "uid": uid,
            "subject": decode_mime_header(msg.get('Subject', '(No Subject)')),
            "from": decode_mime_header(msg.get('From', '')),
            "to": decode_mime_header(msg.get('To', '')),
            "date": date_str,
            "body": body,
            "attachments": attachments
        }


# ============================================================================
# PDF Tools
# ============================================================================

@mcp.tool
def read_pdf(file_path: str) -> str:
    """
    Extract text from a PDF file.
    
    Args:
        file_path: Path to the PDF file
        
    Returns:
        Extracted text content from the PDF
    """
    import pdfplumber
    
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"PDF file not found: {file_path}")
    
    if not path.suffix.lower() == '.pdf':
        raise ValueError(f"File is not a PDF: {file_path}")
    
    with pdfplumber.open(path) as pdf:
        text_parts = []
        for i, page in enumerate(pdf.pages, 1):
            page_text = page.extract_text()
            if page_text:
                text_parts.append(f"--- Page {i} ---\n{page_text}")
        
        if not text_parts:
            return "(No text could be extracted from this PDF)"
        
        return '\n\n'.join(text_parts)


@mcp.tool
def convert_pdf_to_markdown(
    file_path: str,
    output_path: str = None
) -> str:
    """
    Convert a PDF file to Markdown format using Microsoft's MarkItDown library.
    Preserves tables, forms, and document structure as proper Markdown formatting.
    
    Args:
        file_path: Path to the PDF file to convert
        output_path: Optional path to save the markdown file. If not provided,
                     saves alongside the PDF with .md extension
        
    Returns:
        Path to the generated markdown file and preview of content
    """
    from markitdown import MarkItDown
    
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"PDF file not found: {file_path}")
    
    if not path.suffix.lower() == '.pdf':
        raise ValueError(f"File is not a PDF: {file_path}")
    
    # Initialize MarkItDown
    md = MarkItDown()
    
    # Convert the PDF
    result = md.convert(str(path))
    
    # Determine output path
    if output_path:
        out_path = Path(output_path)
    else:
        out_path = path.with_suffix('.md')
    
    # Write the markdown content
    out_path.write_text(result.text_content, encoding='utf-8')
    
    # Return info about the conversion
    preview_length = 500
    preview = result.text_content[:preview_length]
    if len(result.text_content) > preview_length:
        preview += "\n\n... [truncated]"
    
    return f"Converted PDF to Markdown: {out_path}\n\n---\nPreview:\n{preview}"


@mcp.tool
def list_conversation_attachments(conversation_folder: str = None) -> list[dict]:
    """
    List all downloaded attachments from conversations.
    
    Args:
        conversation_folder: Specific folder to list, or None for all
        
    Returns:
        List of attachment files with paths and sizes
    """
    base_path = Path(__file__).parent
    
    if conversation_folder:
        folders = [base_path / conversation_folder]
    else:
        folders = list(base_path.glob("conversation_*_attachments"))
    
    attachments = []
    for folder in folders:
        if folder.is_dir():
            for file in folder.iterdir():
                if file.is_file():
                    attachments.append({
                        "filename": file.name,
                        "path": str(file),
                        "size_kb": round(file.stat().st_size / 1024, 1),
                        "folder": folder.name
                    })
    
    return attachments


@mcp.tool
def download_email_attachment(
    uid: int,
    attachment_name: str,
    folder: str = "INBOX",
    save_dir: str = None
) -> str:
    """
    Download a specific attachment from an email.
    
    Args:
        uid: The unique ID of the email
        attachment_name: Name of the attachment file to download (or partial match)
        folder: The folder containing the email (default: INBOX)
        save_dir: Directory to save the attachment (default: current directory)
        
    Returns:
        Path to the downloaded file
    """
    from email import message_from_bytes
    from email.header import decode_header
    
    def decode_mime_header(header_value):
        if not header_value:
            return ""
        decoded_parts = decode_header(header_value)
        result = []
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                part = part.decode(encoding or 'utf-8', errors='replace')
            result.append(str(part))
        return ''.join(result)
    
    with get_imap_connection() as server:
        server.select_folder(folder, readonly=True)
        fetch_results = server.fetch([uid], ['RFC822'])
        
        if uid not in fetch_results or b'RFC822' not in fetch_results[uid]:
            raise ValueError(f"Email with UID {uid} not found in {folder}")
        
        raw_msg = fetch_results[uid][b'RFC822']
        msg = message_from_bytes(raw_msg)
        
        # Find and save the attachment
        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = str(part.get("Content-Disposition", ""))
                
                if "attachment" in content_disposition:
                    filename = decode_mime_header(part.get_filename() or "")
                    
                    # Match by exact name or partial match
                    if filename and (attachment_name.lower() in filename.lower() or filename.lower() in attachment_name.lower()):
                        # Determine save path
                        if save_dir:
                            save_path = Path(save_dir) / filename
                        else:
                            save_path = Path(__file__).parent / filename
                        
                        # Save the attachment
                        payload = part.get_payload(decode=True)
                        if payload:
                            save_path.write_bytes(payload)
                            return f"Downloaded: {save_path}"
        
        raise ValueError(f"Attachment '{attachment_name}' not found in email UID {uid}")


@mcp.tool
def read_email_attachment_pdf(
    uid: int,
    attachment_name: str = None,
    folder: str = "INBOX"
) -> str:
    """
    Read PDF attachment content directly from an email without saving to disk.
    
    Args:
        uid: The unique ID of the email
        attachment_name: Name of the PDF attachment (optional - uses first PDF if not specified)
        folder: The folder containing the email (default: INBOX)
        
    Returns:
        Text content extracted from the PDF attachment
    """
    from email import message_from_bytes
    from email.header import decode_header
    import pdfplumber
    import io
    
    def decode_mime_header(header_value):
        if not header_value:
            return ""
        decoded_parts = decode_header(header_value)
        result = []
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                part = part.decode(encoding or 'utf-8', errors='replace')
            result.append(str(part))
        return ''.join(result)
    
    with get_imap_connection() as server:
        server.select_folder(folder, readonly=True)
        fetch_results = server.fetch([uid], ['RFC822'])
        
        if uid not in fetch_results or b'RFC822' not in fetch_results[uid]:
            raise ValueError(f"Email with UID {uid} not found in {folder}")
        
        raw_msg = fetch_results[uid][b'RFC822']
        msg = message_from_bytes(raw_msg)
        
        # Find the PDF attachment
        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = str(part.get("Content-Disposition", ""))
                
                if "attachment" in content_disposition:
                    filename = decode_mime_header(part.get_filename() or "")
                    
                    # Check if it's a PDF
                    if filename.lower().endswith('.pdf'):
                        # If attachment_name specified, check for match
                        if attachment_name:
                            if attachment_name.lower() not in filename.lower() and filename.lower() not in attachment_name.lower():
                                continue
                        
                        # Extract PDF content
                        payload = part.get_payload(decode=True)
                        if payload:
                            pdf_buffer = io.BytesIO(payload)
                            try:
                                with pdfplumber.open(pdf_buffer) as pdf:
                                    text_parts = [f"📎 **Attachment:** {filename}\n"]
                                    for i, page in enumerate(pdf.pages, 1):
                                        page_text = page.extract_text()
                                        if page_text:
                                            text_parts.append(f"--- Page {i} ---\n{page_text}")
                                    
                                    if len(text_parts) == 1:
                                        return f"📎 **Attachment:** {filename}\n\n(No text could be extracted from this PDF)"
                                    
                                    return '\n\n'.join(text_parts)
                            except Exception as e:
                                return f"📎 **Attachment:** {filename}\n\nError reading PDF: {str(e)}"
        
        raise ValueError(f"No matching PDF attachment found in email UID {uid}")


# ============================================================================
# Email Sending Tools
# ============================================================================

def get_smtp_access_token(username: str) -> Optional[str]:
    """Get OAuth access token for SMTP based on email provider."""
    username_lower = username.lower()
    
    if any(domain in username_lower for domain in ["@outlook.com", "@hotmail.com", "@live.com"]):
        try:
            from oauth_microsoft import start_microsoft_oauth_flow
            result = start_microsoft_oauth_flow(username)
            return result.get("access_token")
        except Exception as e:
            raise ValueError(f"Microsoft OAuth failed: {e}")
    elif "@gmail.com" in username_lower or "@googlemail.com" in username_lower:
        try:
            from oauth_client import start_oauth_flow
            result = start_oauth_flow(username)
            return result.get("access_token")
        except Exception as e:
            raise ValueError(f"Google OAuth failed: {e}")
    
    return None


def generate_oauth2_string(username: str, access_token: str) -> str:
    """Generate XOAUTH2 authentication string for SMTP."""
    import base64
    auth_string = f"user={username}\x01auth=Bearer {access_token}\x01\x01"
    return base64.b64encode(auth_string.encode()).decode()


@mcp.tool
def send_email(
    to: str,
    subject: str,
    body: str,
    html: bool = False
) -> str:
    """
    Send an email via SMTP with OAuth authentication.
    
    Args:
        to: Recipient email address
        subject: Email subject
        body: Email body (plain text or HTML)
        html: Whether the body is HTML (default: False for plain text)
        
    Returns:
        Confirmation message
    """
    imap_config = get_imap_config()
    username = imap_config["username"]
    
    if not username:
        raise ValueError("IMAP_USERNAME must be set in .env")
    
    # Auto-detect SMTP server based on email provider
    username_lower = username.lower()
    if "gmail" in username_lower:
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
    elif any(d in username_lower for d in ["outlook", "hotmail", "live"]):
        smtp_server = "smtp-mail.outlook.com"
        smtp_port = 587
    else:
        smtp_config = get_smtp_config()
        smtp_server = smtp_config["server"]
        smtp_port = smtp_config["port"]
        if not smtp_server:
            raise ValueError("SMTP_SERVER not configured and could not auto-detect")
    
    # Get OAuth token
    access_token = get_smtp_access_token(username)
    if not access_token:
        raise ValueError(f"Could not get OAuth token for {username}")
    
    # Build the email message
    if html:
        msg = MIMEMultipart("alternative")
        msg.attach(MIMEText(body, "html"))
    else:
        msg = MIMEText(body, "plain")
    
    msg["Subject"] = subject
    msg["From"] = username
    msg["To"] = to
    msg["Date"] = datetime.now().strftime("%a, %d %b %Y %H:%M:%S %z")
    
    # Send via SMTP with OAuth2
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        
        # XOAUTH2 authentication
        auth_string = generate_oauth2_string(username, access_token)
        code, response = server.docmd("AUTH", f"XOAUTH2 {auth_string}")
        
        if code != 235:
            raise ValueError(f"SMTP authentication failed: {code} {response.decode()}")
        
        server.sendmail(username, [to], msg.as_string())
    
    return f"✅ Email sent successfully!\n\nTo: {to}\nSubject: {subject}\nFrom: {username}"


@mcp.tool
def draft_reply(
    original_uid: int,
    reply_body: str,
    folder: str = "INBOX"
) -> str:
    """
    Draft a reply to an email (returns formatted reply, doesn't send).
    
    Args:
        original_uid: UID of the email to reply to
        reply_body: Your reply message
        folder: Folder containing the original email
        
    Returns:
        Formatted reply ready to send
    """
    # Get original email
    original = get_email_by_uid(original_uid, folder)
    
    # Format reply
    reply_subject = original["subject"]
    if not reply_subject.lower().startswith("re:"):
        reply_subject = f"Re: {reply_subject}"
    
    # Extract sender email
    from_header = original["from"]
    import re
    match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', from_header)
    reply_to = match.group(0) if match else from_header
    
    formatted = f"""
To: {reply_to}
Subject: {reply_subject}

{reply_body}

--- Original Message ---
From: {original['from']}
Date: {original['date']}
Subject: {original['subject']}

{original['body'][:500]}{'...' if len(original['body']) > 500 else ''}
"""
    
    return formatted


# ============================================================================
# Resources
# ============================================================================

@mcp.resource("config://email")
def email_config() -> str:
    """Current email configuration."""
    imap = get_imap_config()
    smtp = get_smtp_config()
    
    return f"""
Email Configuration
===================

IMAP (Receiving):
  Server: {imap['server']}
  Port: {imap['port']}
  Username: {imap['username']}

SMTP (Sending):
  Server: {smtp['server'] or '(not configured)'}
  Port: {smtp['port']}
  Username: {smtp['username'] or '(not configured)'}

Authentication: OAuth (Microsoft/Google) or App Password
"""


@mcp.resource("conversations://list")
def list_conversations() -> str:
    """List all exported conversations."""
    base_path = Path(__file__).parent
    conversations = list(base_path.glob("conversation_*.md"))
    
    if not conversations:
        return "No conversations exported yet."
    
    lines = ["Exported Conversations", "=" * 20, ""]
    for conv in sorted(conversations, key=lambda p: p.stat().st_mtime, reverse=True):
        size = round(conv.stat().st_size / 1024, 1)
        mtime = datetime.fromtimestamp(conv.stat().st_mtime).strftime('%Y-%m-%d %H:%M')
        lines.append(f"- {conv.name} ({size} KB, {mtime})")
    
    return '\n'.join(lines)


# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":
    # Run the server
    mcp.run()
