import os
from imapclient import IMAPClient
import sys
import re
from email.header import decode_header

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

EXPORT_DIR = 'mail_export'
os.makedirs(EXPORT_DIR, exist_ok=True)

def list_folders(server):
    folders = server.list_folders()
    folder_names = [folder_name for flags, delimiter, folder_name in folders]
    return folder_names

def prompt_user_for_folders(folder_names):
    print("Available folders:")
    for idx, name in enumerate(folder_names):
        print(f"[{idx}] {name}")
    selected = input("Enter comma-separated numbers of folders to export (e.g. 0,2,3): ")
    try:
        indices = [int(i.strip()) for i in selected.split(',') if i.strip().isdigit()]
        chosen = [folder_names[i] for i in indices if 0 <= i < len(folder_names)]
        return chosen
    except Exception:
        print("Invalid input. No folders selected.")
        return []

def sanitize_folder_name(folder_name):
    # Remove or replace characters not allowed in Windows folder names, including control characters
    sanitized = re.sub(r'[\\/:*?"<>|]', '_', folder_name)
    sanitized = re.sub(r'[\r\n\t]', '', sanitized)  # Remove \r, \n, \t
    sanitized = ''.join(c for c in sanitized if c.isprintable())  # Remove other non-printable chars
    return sanitized

def export_folder(server, folder):
    try:
        server.select_folder(folder, readonly=True)
    except Exception:
        print(f"Skipping {folder} (cannot select)")
        return
    messages = server.search(['ALL'])
    print(f"Exporting {len(messages)} messages from {folder}...")
    folder_dir = os.path.join(EXPORT_DIR, sanitize_folder_name(folder))
    os.makedirs(folder_dir, exist_ok=True)
    for uid in messages:
        fetch_result = server.fetch([uid], ['RFC822'])
        if uid not in fetch_result or b'RFC822' not in fetch_result[uid]:
            print(f"Skipping UID {uid}: message not found or missing RFC822 data.")
            continue
        raw_message = fetch_result[uid][b'RFC822']
        filename = f"{uid}.eml"
        filepath = os.path.join(folder_dir, filename)
        with open(filepath, 'wb') as f:
            f.write(raw_message)

def decode_subject(subject):
    decoded_parts = decode_header(subject)
    decoded_subject = []
    for part, encoding in decoded_parts:
        if isinstance(part, bytes):
            if encoding is not None:
                part = part.decode(encoding)
            else:
                part = part.decode('utf-8', errors='replace')
        decoded_subject.append(part)
    return ''.join(decoded_subject)

def main():
    imap_server, imap_port, username, password = prompt_imap_credentials()
    with IMAPClient(imap_server, port=imap_port, ssl=True) as server:
        server.login(username, password)
        folder_names = list_folders(server)
        exported_folders = set()
        while True:
            # Only show folders that haven't been exported yet
            available_folders = [f for f in folder_names if f not in exported_folders]
            if not available_folders:
                print("All folders have been exported.")
                break
            selected_folders = prompt_user_for_folders(available_folders)
            if not selected_folders:
                print("No folders selected.")
            else:
                for folder in selected_folders:
                    export_folder(server, folder)
                    exported_folders.add(folder)
                print("Export complete for selected folders.")
            again = input("Do you want to export more folders? (y/n): ").strip().lower()
            if again != 'y':
                print("Goodbye.")
                break

if __name__ == "__main__":
    main()