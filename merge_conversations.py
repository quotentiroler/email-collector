"""
Merge multiple email conversation markdown files into a single chronological file.
Deduplicates messages based on date, subject, and sender.
"""

import re
import sys
from datetime import datetime
from pathlib import Path


def parse_messages(filepath: Path) -> dict:
    """Parse messages from a conversation markdown file."""
    content = filepath.read_text(encoding='utf-8')
    messages = {}
    
    # Pattern to match message blocks
    pattern = (
        r'## Message \d+ (📥 RECEIVED|📤 SENT)\n\n'
        r'\*\*Date:\*\* (.+?)\n\n'
        r'\*\*From:\*\* (.+?)\n\n'
        r'\*\*To:\*\* (.+?)\n\n'
        r'\*\*Subject:\*\* (.+?)\n\n'
        r'\*\*Folder:\*\* (.+?)\n\n'
        r'\*\*Message:\*\*\n\n```\n(.*?)```'
    )
    
    for match in re.finditer(pattern, content, re.DOTALL):
        direction, date_str, from_addr, to_addr, subject, folder, body = match.groups()
        
        # Parse date
        try:
            date = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            print(f"Warning: Could not parse date '{date_str}', skipping message")
            continue
        
        # Create unique key from date + subject + from (truncated to avoid minor differences)
        key = f'{date_str}|{subject[:50]}|{from_addr[:30]}'
        
        if key not in messages:
            messages[key] = {
                'direction': direction,
                'date_str': date_str,
                'date': date,
                'from': from_addr,
                'to': to_addr,
                'subject': subject,
                'folder': folder,
                'body': body
            }
    
    return messages


def merge_conversations(input_files: list[Path], output_file: Path) -> int:
    """Merge multiple conversation files into one."""
    all_messages = {}
    
    for filepath in input_files:
        if not filepath.exists():
            print(f"Warning: File not found: {filepath}")
            continue
        
        print(f"Reading: {filepath.name}")
        messages = parse_messages(filepath)
        print(f"  Found {len(messages)} messages")
        
        # Merge, keeping first occurrence
        for key, msg in messages.items():
            if key not in all_messages:
                all_messages[key] = msg
    
    # Sort by date
    sorted_msgs = sorted(all_messages.values(), key=lambda x: x['date'])
    
    # Gather statistics
    stats = {
        'sent': 0,
        'received': 0,
        'by_folder': {},
        'by_from': {},
        'by_to': {},
    }
    
    for msg in sorted_msgs:
        if '📤 SENT' in msg['direction']:
            stats['sent'] += 1
        else:
            stats['received'] += 1
        
        # Count by folder
        folder = msg['folder']
        stats['by_folder'][folder] = stats['by_folder'].get(folder, 0) + 1
        
        # Extract email addresses
        from_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', msg['from'])
        to_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', msg['to'])
        
        if from_match:
            from_email = from_match.group(0).lower()
            stats['by_from'][from_email] = stats['by_from'].get(from_email, 0) + 1
        
        if to_match:
            to_email = to_match.group(0).lower()
            stats['by_to'][to_email] = stats['by_to'].get(to_email, 0) + 1
    
    # Write merged file
    with output_file.open('w', encoding='utf-8') as f:
        # Extract sender email from first received message
        sender_email = "unknown"
        for msg in sorted_msgs:
            if '📥 RECEIVED' in msg['direction']:
                match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', msg['from'])
                if match:
                    sender_email = match.group(0).lower()
                    break
        
        f.write(f'# Email Conversation with {sender_email} (MERGED)\n\n')
        f.write(f'**Total Messages:** {len(sorted_msgs)} (merged and deduplicated)\n\n')
        f.write(f'**Source Files:** {", ".join(p.name for p in input_files)}\n\n')
        f.write(f'**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n\n')
        
        # Date range
        if sorted_msgs:
            f.write(f'**Date Range:** {sorted_msgs[0]["date_str"]} to {sorted_msgs[-1]["date_str"]}\n\n')
        
        f.write('---\n\n')
        f.write('## Summary\n\n')
        f.write(f'| Direction | Count |\n')
        f.write(f'|-----------|-------|\n')
        f.write(f'| 📤 Sent | {stats["sent"]} |\n')
        f.write(f'| 📥 Received | {stats["received"]} |\n\n')
        
        f.write('### Messages by Sender\n\n')
        f.write('| From | Count |\n')
        f.write('|------|-------|\n')
        for email, count in sorted(stats['by_from'].items(), key=lambda x: -x[1]):
            f.write(f'| {email} | {count} |\n')
        f.write('\n')
        
        f.write('### Messages by Recipient\n\n')
        f.write('| To | Count |\n')
        f.write('|----|-------|\n')
        for email, count in sorted(stats['by_to'].items(), key=lambda x: -x[1]):
            f.write(f'| {email} | {count} |\n')
        f.write('\n')
        
        f.write('### Messages by Folder/Account\n\n')
        f.write('| Folder | Count |\n')
        f.write('|--------|-------|\n')
        for folder, count in sorted(stats['by_folder'].items(), key=lambda x: -x[1]):
            f.write(f'| {folder} | {count} |\n')
        f.write('\n')
        
        f.write('---\n\n')
        
        for i, msg in enumerate(sorted_msgs, 1):
            f.write(f'## Message {i} {msg["direction"]}\n\n')
            f.write(f'**Date:** {msg["date_str"]}\n\n')
            f.write(f'**From:** {msg["from"]}\n\n')
            f.write(f'**To:** {msg["to"]}\n\n')
            f.write(f'**Subject:** {msg["subject"]}\n\n')
            f.write(f'**Folder:** {msg["folder"]}\n\n')
            f.write('**Message:**\n\n')
            f.write('```\n')
            f.write(msg['body'])
            f.write('```\n\n')
            f.write('---\n\n')
    
    return len(sorted_msgs)


def main():
    if len(sys.argv) < 3:
        print("Usage: python merge_conversations.py <file1.md> <file2.md> [file3.md ...] [-o output.md]")
        print()
        print("Merges multiple conversation markdown files into a single chronological file.")
        print("Deduplicates messages based on date, subject, and sender.")
        print()
        print("Options:")
        print("  -o, --output    Output filename (default: conversation_MERGED.md)")
        print()
        print("Example:")
        print("  python merge_conversations.py conversation_gmail.md conversation_work.md -o merged.md")
        sys.exit(1)
    
    # Parse arguments
    input_files = []
    output_file = None
    
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] in ('-o', '--output'):
            if i + 1 < len(args):
                output_file = Path(args[i + 1])
                i += 2
            else:
                print("Error: -o requires an output filename")
                sys.exit(1)
        else:
            input_files.append(Path(args[i]))
            i += 1
    
    if not input_files:
        print("Error: No input files specified")
        sys.exit(1)
    
    # Default output filename
    if output_file is None:
        output_file = Path("conversation_MERGED.md")
    
    print(f"\nMerging {len(input_files)} files...")
    count = merge_conversations(input_files, output_file)
    print(f"\n✓ Merged {count} unique messages into: {output_file}")


if __name__ == "__main__":
    main()
