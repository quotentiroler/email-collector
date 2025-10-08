"""
PDF Amount Scraper
Processes expense CSV to extract missing amounts from PDF attachments using AI.
"""

import os
import csv
import sys
from pathlib import Path
from dotenv import load_dotenv
import json
import re

# Load environment variables
load_dotenv()

def get_ai_client(provider: str, api_key: str):
    """Initialize the AI client based on provider."""
    if provider.lower() == 'openai':
        try:
            from openai import OpenAI
            return OpenAI(api_key=api_key)
        except ImportError:
            print("Error: openai package not installed. Run: pip install openai")
            sys.exit(1)
    elif provider.lower() == 'anthropic':
        try:
            import anthropic
            return anthropic.Anthropic(api_key=api_key)
        except ImportError:
            print("Error: anthropic package not installed. Run: pip install anthropic")
            sys.exit(1)
    else:
        print(f"Error: Unsupported AI provider '{provider}'. Use 'openai' or 'anthropic'")
        sys.exit(1)


def extract_text_from_pdf(pdf_path: str) -> tuple:
    """Extract text from PDF file."""
    try:
        import pdfplumber
        
        with pdfplumber.open(pdf_path) as pdf:
            # Extract text from all pages
            text = ""
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"
            
            if not text.strip():
                return None, "No text found in PDF"
            
            return text, None
            
    except ImportError:
        # Fallback to PyPDF2
        try:
            from PyPDF2 import PdfReader
            
            reader = PdfReader(pdf_path)
            text = ""
            for page in reader.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"
            
            if not text.strip():
                return None, "No text found in PDF"
            
            return text, None
            
        except ImportError:
            return None, "Neither pdfplumber nor PyPDF2 is installed. Install with: pip install pdfplumber"
        except Exception as e:
            return None, f"PyPDF2 error: {e}"
            
    except Exception as e:
        return None, f"PDF extraction error: {e}"


def pdf_text_to_markdown(text: str) -> str:
    """Convert PDF text to simple markdown format."""
    # Simple cleanup and formatting
    lines = text.split('\n')
    markdown_lines = []
    
    for line in lines:
        line = line.strip()
        if line:
            markdown_lines.append(line)
    
    return '\n'.join(markdown_lines)


def extract_amount_from_pdf_with_openai(pdf_path: str, client, currency: str = "EUR"):
    """Extract amount from PDF using OpenAI by analyzing text."""
    
    # Extract text from PDF
    pdf_text, error = extract_text_from_pdf(pdf_path)
    if error:
        return None, error
    
    # Convert to markdown for better readability
    markdown_text = pdf_text_to_markdown(pdf_text)
    
    # Limit text size (first 3000 chars should contain the total)
    if len(markdown_text) > 3000:
        markdown_text = markdown_text[:3000] + "\n...[truncated]"
    
    # Ask OpenAI to extract the total amount
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "user",
                    "content": f"""You are analyzing an invoice/receipt document. 
Extract the TOTAL amount that was charged/paid. Look for:
- "Total", "Gesamt", "Summe", "Amount Due", "Amount Paid", "Betrag", "Rechnungsbetrag"
- The final amount at the bottom of the document
- Include tax/VAT in the total
- Look for the GRAND TOTAL, not subtotals

Expected currency: {currency}

Document text:
{markdown_text}

Return ONLY a JSON object with this structure:
{{"amount": <number>, "currency": "<3-letter code>", "confidence": <0.0-1.0>}}

If you cannot find a clear total amount, return:
{{"amount": 0, "currency": "{currency}", "confidence": 0.0}}"""
                }
            ],
            max_tokens=300,
            response_format={"type": "json_object"}
        )
        
        result_text = response.choices[0].message.content.strip()
        result = json.loads(result_text)
        return result, None
        
    except Exception as e:
        return None, f"OpenAI API error: {e}"


def extract_amount_from_pdf_with_anthropic(pdf_path: str, client, currency: str = "EUR"):
    """Extract amount from PDF using Anthropic by analyzing text."""
    
    # Extract text from PDF
    pdf_text, error = extract_text_from_pdf(pdf_path)
    if error:
        return None, error
    
    # Convert to markdown
    markdown_text = pdf_text_to_markdown(pdf_text)
    
    # Limit text size
    if len(markdown_text) > 3000:
        markdown_text = markdown_text[:3000] + "\n...[truncated]"
    
    # Ask Claude to extract the total amount
    try:
        message = client.messages.create(
            model="claude-3-5-haiku-20241022",
            max_tokens=300,
            messages=[
                {
                    "role": "user",
                    "content": f"""You are analyzing an invoice/receipt document. 
Extract the TOTAL amount that was charged/paid. Look for:
- "Total", "Gesamt", "Summe", "Amount Due", "Amount Paid", "Betrag", "Rechnungsbetrag"
- The final amount at the bottom of the document
- Include tax/VAT in the total
- Look for the GRAND TOTAL, not subtotals

Expected currency: {currency}

Document text:
{markdown_text}

Return ONLY a JSON object with this structure:
{{"amount": <number>, "currency": "<3-letter code>", "confidence": <0.0-1.0>}}

If you cannot find a clear total amount, return:
{{"amount": 0, "currency": "{currency}", "confidence": 0.0}}"""
                }
            ]
        )
        
        result_text = message.content[0].text.strip()
        
        # Parse JSON response (remove markdown if present)
        if result_text.startswith("```"):
            result_text = result_text.split("```")[1]
            if result_text.startswith("json"):
                result_text = result_text[4:]
            result_text = result_text.strip()
        
        result = json.loads(result_text)
        return result, None
        
    except Exception as e:
        return None, f"Anthropic API error: {e}"


def process_csv_with_missing_amounts(csv_path: str, attachments_dir: str, ai_provider: str, api_key: str):
    """Process CSV to find and update rows with missing amounts but have PDFs."""
    
    if not os.path.exists(csv_path):
        print(f"Error: CSV file not found: {csv_path}")
        return
    
    if not os.path.exists(attachments_dir):
        print(f"Error: Attachments directory not found: {attachments_dir}")
        return
    
    # Initialize AI client
    client = get_ai_client(ai_provider, api_key)
    
    # Read the CSV
    rows = []
    fieldnames = None
    
    with open(csv_path, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        rows = list(reader)
    
    print(f"\n{'='*60}")
    print(f"PDF Amount Scraper")
    print(f"{'='*60}")
    print(f"CSV file: {csv_path}")
    print(f"Total rows: {len(rows)}")
    
    # Find rows with missing amounts but have PDF attachments
    rows_to_process = []
    for idx, row in enumerate(rows):
        amount = float(row.get('amount', 0))
        has_attachments = row.get('has_attachments', 'False').lower() == 'true'
        attachment_files = row.get('attachment_files', '')
        
        # Check if has PDFs
        has_pdf = any(f.lower().endswith('.pdf') for f in attachment_files.split(', ') if f)
        
        if amount == 0 and has_pdf:
            rows_to_process.append((idx, row))
    
    print(f"Rows with missing amounts but have PDFs: {len(rows_to_process)}")
    
    if not rows_to_process:
        print("\n✓ No rows need processing!")
        return
    
    print(f"\n{'='*60}")
    print(f"Processing {len(rows_to_process)} rows...")
    print(f"{'='*60}\n")
    
    updated_count = 0
    failed_count = 0
    
    for idx, row in rows_to_process:
        print(f"\n[{idx+1}/{len(rows)}] {row['subject'][:50]}")
        print(f"  Vendor: {row.get('vendor', 'Unknown')}")
        print(f"  Current amount: {row.get('amount', 0)} {row.get('currency', 'EUR')}")
        
        # Get PDF filenames
        attachment_files = row.get('attachment_files', '')
        pdf_files = [f.strip() for f in attachment_files.split(',') if f.strip().lower().endswith('.pdf')]
        
        if not pdf_files:
            print("  ✗ No PDF files found (skipped)")
            failed_count += 1
            continue
        
        print(f"  PDF files: {', '.join(pdf_files)}")
        
        # Try to extract amount from first PDF
        pdf_path = os.path.join(attachments_dir, pdf_files[0])
        
        if not os.path.exists(pdf_path):
            print(f"  ✗ PDF file not found: {pdf_path}")
            failed_count += 1
            continue
        
        print(f"  Analyzing PDF with AI...")
        
        # Extract amount based on provider
        result = None
        error = None
        
        if ai_provider.lower() == 'openai':
            result, error = extract_amount_from_pdf_with_openai(pdf_path, client, row.get('currency', 'EUR'))
        elif ai_provider.lower() == 'anthropic':
            result, error = extract_amount_from_pdf_with_anthropic(pdf_path, client, row.get('currency', 'EUR'))
        
        if error:
            print(f"  ✗ Error: {error}")
            failed_count += 1
            continue
        
        if result and result.get('amount', 0) > 0:
            new_amount = result['amount']
            new_currency = result.get('currency', row.get('currency', 'EUR'))
            confidence = result.get('confidence', 0.0)
            
            print(f"  ✓ Found amount: {new_amount} {new_currency} (confidence: {confidence:.2f})")
            
            # Update the row
            rows[idx]['amount'] = new_amount
            rows[idx]['currency'] = new_currency
            updated_count += 1
        else:
            print(f"  ✗ Could not extract amount from PDF")
            failed_count += 1
    
    # Write back to CSV
    if updated_count > 0 and fieldnames:
        with open(csv_path, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        
        print(f"\n{'='*60}")
        print(f"✓ CSV updated successfully!")
        print(f"{'='*60}")
        print(f"Rows updated: {updated_count}")
        print(f"Rows failed: {failed_count}")
        print(f"CSV file: {csv_path}")
    else:
        print(f"\n{'='*60}")
        print(f"✗ No rows were updated")
        print(f"{'='*60}")
        print(f"Rows failed: {failed_count}")


def main():
    """Main entry point."""
    
    # Get AI provider and API key
    ai_provider = os.getenv('AI_PROVIDER', 'openai').lower()
    
    if ai_provider == 'openai':
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            print("Error: OPENAI_API_KEY not found in environment")
            print("Please set it in your .env file")
            sys.exit(1)
    elif ai_provider == 'anthropic':
        api_key = os.getenv('ANTHROPIC_API_KEY')
        if not api_key:
            print("Error: ANTHROPIC_API_KEY not found in environment")
            print("Please set it in your .env file")
            sys.exit(1)
    else:
        print(f"Error: Unknown AI_PROVIDER '{ai_provider}'. Use 'openai' or 'anthropic'")
        sys.exit(1)
    
    print(f"Using AI provider: {ai_provider}")
    
    # Get year
    year_input = input("Year of expenses CSV (default 2025): ").strip()
    year = int(year_input) if year_input else 2025
    
    # Construct paths
    expense_dir = f'expenses_{year}'
    csv_path = os.path.join(expense_dir, f'expenses_{year}.csv')
    attachments_dir = os.path.join(expense_dir, 'attachments')
    
    # Process the CSV
    process_csv_with_missing_amounts(csv_path, attachments_dir, ai_provider, api_key)


if __name__ == '__main__':
    main()
