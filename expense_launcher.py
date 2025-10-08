"""
Expense Collector Launcher
Prompts for credentials and runs the expense collector
"""
import csv
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional


def _find_latest_expense_csv(base_dir: Path) -> Optional[Path]:
    """Return the most recent expenses_YYYY.csv file if available."""
    candidate_csvs: list[Path] = []

    for folder in base_dir.iterdir():
        if not folder.is_dir() or not folder.name.startswith("expenses_"):
            continue

        year_suffix = folder.name[len("expenses_"):]
        if not year_suffix.isdigit():
            continue

        csv_path = folder / f"expenses_{year_suffix}.csv"
        if csv_path.exists():
            candidate_csvs.append(csv_path)

    if not candidate_csvs:
        return None

    return max(candidate_csvs, key=lambda path: path.stat().st_mtime)


def _row_has_pdf(row: dict) -> bool:
    """Heuristically determine whether a CSV row references any PDF attachment."""
    attachment_columns = [
        "attachment_files",
        "attachment_filenames",
        "attachments",
        "pdf_files",
        "attachments_saved",
    ]

    for column in attachment_columns:
        value = row.get(column)
        if not value:
            continue

        if isinstance(value, bool):
            if value:
                return True
            continue

        text_value = str(value)
        # Split on common delimiters
        parts = [part.strip() for part in text_value.replace(";", ",").split(",") if part.strip()]
        if any(part.lower().endswith(".pdf") for part in parts):
            return True

    # Fall back to boolean indicators
    for column in ("has_pdf_attachments", "has_attachments"):
        value = row.get(column)
        if isinstance(value, bool):
            if value:
                return True
        elif isinstance(value, str):
            if value.strip().lower() in {"true", "1", "yes", "y"}:
                return True

    return False


def _count_zero_amount_rows_with_pdf(csv_path: Path) -> int:
    """Count rows where amount == 0 and at least one PDF is referenced."""
    try:
        with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            count = 0
            for row in reader:
                amount_raw = (row.get("amount") or "").strip().replace(",", ".")
                try:
                    amount_value = float(amount_raw) if amount_raw else 0.0
                except ValueError:
                    amount_value = 0.0

                if amount_value != 0.0:
                    continue

                if _row_has_pdf(row):
                    count += 1

            return count
    except FileNotFoundError:
        return 0


def _prompt_and_run_pdf_scraper(csv_path: Path, base_dir: Path) -> None:
    """Ask the user whether to run the PDF amount scraper and execute it when requested."""
    attachments_dir = csv_path.parent / "attachments"

    provider = os.getenv("AI_PROVIDER", "openai").strip().lower() or "openai"
    if provider not in {"openai", "anthropic"}:
        provider = "openai"

    api_key_var = "OPENAI_API_KEY" if provider == "openai" else "ANTHROPIC_API_KEY"
    api_key = os.getenv(api_key_var, "").strip()

    # Try calling the scraper module directly first
    try:
        import pdf_amount_scraper as scraper

        if not api_key:
            print(f"No {provider.title()} API key found; required for PDF amount scraping.")
            api_key = input(f"Enter {provider.title()} API key (leave empty to cancel): ").strip()
            if not api_key:
                print("Skipping PDF amount scraper.")
                return

        if hasattr(scraper, "process_csv_with_missing_amounts"):
            scraper.process_csv_with_missing_amounts(
                str(csv_path),
                str(attachments_dir),
                provider,
                api_key,
            )
            return

        if hasattr(scraper, "main"):
            scraper.main()
            return
    except Exception as exc:
        print(f"Could not invoke pdf_amount_scraper directly ({exc}). Attempting subprocess...")

    scraper_path = base_dir / "pdf_amount_scraper.py"
    if not scraper_path.exists():
        print("pdf_amount_scraper.py not found. Skipping.")
        return

    # Last resort: launch as a separate process (interactive)
    subprocess.run([sys.executable, str(scraper_path)], check=False)

def setup_environment():
    """Prompt user for credentials and set up environment."""
    print("="*60)
    print("Expense Collector - Initial Setup")
    print("="*60)
    print()
    
    # Get the directory where the exe/script is located
    if getattr(sys, 'frozen', False):
        # Running as compiled exe
        app_dir = Path(sys.executable).parent
    else:
        # Running as script
        app_dir = Path(__file__).parent
    
    env_file = app_dir / '.env'
    
    # Check if .env already exists
    if env_file.exists():
        print(f"✓ Found existing configuration: {env_file}")
        use_existing = input("Use existing credentials? (y/n, default y): ").strip().lower()
        if use_existing != 'n':
            print("Using existing credentials from .env file")
            return
        print()
    
    # Prompt for OpenAI API key
    print("OpenAI API Key (required for AI expense analysis)")
    print("Get your key from: https://platform.openai.com/api-keys")
    openai_key = input("Enter OpenAI API key: ").strip()
    
    if not openai_key:
        print("ERROR: OpenAI API key is required!")
        input("Press Enter to exit...")
        sys.exit(1)
    
    print()
    
    # Prompt for optional Google App Password
    print("Google App Password (optional, for Gmail IMAP access)")
    print("Only needed if using Gmail with 2-step verification")
    print("Create one at: https://myaccount.google.com/apppasswords")
    print("Leave empty to skip (you can use OAuth or enter password each time)")
    google_password = input("Enter Google App Password (optional): ").strip()
    
    print()
    
    # Prompt for optional Anthropic key
    print("Anthropic API Key (optional, alternative to OpenAI)")
    print("Get your key from: https://console.anthropic.com/")
    anthropic_key = input("Enter Anthropic API key (optional): ").strip()
    
    # Write to .env file
    env_content = f"""# Expense Collector Configuration
# Generated by expense_launcher.py

# OpenAI API Key (required for AI analysis)
OPENAI_API_KEY={openai_key}
"""
    
    if google_password:
        env_content += f"\n# Google App Password (for Gmail IMAP)\nGOOGLE_APP_PASSWORD={google_password}\n"
    
    if anthropic_key:
        env_content += f"\n# Anthropic API Key (alternative AI provider)\nANTHROPIC_API_KEY={anthropic_key}\n"
    
    env_content += "\n# Default AI provider (anthropic or openai)\nAI_PROVIDER=openai\n"
    
    try:
        with open(env_file, 'w', encoding='utf-8') as f:
            f.write(env_content)
        print(f"\n✓ Configuration saved to: {env_file}")
    except Exception as e:
        print(f"\nERROR: Could not save configuration: {e}")
        input("Press Enter to exit...")
        sys.exit(1)

def main():
    """Main entry point."""
    try:
        # Setup environment
        setup_environment()
        
        print("\n" + "="*60)
        print("Starting Expense Collector...")
        print("="*60 + "\n")
        
        # Import and run the collector
        # This needs to be after setup_environment() so .env is loaded
        from dotenv import load_dotenv
        load_dotenv()
        
        # Determine base directory (script or executable)
        if getattr(sys, 'frozen', False):
            base_dir = Path(sys.executable).parent
        else:
            base_dir = Path(__file__).parent

        # Import the main collector module
        import collect_expenses

        # Run the main function
        collect_expenses.main()

        # After collection, check for missing amounts that can be filled
        latest_csv = _find_latest_expense_csv(base_dir)

        if latest_csv is None:
            print("\nNo expenses CSV found after collection. Skipping PDF amount scraper.")
        else:
            zero_pdf_rows = _count_zero_amount_rows_with_pdf(latest_csv)

            if zero_pdf_rows == 0:
                print("\nAll expenses with PDFs already have amounts. No further action needed.")
            else:
                print("\n" + "="*60)
                print(f"Detected {zero_pdf_rows} expense row(s) in {latest_csv.name} with amount 0.00 and PDF attachments.")
                choice = input("Run the PDF amount scraper now? (Y/n): ").strip().lower()

                if choice in {"", "y", "yes"}:
                    _prompt_and_run_pdf_scraper(latest_csv, base_dir)
                else:
                    print("Skipping PDF amount scraper for now.")
        
    except KeyboardInterrupt:
        print("\n\nCancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n\nERROR: {e}")
        import traceback
        traceback.print_exc()
        input("\nPress Enter to exit...")
        sys.exit(1)

if __name__ == "__main__":
    main()
