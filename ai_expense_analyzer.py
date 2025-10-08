"""
AI Integration for Expense Analysis
Supports OpenAI and Anthropic Claude
"""

import json
import math
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Pricing information for OpenAI GPT-5 family (per 1M tokens)
OPENAI_PRICING_PER_MILLION = {
    "gpt-5": {
        "input": 1.25,
        "output": 10.0,
    },
    "gpt-5-mini": {
        "input": 0.25,
        "output": 1.0,
    },
}


def _limit_confidence(result: dict, ceiling: float = 0.2) -> None:
    confidence = result.get("confidence")
    if isinstance(confidence, (int, float)):
        confidence_value = float(confidence)
    else:
        try:
            confidence_value = float(str(confidence))
        except (TypeError, ValueError):
            confidence_value = 0.0
    result["confidence"] = min(confidence_value, ceiling)


def _normalize_ai_result(result: dict | None, has_attachments: bool = False) -> dict | None:
    """Post-process AI output to enforce safety checks."""
    if not isinstance(result, dict):
        return None

    amount_value = result.get("amount")
    normalized_amount: float | None = None

    if isinstance(amount_value, (int, float)):
        normalized_amount = float(amount_value)
    elif isinstance(amount_value, str):
        try:
            normalized_amount = float(amount_value.strip())
        except ValueError:
            normalized_amount = None
    elif amount_value is not None:
        try:
            normalized_amount = float(amount_value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            normalized_amount = None

    if normalized_amount is None or not math.isfinite(normalized_amount):
        normalized_amount = None

    if normalized_amount is not None and normalized_amount < 0:
        normalized_amount = abs(normalized_amount)

    # Allow zero amounts if there are attachments (amount might be in PDF)
    # But still reject if amount is missing entirely and no attachments
    if normalized_amount is None or (normalized_amount <= 0 and not has_attachments):
        result["is_expense"] = False
        result["amount"] = 0.0
        _limit_confidence(result)
    elif normalized_amount == 0 and has_attachments:
        # Keep as expense if there are attachments - amount is likely in the PDF
        result["is_expense"] = True  # Force to True since we have PDF to check
        result["amount"] = 0.0
        result["description"] = result.get("description", "") + " (amount in PDF)"
    else:
        # Positive amount found - keep as expense
        result["amount"] = normalized_amount

    # Normalize and trim string fields
    for key in ("vendor", "currency", "category", "description"):
        value = result.get(key, "")
        if isinstance(value, str):
            cleaned = value.strip()
        elif value is None:
            cleaned = ""
        else:
            cleaned = str(value).strip()
        result[key] = cleaned

    # Check vendor and currency - but allow empty currency if there are attachments
    vendor_ok = bool(result.get("vendor"))
    currency_ok = bool(result.get("currency"))
    
    if not vendor_ok:
        result["is_expense"] = False
        result["amount"] = 0.0
        _limit_confidence(result)
    elif not currency_ok and not has_attachments:
        # No currency and no PDF to check - reject
        result["is_expense"] = False
        result["amount"] = 0.0
        _limit_confidence(result)
    elif not currency_ok and has_attachments:
        # No currency but has PDF - keep but set default
        result["currency"] = "EUR"

    return result


def summarize_openai_usage(model: str, usage) -> dict | None:
    """Return a dictionary with token usage and estimated USD cost for supported models."""
    if not usage:
        return None

    usage_dict = {}
    for key in ("input_tokens", "output_tokens", "total_tokens"):
        value = getattr(usage, key, None)
        if value is None and isinstance(usage, dict):
            value = usage.get(key)
        if value is not None:
            usage_dict[key] = value

    if not usage_dict:
        return None

    model_key = (model or "").lower()
    pricing = OPENAI_PRICING_PER_MILLION.get(model_key)

    cost = None
    if pricing:
        input_tokens = usage_dict.get("input_tokens", 0)
        output_tokens = usage_dict.get("output_tokens", 0)
        cost = (
            (input_tokens * pricing["input"]) + (output_tokens * pricing["output"])
        ) / 1_000_000

    summary = {
        "model": model,
        **usage_dict,
    }
    if cost is not None:
        summary["estimated_cost_usd"] = round(cost, 6)

    return summary

def analyze_expense_with_openai(email_info, api_key, has_attachments=False):
    """Analyze expense using OpenAI GPT with Responses API."""
    try:
        from openai import OpenAI
    except ImportError:
        print("  Warning: openai package not installed. Install with: pip install openai")
        return None, None

    prompt = f"""Analyze this email and extract expense information if it's a business expense.

IMPORTANT RULES:
- Only mark is_expense=true when you can find a POSITIVE numeric amount, vendor name, and currency in the email
- If amount is 0 or missing, set is_expense=false
- If currency is unknown or missing, use empty string ""
- Currency must be a 3-letter code (EUR, USD, GBP) or empty string, never use placeholders like "unknown"

Email Details:
- Subject: {email_info['subject']}
- From: {email_info['from']}
- Date: {email_info['date']}
- Has PDF: {email_info['has_pdf']}
- Has Image: {email_info['has_image']}
- Body Preview: {email_info['body']}

Extract:
1. Is this a business expense with a clear amount?
2. Vendor/Company name
3. Amount (numeric value only, 0 if not found)
4. Currency (3-letter code like EUR/USD/GBP, or empty string if not found)
5. Category (Office Supplies, Travel, Software, Services, Utilities, Meals, etc.)
6. Brief description"""

    client = OpenAI(api_key=api_key)
    model_name = "gpt-5"

    try:
        response = client.responses.create(
            model=model_name,
            instructions="You are an expert accountant analyzing business expenses from emails.",
            input=prompt,
            text={
                "format": {
                    "type": "json_schema",
                    "name": "expense_analysis",
                    "schema": {
                        "type": "object",
                        "properties": {
                            "is_expense": {"type": "boolean"},
                            "vendor": {"type": "string"},
                            "amount": {"type": "number", "minimum": 0},
                            "currency": {"type": "string"},
                            "category": {"type": "string"},
                            "description": {"type": "string"},
                            "confidence": {"type": "number", "minimum": 0, "maximum": 1}
                        },
                        "required": [
                            "is_expense",
                            "vendor",
                            "amount",
                            "currency",
                            "category",
                            "description",
                            "confidence",
                        ],
                        "additionalProperties": False,
                    },
                    "strict": True,
                }
            },
        )
    except Exception as e:
        print(f"  Error calling OpenAI API: {e}")
        return None, None

    usage_summary = summarize_openai_usage(model_name, getattr(response, "usage", None))
    if usage_summary:
        input_tokens = usage_summary.get("input_tokens", 0)
        output_tokens = usage_summary.get("output_tokens", 0)
        total_tokens = usage_summary.get("total_tokens", 0)
        cost_display = usage_summary.get("estimated_cost_usd")
        cost_text = f"${cost_display:.6f}" if cost_display is not None else "n/a"
        print(
            f"  OpenAI usage ({model_name}): input={input_tokens}, output={output_tokens}, "
            f"total={total_tokens}, est. cost={cost_text}"
        )

    if response.status == "completed" and response.output:
        for item in response.output:
            if hasattr(item, "type") and item.type == "message":
                if hasattr(item, "content") and item.content:
                    for content_item in item.content:
                        # Check for both output_text and json_output types
                        if hasattr(content_item, "type"):
                            if content_item.type == "output_text":
                                result_text = content_item.text
                                
                                try:
                                    result = json.loads(result_text)
                                except json.JSONDecodeError as e:
                                    print(f"  ⚠️  JSON parsing error: {e}")
                                    print(f"  Raw response: {result_text[:500]}")
                                    return None, usage_summary
                                
                                normalized = _normalize_ai_result(result, has_attachments)
                                return normalized, usage_summary
                            
                            elif content_item.type == "json_output":
                                # Structured output returns JSON directly
                                if hasattr(content_item, "json_output"):
                                    result = content_item.json_output
                                    normalized = _normalize_ai_result(result, has_attachments)
                                    return normalized, usage_summary

    return None, usage_summary

def analyze_expense_with_anthropic(email_info, api_key, has_attachments=False):
    """Analyze expense using Anthropic Claude."""
    try:
        import anthropic  # type: ignore[import-not-found]
    except ImportError:
        print("  Warning: anthropic package not installed. Install with: pip install anthropic")
        return None, None

    prompt = f"""Analyze this email and extract expense information if it's a business expense.

Email Details:
- Subject: {email_info['subject']}
- From: {email_info['from']}
- Date: {email_info['date']}
- Has PDF: {email_info['has_pdf']}
- Has Image: {email_info['has_image']}
- Body Preview: {email_info['body']}

Extract the following information:
1. Is this a business expense? (yes/no)
2. Vendor/Company name
3. Amount (numeric only)
4. Currency (EUR, USD, etc.)
5. Category (Office Supplies, Travel, Software, Services, Utilities, etc.)
6. Brief description

Rules:
- Only respond with "is_expense": true when you can quote a clear, positive numeric amount, the vendor/company name, and the billing currency from the message.
- If any required detail is missing, unclear, or the amount is zero, respond with "is_expense": false and set the amount to 0.0.
- Keep the description short (one sentence).

Respond ONLY with a JSON object in this exact format:
{
    "is_expense": true,
    "vendor": "vendor name",
    "amount": 0.00,
    "currency": "EUR",
    "category": "category",
    "description": "brief description",
    "confidence": 0.9
}"""

    client = anthropic.Anthropic(api_key=api_key)

    try:
        message = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1024,
            temperature=0.3,
            messages=[{"role": "user", "content": prompt}],
        )
    except Exception as e:
        print(f"  Error calling Anthropic API: {e}")
        return None, None

    if not getattr(message, "content", None):
        return None, None

    first_chunk = message.content[0]
    result_text = getattr(first_chunk, "text", "").strip()

    if result_text.startswith("```"):
        parts = result_text.split("```", 2)
        if len(parts) >= 2:
            result_text = parts[1]
            if result_text.startswith("json"):
                result_text = result_text[4:]
    result_text = result_text.strip()

    try:
        result = json.loads(result_text)
    except json.JSONDecodeError:
        print("  Error: Anthropic response was not valid JSON")
        return None, None

    normalized = _normalize_ai_result(result, has_attachments)
    return normalized, None

def analyze_with_ai(email_info, api_key, provider='anthropic', has_attachments=False):
    """
    Main function to analyze email with AI.
    
    Args:
        email_info: Dict with email data
        api_key: API key for the chosen provider
        provider: 'openai' or 'anthropic'
        has_attachments: Whether the email has PDF attachments
    
    Returns:
        Tuple of (result_dict or None, usage_summary or None)
    """
    if not api_key:
        return None, None
    
    if provider.lower() == 'openai':
        return analyze_expense_with_openai(email_info, api_key, has_attachments)
    elif provider.lower() == 'anthropic':
        return analyze_expense_with_anthropic(email_info, api_key, has_attachments)
    else:
        print(f"Unknown provider: {provider}")
        return None, None

# Example usage
if __name__ == "__main__":
    # Test data
    test_email = {
        'subject': 'Rechnung #12345 - Microsoft Azure',
        'from': 'billing@microsoft.com',
        'date': '2025-01-15',
        'has_pdf': True,
        'has_image': False,
        'body': 'Sehr geehrter Kunde, anbei finden Sie Ihre Rechnung über 125,50 EUR für Azure Services.'
    }
    
    # Test with your API key
    api_key = os.getenv('ANTHROPIC_API_KEY') or os.getenv('OPENAI_API_KEY')
    if api_key:
        provider = 'anthropic' if os.getenv('ANTHROPIC_API_KEY') else 'openai'
        result, usage = analyze_with_ai(test_email, api_key, provider)
        print(json.dumps(result, indent=2))
        if usage:
            print(json.dumps(usage, indent=2))
    else:
        print("No API key found. Set ANTHROPIC_API_KEY or OPENAI_API_KEY environment variable.")
