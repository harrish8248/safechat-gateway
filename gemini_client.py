"""
gemini_client.py
----------------
Gemini API client wrapper for SafeChat Gateway.
Uses the official google-genai SDK to generate assistant responses.
Handles missing API keys and API/network errors gracefully without crashing.
"""

import os
from typing import Optional
from dotenv import load_dotenv
from google import genai
from google.genai import types

# Load environment variables from .env file
load_dotenv()

# Default configuration
DEFAULT_MODEL = "gemini-2.5-flash"
SYSTEM_INSTRUCTION = (
    "You are a helpful, polite, and concise AI assistant working inside the "
    "SafeChat Gateway. Provide clear, direct, and factual answers in 1-3 short paragraphs."
)


def get_api_key(custom_key: Optional[str] = None) -> str:
    """
    Returns the active API key, preferring a user-supplied runtime key
    over the .env / environment variable.
    """
    if custom_key and custom_key.strip():
        return custom_key.strip()
    return os.getenv("GEMINI_API_KEY", "").strip()


def get_model_name() -> str:
    """
    Returns the configured Gemini model name from .env or defaults to gemini-2.5-flash.
    """
    return os.getenv("GEMINI_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL


def is_api_key_configured(custom_key: Optional[str] = None) -> bool:
    """
    Checks if a valid, non-placeholder API key is available.
    """
    key = get_api_key(custom_key)
    if not key or key == "your_key_here":
        return False
    return True


def ask_gemini(prompt: str, custom_api_key: Optional[str] = None) -> str:
    """
    Sends a user prompt to Gemini using the google-genai SDK and returns the response.
    
    If the API key is missing or an error occurs during the call,
    a helpful and friendly message is returned so the application never crashes.
    """
    key = get_api_key(custom_api_key)

    if not key or key == "your_key_here":
        return (
            "⚠️ Gemini API Key Missing: Please provide your GEMINI_API_KEY in the `.env` file "
            "or enter it in the sidebar settings. You can still test all input guardrails and "
            "security triggers without an API key!"
        )

    model_name = get_model_name()

    try:
        # Initialize Google GenAI client
        client = genai.Client(api_key=key)

        # Configure system instructions for concise and helpful replies
        config = types.GenerateContentConfig(
            system_instruction=SYSTEM_INSTRUCTION,
            temperature=0.7,
        )

        response = client.models.generate_content(
            model=model_name,
            contents=prompt,
            config=config,
        )

        if response and response.text:
            return response.text.strip()
        return "I processed your request, but no text response was returned."

    except Exception as e:
        error_msg = str(e)
        # Handle common issues with friendly explanations
        if "API_KEY_INVALID" in error_msg or "400" in error_msg and "key" in error_msg.lower():
            return (
                "⚠️ Invalid Gemini API Key: The provided API key was rejected by Google Gemini. "
                "Please check that your GEMINI_API_KEY is correct."
            )
        if "RESOURCE_EXHAUSTED" in error_msg or "429" in error_msg:
            return (
                "⚠️ Quota Exceeded: Your Gemini API rate limit or quota has been reached. "
                "Please wait a moment before trying again."
            )
        return (
            f"⚠️ Gemini API Error: Could not complete the request ({error_msg}). "
            "Please check your network connection and API settings."
        )
