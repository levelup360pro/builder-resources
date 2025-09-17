# WebSearch tool for custom AI model endpoints, i.e. custom ChatCompletions endpoints
# Replaces OpenAI's hosted WebSearchTool that doesn't work on custom endpoints
# Uses Serper.dev for Google SERP results

import os
import time
import requests
from agents import function_tool

def _http_with_retry(method: str, url: str, **kwargs) -> dict:
    """Simple HTTP with one retry on 429/5xx"""
    for attempt in range(2):
        try:
            r = requests.request(method, url, timeout=15, **kwargs)
            if r.status_code in (429, 500, 502, 503, 504) and attempt == 0:
                time.sleep(1)
                continue
            r.raise_for_status()
            return r.json()
        except Exception as e:
            if attempt == 1:
                raise RuntimeError(f"Search failed: {e}")
            time.sleep(0.5)

@function_tool
def web_search(query: str, count: int = 8) -> str:
    #Search the web using Serper.dev (Google SERP) and return results as text lines.
    #Returns: Newline-separated results in format "Title: snippet (URL)"
    
    api_key = os.getenv("SERPER_API_KEY")
    if not api_key:
        raise RuntimeError("SERPER_API_KEY required")
    
    count = max(1, min(count, 20))
    
    data = _http_with_retry(
        "POST",
        "https://google.serper.dev/search",
        headers={"X-API-KEY": api_key, "Content-Type": "application/json"},
        json={"q": query, "num": count}
    )
    
    results = []
    # Add answer box if present
    if data.get("answerBox", {}).get("snippet"):
        ab = data["answerBox"]
        results.append(f"AnswerBox: {ab['snippet']} ({ab.get('link', '')})")
    
    # Add organic results
    for item in data.get("organic", []):
        title = item.get("title", "").strip()
        snippet = item.get("snippet", "").strip()
        url = item.get("link", "").strip()
        if title and url:
            results.append(f"{title}: {snippet} ({url})")
    
    return "\n".join(results) if results else "No results found"