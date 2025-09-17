# WebSearch Tool for Custom AI Model Endpoints Documentation

## Overview
This Python tool provides drop-in WebSearch functionality for custom AI model endpoints using the OpenAI Agents SDK. It addresses the gap where OpenAI's hosted WebSearchTool doesn't work with custom ChatCompletions endpoints (like OpenRouter, direct Azure OpenAI, or local models). 

**Author:** Manuel Tomas Estarlich  
**Version:** 1.0  
**Date:** 2025-09-17  
**License:** MIT  

## Features
- **Universal Compatibility:** Works with OpenRouter, direct Azure OpenAI, local models, or any ChatCompletions-compatible endpoint.
- **Google SERP Results:** Uses the Serper.dev API for high-quality search results, including answer boxes.
- **Simple Integration:** A clean, drop-in replacement for the hosted WebSearchTool using the standard `function_tool` pattern.
- **Robust Retry Logic:** Includes a simple, built-in retry mechanism for transient network errors (429/5xx).
- **Clean Output:** Returns a structured text format ("Title: snippet (URL)") optimized for LLM consumption.
- **Minimalist & Readable:** Intentionally simple code, easy to understand, modify, and integrate.

## When to Use This Tool

### Use this custom tool when:
- You are using **OpenRouter**, **direct Azure OpenAI**, **local models**, or other custom ChatCompletions endpoints.
- You are using the **OpenAI Agents SDK directly** and not a managed platform like Azure AI Agent Service.
- You need a simple, reliable web search capability for your agents.

### Do NOT use this tool when:
- You are using the **Azure AI Foundry Agent Service**. Instead, use the native "Grounding with Bing Search" for better integration and enterprise features.
- You are using the **OpenAI Platform directly** with their managed models. Instead, use the hosted `WebSearchTool` for integrated billing and support.

**The Problem This Tool Solves:** Hosted tools from major platforms are often locked to their specific environments. This tool fills the gap, providing web search for any custom endpoint that speaks the ChatCompletions language.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/{yourusername}/websearch-custom-endpoints
    cd websearch-custom-endpoints
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    pip install git+https://github.com/openai/openai-agents-sdk
    ```

3.  **Configure your environment:**
    ```bash
    cp .env.example .env
    ```
    Then, edit the newly created `.env` file with your API keys.

## Usage

1.  **Set API Keys:** Configure your custom endpoint (e.g., OpenRouter) and your Serper API key in the `.env` file.

2.  **Import the Tool:** In your agent's Python script, add the following import statement:
    ```python
    from custom_endpoints_websearch_tool import web_search
    ```

3.  **Create Your Agent:** Build your agent using the standard OpenAI Agents SDK pattern. Pass the imported `web_search` tool into the `tools` list when creating your `Agent` instance.

4.  **Run Your Agent:** When the agent's logic requires a web search, it will automatically have the ability to call the `web_search` tool. See `examples/research_agent_demo.py` for a complete, runnable example.

## How It Works
1.  **Tool Call:** Your agent decides to call the `web_search` function tool.
2.  **Search Execution:** The tool calls the Serper.dev API with your query.
3.  **Error Handling:** If a rate limit (429) or server error (5xx) occurs, the tool waits briefly and retries once.
4.  **Result Processing:** It formats the search results, including Google's "Answer Box," into a clean "Title: snippet (URL)" text block.
5.  **Return to Agent:** The formatted text is returned to the agent as the tool's output for summarization or further action.

## Supported Endpoints
- **OpenRouter:** For model selection and cost optimization.
- **Direct Azure OpenAI:** For enterprise security without the full AI Foundry service wrapper.
- **Local Models:** For self-hosted or on-premise deployments (e.g., via LiteLLM or vLLM).
- **Custom APIs:** Any service that implements the standard OpenAI ChatCompletions interface.

## Troubleshooting
- **Import Errors:** Ensure the OpenAI Agents SDK is installed correctly from the GitHub repository, not from PyPI.
- **API Key Issues:** Verify that `SERPER_API_KEY` and your endpoint's API key are set correctly in the `.env` file.
- **Endpoint Failures:** Check your custom endpoint's configuration, model availability, and base URL.
- **Search Timeouts:** Confirm your internet connectivity and check the Serper.dev service status page.
- **Tool Not Called by Agent:** Make sure your agent's instructions clearly mention performing a web search, and that `tool_choice` is configured to allow function calls.

## Roadmap
This tool is intentionally minimal. Based on community feedback, future enhancements may be added as optional modules:
- **Redis Caching:** Add a TTL cache to reduce API calls and lower costs.
- **Production-Grade Retry:** Implement a circuit breaker with exponential backoff.
- **Structured Logging:** Add observability hooks for monitoring and debugging.
- **Enterprise Providers:** Create a separate guide for integrating Bing Web Search with private endpoints.
- **Page Content Extraction:** A new tool to fetch and clean the full content from a URL.

## Contribution
Fork the repository, create a feature branch, and submit a pull request. Focus on reliability improvements, additional providers, or enterprise features. For questions, connect with me on LinkedIn: https://www.linkedin.com/in/manuel-tomas-estarlich/

## Disclaimer
This tool is not affiliated with OpenAI, Microsoft, or Serper.dev. It provides a bridge solution for custom endpoints where hosted tools aren't available. Test thoroughly in non-production environments before deploying. You are responsible for adhering to the terms of service of any API provider you use. Use at your own risk.