# Complete working example for custom ChatCompletions endpoints
# Works with OpenRouter, Azure OpenAI direct, local models, or any custom endpoint
# Use ENDPOINT_TYPE to explicitly choose which endpoint to use

import os
import asyncio
from dotenv import load_dotenv
from openai import AsyncOpenAI, AsyncAzureOpenAI
from agents import Agent, Runner, trace, OpenAIChatCompletionsModel
from agents.model_settings import ModelSettings

# Import the WebSearch tool
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from custom_endpoints_websearch_tool import web_search

load_dotenv()

# ===== CONFIGURATION =====
ENDPOINT_TYPE = "openrouter"  # Use "openrouter", "azure", or "custom"

INSTRUCTIONS = "You are a research assistant. Given a search term, you search the web for that term and produce a concise summary of the results. The summary must be 2-3 paragraphs and less than 300 words. Capture the main points. Write succinctly, no need to have complete sentences or good grammar. This will be consumed by someone synthesizing a report, so it's vital you capture the essence and ignore any fluff. Do not include any additional commentary other than the summary itself."

def create_model():
    # Create OpenAI model based on ENDPOINT_TYPE
    
    if ENDPOINT_TYPE == "azure":
        print("Using Azure OpenAI direct endpoint")
        client = AsyncAzureOpenAI(
            api_key=os.getenv('AZURE_OPENAI_API_KEY'),
            azure_endpoint=os.getenv('AZURE_OPENAI_ENDPOINT'),
            api_version=os.getenv('AZURE_OPENAI_API_VERSION', '2024-08-01-preview')
        )
        model_name = os.getenv('AZURE_OPENAI_DEPLOYMENT')
        
    elif ENDPOINT_TYPE == "custom":
        print(f"Using custom endpoint: {os.getenv('CUSTOM_BASE_URL')}")
        client = AsyncOpenAI(
            base_url=os.getenv('CUSTOM_BASE_URL'),
            api_key=os.getenv('CUSTOM_API_KEY')
        )
        model_name = os.getenv('CUSTOM_MODEL')
        
    else:  
        print("Using OpenRouter")
        client = AsyncOpenAI(
            base_url=os.getenv('OPENROUTER_BASE_URL', 'https://openrouter.ai/api/v1'),
            api_key=os.getenv('OPENROUTER_API_KEY')
        )
        model_name = os.getenv('OPENROUTER_MODEL', 'openai/gpt-4o-mini')

    model = OpenAIChatCompletionsModel(
        openai_client=client,
        model=model_name)
    
    return model, model_name

async def main():
    try:
        model, model_name = create_model()
        
        agent = Agent(
            name="WebSearch Research Agent",
            instructions=INSTRUCTIONS,
            tools=[web_search],
            model=model,
            model_settings=ModelSettings(tool_choice="required")
        )
        
        query = "Latest AI Agent frameworks in 2025"
        print(f"Model: {model_name}")
        print(f"Query: {query}")
        print("=" * 50)
        
        # Note: You may see trace export warnings below - these are harmless
        # The OpenAI Agents SDK tries to export traces to OpenAI's platform,
        # but this doesn't affect functionality when using custom endpoints
        result = await Runner.run(agent, query) 
        
        print("\n=== Summary ===")
        print(result.final_output)
        
    except Exception as e:
        print(f"Error: {e}")
        print("\nMake sure you have:")
        print("1. Copied .env.example to .env")
        print("2. Set your API keys in .env")
        print("3. Installed requirements: pip install -r requirements.txt")
        print("4. Installed Agents SDK: pip install git+https://github.com/openai/openai-agents-sdk")

if __name__ == "__main__":
    asyncio.run(main())