# LevelUp360 Builder Resources

## Overview
Welcome to the LevelUp360 Builder Resources repository! This is your one-stop hub for free, practical tools and resources I've developed as part of my hands-on work as a Cloud & AI Solutions Architect. Focused on bridging theoretical knowledge to real-world enterprise implementation, these resources span secure Azure infrastructure, AI governance, cloud architecture, and practical AI agent development tools. Everything here is a byproduct of my designs and builds, and is shared under an MIT license to help aspiring and experienced technical professionals level up their skills.

Whether you're a junior engineer translating small-scale projects to enterprise demands, a transitioning IT pro pivoting to cloud/AI, or a seasoned architect optimizing for security and cost, these tools are designed to save you time and demonstrate implementation mastery across the full spectrum of modern technical challenges.

This repo is for sharing resources only—no contributions or pull requests are accepted. If you find these useful, star the repo, fork it for personal use, or connect with me on LinkedIn for discussions.

## Available Resources
Below is a curated list of free resources, organized by sub-folder. Each includes a brief description and direct link. I'll add more as I build and share from my projects.

| Resource | Description | Link |
|----------|-------------|------|
| **Azure Diag Policy Builder** | A Python script to automate customization of 148+ Azure diagnostic policies, adding parameters for dedicated tables, metrics, and categories. Solves enterprise logging gaps efficiently. | [/scripts/policy-builder](/scripts/policy-builder) |
| **Azure AI Foundry LLM Security Testing Framework** | A Python-based framework tests the security of Large Language Models (LLMs) deployed via Azure AI Foundry. It runs 12 specific tests to check if the AI can be tricked into dangerous behaviors like executing commands or generating malicious code. The tool analyzes responses, detects risks, and generates detailed reports. | [/scripts/ai-foundry-security-testing](/scripts/ai-foundry-security-testing) |
| **WebSearch Tool for Custom AI Endpoints** | A drop-in WebSearch function tool for the OpenAI Agents SDK when hosted WebSearchTool isn't available on custom endpoints (OpenRouter, direct Azure OpenAI, local models). Uses Serper.dev for Google SERP results with simple retry logic and clean output formatting. | [/tools/websearch-custom-endpoints](/tools/websearch-custom-endpoints) |

## How to Use
1. **Clone the Repo:** `git clone https://github.com/levelup360/builder-resources.git`
2. **Navigate Folders:** Each sub-folder contains its own README.md with detailed usage, examples, and code.
3. **Run/Adapt:** Tools are Python-based where applicable—check requirements in sub-READMEs.
4. **Feedback:** Connect on LinkedIn or DM me with questions (no issues/PRs here).

## License
MIT License – see [LICENSE](/LICENSE) for details.

## Connect & Level Up
Questions or ideas? Reach out on LinkedIn: https://www.linkedin.com/in/manuel-tomas-estarlich/. For structured mentorship, or enterprise consultancy, contact me at https://levelup360.pro/contact/. Start with the free Blueprint: https://levelup360.pro/ai-sa-blueprint/.

#Azure #CloudArchitecture #AIGovernance #DevOps