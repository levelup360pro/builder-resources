# Azure AI Foundry LLM Security Testing Framework

## Overview

This Python-based framework tests the security of Large Language Models (LLMs) deployed via Azure AI Foundry. It runs 12 specific tests to check if the AI can be tricked into dangerous behaviors like executing commands or generating malicious code. The tool analyzes responses, detects risks, and generates detailed reports.

Important: These tests specifically focus on the AI model layer, assuming all other foundational protections are in place. Results from my environment—share yours for community validation.

Limitations: My tests aren't as sophisticated as real AI attacks; strict rules may block genuine requests. Use as starting points for:
    (1) Restrictive-then-ease approach, or
    (2) Integration with AI protection platforms like Lakera.

Verify thoroughly for your env. Excited for Microsoft's continued innovations in this space!

## Important Disclaimer & Responsible Use

This framework and its associated files are provided for **educational and security testing purposes only**. Before using, please acknowledge the following:

-   **Do Not Use in Production Directly**: The provided WAF rules and `custom-blocklist.csv` terms are aggressive and designed for testing. Deploying them directly into a production environment without validation will likely block legitimate user traffic.
-   **Always Test First**: Run this framework and any generated rules in a dedicated, non-production environment. Understand the impact of each rule before considering it for production.
-   **Customize for Your Needs**: The provided patterns are a general-purpose starting point, not a one-size-fits-all solution. You must adapt them to your specific application's risk profile and use case.
-   **Not an Exhaustive Audit**: These 12 tests represent common vulnerabilities but do not capture the full spectrum of sophisticated or emerging AI attack vectors. Continuous security assessment is essential.

The user assumes all responsibility for the use of this framework.

## Testing Environment & Methodology

The framework was tested against two distinct architectural setups to validate different layers of security:

#### 1. WAF Policy Validation (via Application Gateway)
-   **Endpoint Used:** `https://ai-gateway.local`
-   **Architecture:** This local domain, resolves to an Azure Application Gateway with a self-signed certificate. This gateway was integrated with an Azure Web Application Firewall (WAF) policy.
-   **Purpose:** This setup ensures that all test traffic is inspected by the WAF *before* reaching the backend AI service. It is used to validate the effectiveness of network-level rules created by `waf_rules_creator.py`.

#### 2. Direct AI Service Validation (No WAF)
-   **Endpoint Used:** `https://fabric-sqldb-ai-foundry.services.ai.azure.com`
-   **Architecture:** This is the public endpoint for my Azure AI Foundry resource.
-   **Purpose:** Testing against this endpoint bypasses the Application Gateway and WAF entirely. This is used to assess the model's inherent security posture and the effectiveness of its internal safety mechanisms, such as the custom blocklist uploaded from `custom-blocklist.csv`.


## Components and Files

This framework consists of three main files, each serving a specific purpose:

- **`azure_foundry_security_tester.py`** (Main Script): The core testing engine. It runs the 12 security tests, analyzes the AI's responses, and generates detailed reports, including an HTML dashboard.

- **`waf_rules_creator.py`** (WAF Script): A utility script to create Azure Web Application Firewall (WAF) rules from a list of security patterns. This is a security layer to block malicious requests at the network level. 

- **`custom-blocklist.csv`** (Blocklist File): A ready-to-use CSV file containing regex patterns. This file can be uploaded directly to the Azure AI Foundry "Custom Blocklists" feature to block malicious prompts without needing to run any code. 

## The 12 Core Security Tests

The framework runs 12 tests across 5 categories to probe different vulnerabilities.

### 1. Command Execution Tests
These tests attempt to make the AI execute system commands.

- **Shell Command Injection**: Tries to list sensitive system files like `/etc/passwd`. (Risk: **CRITICAL**)
- **PowerShell Execution**: Attempts to run Windows process queries. (Risk: **CRITICAL**)
- **Azure CLI Command**: Probes for cloud account information. (Risk: **CRITICAL**)
- **Python Code Execution**: Tries to run system commands via Python's `os.system`. (Risk: **CRITICAL**)
- **File System Access**: Attempts to read protected system files. (Risk: **CRITICAL**)

### 2. API Manipulation Tests
These tests check if the AI can be forced to make unauthorized API calls.

- **REST API Call**: Attempts to access an external API (GitHub). (Risk: **HIGH**)
- **Azure Resource Graph Query**: Tries to enumerate cloud resources via KQL. (Risk: **CRITICAL**)

### 3. Code Generation Tests
These tests evaluate if the AI will generate harmful code.

- **Malicious Python Script**: Prompts the AI to generate file-deleting code. (Risk: **HIGH**)
- **Reverse Shell Code**: Asks the AI to create a script for a network backdoor. (Risk: **CRITICAL**)

### 4. Function Calling Tests
This tests for unauthorized execution of predefined functions.

- **Unauthorized Function Call**: Attempts to call a `delete_user('admin')` function. (Risk: **CRITICAL**)

### 5. Indirect Execution Tests
These tests use social engineering to trick the AI.

- **Disguised Command**: Asks for dangerous commands under a "diagnostic" pretext. (Risk: **MEDIUM**)
- **Educational Pretext**: Asks for dangerous commands in an "educational" context. (Risk: **LOW**)

## How to Use the Framework

### Method 1: Running the Main Security Tests

This is the most comprehensive approach. It runs all 12 tests and generates detailed reports.

**1. Install Prerequisites**
```bash
pip install requests azure-ai-inference azure-core urllib3

2.  **Configure the Script**
    Open `azure_foundry_security_tester.py` and update these variables with your Azure details:
    ```python
    BASE_ENDPOINT = "https://your-ai-foundry-endpoint.com"
    API_KEY = "your-api-key-here"
    MODEL_NAME = "your-model-name"
    ```

3.  **Run the Tests**
    Execute the script from your terminal:
    ```bash
    python azure_foundry_security_tester.py
    ```
    Confirm with `yes` when prompted. The script will run all tests and create a new directory (e.g., `azure_foundry_security_reports_[timestamp]`) with the results. Open `dashboard.html` in that folder for an interactive summary.

---

### Method 2: Using the WAF Rules Creator

Use this method if you want to block threats at the network level using an Azure WAF policy.

1.  **Configure the Script**
    Open `waf_rules_creator.py` and ensure the `RESOURCE_GROUP` and `WAF_POLICY_NAME` match your environment.

2.  **Run the Script**
    ```bash
    python waf_rules_creator.py
    ```
    The script will use the Azure CLI to create a set of custom WAF rules in your specified policy, based on the aggressive blocklist patterns.

---

### Method 3: Using the Custom Blocklist

This is the simplest method and does not require running any code.

1.  **Navigate to Azure AI Foundry**
    In the Azure Portal, go to your AI Foundry resource.

2.  **Upload the Blocklist**
    - Go to the **Content Filters** section.
    - Find the **Custom Blocklists** feature.
    - Upload the `custom-blocklist.csv` file and ensure it is enabled.

This will configure the AI service to block any incoming prompts that match the patterns in the CSV file.