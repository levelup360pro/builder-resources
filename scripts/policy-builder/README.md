# Azure Diagnostic Settings Policy Builder Script Documentation

## Overview
This Python script automates the customization of Azure Policy definitions pulled from AZPolicyAdvertizer.net. It addresses gaps in Microsoft's built-in diagnostic settings policies by adding parameters for log destination type, metrics collection, and category groups. Built for enterprise use, it processes URLs in bulk, modifies policies, and saves outputs with smart naming.

**Author:** Manuel Tomas Estarlich  
**Version:** 1.0  
**Date:** 2025-07-28  
**License:** MIT  

## Features
- **Policy Extraction:** Scrapes JSON from web pages using regex.
- **Parameter Additions:** Adds `logAnalyticsDestinationType`, `collectMetrics`, and `categoryGroup` (in 3 locations if missing).
- **Preserved Logic:** Maintains original modifications for diagnostic settings and existence conditions.
- **Smart Naming:** Extracts service names (e.g., "Data Lake Analytics") for filenames, with unique handling to avoid overwrites.
- **Output Structure:** Saves to subdirectories (processed, original, logs).
- **Verification & Logging:** Checks modifications and logs details for debugging.

## Requirements
- Python 3.6+
- `pip install requests`
- Internet access

## Installation
1. Clone or download the script.
2. Update `URLS_TO_PROCESS` and `OUTPUT_DIRECTORY` in the script.cd ..

3. Run: `python azure_diag_policy_builder.py`

## Usage
1. **Configure URLs:** Add AZPolicyAdvertizer links to `URLS_TO_PROCESS`.
2. **Set Output Path:** Update `OUTPUT_DIRECTORY`.
3. **Run the Script:** Execute in a terminal. It will process each URL, log progress, and save files.
4. **Check Outputs:** 
   - `processed/`: Custom policies (e.g., "Data Lake Analytics - custom.json").
   - `original/`: Unmodified policies.
   - `logs/`: Log file with details.

**Example Command:**  
`python azure_diag_policy_builder.py`

**Expected Output:**  
Logs show processing status, e.g., "Successfully processed: [URL]" and a final summary.

## How It Works
1. **Extraction:** Fetches page and regex-searches for JSON.
2. **Modification:** Adds parameters, updates deployment sections, preserves metrics logic.
3. **Naming & Saving:** Extracts service name, ensures uniqueness, saves wrapped JSON.
4. **Verification:** Checks key changes and logs results.

## Troubleshooting
- **Extraction Fails:** Check URL validity or regex pattern (pages may change).
- **Missing Sections:** Script skips and warns if policy JSON lacks expected structure.
- **Duplicates:** Unique naming handles same service names; check logs for mappings.
- **Errors:** Review `logs/azure-diag-policy-builder.log` for details.

## Connect
For questions, connect via LinkedIn: https://www.linkedin.com/in/manuel-tomas-estarlich/ 

## Disclaimer
This is not official Microsoft software. Test in a non-production environment. Use at your own risk.