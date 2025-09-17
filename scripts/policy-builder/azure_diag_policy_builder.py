#!/usr/bin/env python3
"""
Azure Diagnostic Settings Policy Builder 

Overview:
This script automates the extraction and customization of Azure Policy definitions from AZPolicyAdvertizer.net.
It addresses limitations in Microsoft's built-in diagnostic settings policies by adding configurable parameters
for log destination type, metrics collection, and category groups. Designed for enterprise-scale use, it processes
a list of URLs, modifies policies, and saves both original and custom versions with smart naming to avoid overwrites.

Key Features:
1. Extracts policy JSON from web pages using regex-based scraping.
2. Adds/Modifies parameters: logAnalyticsDestinationType, collectMetrics, and categoryGroup (in 3 locations if missing).
3. Preserves original logic for diagnostic settings modifications (e.g., conditional metrics in ARM templates).
4. Smart service name extraction from displayName for file naming (handles explicit names and resource providers).
5. Unique filename generation to prevent overwrites.
6. Structured output directories: processed (custom policies), original (source policies), logs (reports).
7. Logging and verification for reliability.

Requirements:
- Python 3.6+
- Libraries: requests, json, logging, re, os, pathlib (all standard except requests – pip install requests)
- Internet access for fetching URLs.

Usage:
1. Update URLS_TO_PROCESS with your list of AZPolicyAdvertizer URLs.
2. Set OUTPUT_DIRECTORY to your desired path.
3. Run: python azure-diag-policy-builder.py
4. Check subdirectories for outputs and logs for details.

Example:
If processing a URL for "Data Lake Analytics", it extracts "Data Lake Analytics" as the service name,
adds missing parameters, and saves "Data Lake Analytics - custom.json" in the processed folder.

Author: Manuel Tomas Estarlich (with AI-assisted refinements)
Version: 1.0
Date: 2025-07-28
License: MIT (feel free to use/adapt with attribution)
"""

import requests
import json
import logging
import re
import os
from pathlib import Path

# Configuration
OUTPUT_DIRECTORY = "your-directory-here"

URLS_TO_PROCESS = [
    "https://www.azadvertizer.net/azpolicyadvertizer/aade2723-e7f6-46fd-b1dc-e6c2c7f7edc4.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/e40b8f6f-0ecf-4c3b-b095-ba3562256e48.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/29565b0a-e1b5-49c1-94bf-b8b258656460.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/567c93f7-3661-494f-a30f-0a94d9bfebf8.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/4b05de63-3ad2-4f6d-b421-da21f1328f3b.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/9dc3e252-1cff-4ae5-bcad-5a92b7167d43.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/92012204-a7e4-4a95-bbe5-90d0d3e12735.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/99b3bfad-aef0-476d-ae98-40861f8eae22.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/79494980-ea12-4ca1-8cca-317e942b6da2.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/856331d3-0169-4dd9-9b04-cbb2ad3d1cf2.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/b797045a-b3cd-46e4-adc4-bbadb3381d78.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/69ab8bfc-dc5b-443d-93a7-7531551dec66.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/1bd91eae-4429-4f23-b780-8c9622e023e3.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/e25bcb29-0412-42c3-a526-1ff794310a1e.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/aec4c33f-2f2a-4fd3-91cd-24a939513c60.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/68ba9fc9-71b9-4e6f-9cf5-ecc07722324c.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/a819f227-229d-44cb-8ad6-25becdb4451f.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/f62b9eab-b489-4388-9874-b0a62ca31327.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/041fdf14-0dd4-4ce0-83ff-de5456be0c85.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/454c7d4b-c141-43f1-8c81-975ebb15a9b5.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/4c9cd884-3e45-4588-ac9d-00d44be2cbcd.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/f969646f-b6b8-45a0-b736-bf9b4bb933dc.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/75a112bc-759f-4f29-83cc-799019db39c3.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/90c90eda-bfe7-4c67-bf26-410420ed1047.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/d98f63ed-e319-4dc3-898f-600953a05f7e.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/0b6b8abb-7761-4e02-ae0e-2c873b5152ca.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/305408ed-dd5a-43b9-80c1-9eea87a176bb.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/a1a5f3c5-d01a-459c-8398-a3c9a79ad879.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/fea83f6c-a18a-4338-8f1f-80ecba4c5643.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/f8352124-56fa-4f94-9441-425109cdc14b.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/9fcae8ed-246a-407b-8f75-f3500ff2c9db.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/415eaa04-e9db-476a-ba43-092d70ebe1e7.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/fa570aa1-acca-4eea-8e5a-233cf2c5e4c2.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/39078c44-b8d4-4c7d-8579-7f021d326ebf.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/958060c2-8d8e-478e-b3ec-d3d2249b461c.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/55d1f543-d1b0-4811-9663-d6d0dbc6326d.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/acbb9698-46bd-4800-89da-e3473c4ab10d.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/0e4325e3-228b-40f0-83ae-9c03276858c1.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/6a664864-e2b5-413e-b930-f11caa132f16.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/85779c9a-7fdf-4294-937c-ded183166fa8.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/56288eb2-4350-461d-9ece-2bb242269dce.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/7e87b2cc-1e49-4e07-a651-a2f38d4667ad.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/751f9297-5aae-4313-af2d-2a89226a7856.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/d111f33e-5cb3-414e-aec4-427e7d1080c9.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/dfe69c56-9c12-4271-9e62-7607ab669582.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/ed251afd-72b1-4e41-b6c9-6614420f1207.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/a271e156-b295-4537-b01d-09675d9e7851.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/82b076b9-2062-4516-ae4c-37b1890eabb2.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/f0d25196-1ea4-49e1-ad53-ccada27b4862.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/e74570cf-1b7d-4bed-b79e-d1fd1117a39a.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/b90ec596-faa6-4c61-9515-34085703e260.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/3496f6fd-57ba-485c-8a14-183c4493b781.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/e1bf4d43-542a-4410-918d-7e61c8e1ac21.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/0fff3e39-f422-45b0-b497-33a05b996d3e.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/46b2dd5d-3936-4347-8908-b298ea4466d3.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/441af8bf-7c88-4efc-bd24-b7be28d4acce.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/0ba93a1b-ac4d-4e7b-976a-548a18be1e52.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/c5ecf495-6caa-445c-b431-04fda56c555a.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/eb2fea88-fa7b-4531-a4c1-428c618fbcc8.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/5fcf46f9-194c-47ff-8889-380f57ae4617.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/6201aeb7-2b5c-4671-8ab4-5d3ba4d77f3b.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/e9c56c41-d453-4a80-af93-2331afeb3d82.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/a7c668bd-3327-474f-8fb5-8146e3e40e40.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/3d28ea18-8e88-4160-96ff-4b6af4fd94c7.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/1840aef8-71df-4a30-a108-efdb4f291a7f.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/614d9fbd-68cd-4832-96db-3362069661b2.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/6b359d8f-f88d-4052-aa7c-32015963ecc1.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/5d487647-6a53-4839-8eb8-edccf5e6bf1d.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/889bfebf-7428-426e-a86f-79e2a7de2f71.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/818719e5-1338-4776-9a9d-3c31e4df5986.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/63d1a629-735c-448b-b45f-5e3865e84cf5.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/b6f29e6b-4b21-4bb6-a997-38592fa02864.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/8d42b501-dd03-449d-a070-32d1db2e546b.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/b88bfd90-4da5-43eb-936f-ae1481924291.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/69214fad-6742-49a9-8f71-ee9d269364ab.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/557c828f-aa51-40d9-868a-cff8d3982818.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/4cabf9fc-4ed1-4990-bbaf-7248fb8751bc.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/234bbd1b-05f6-4639-8770-1cd5278ba2c9.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/bbf47f27-95e4-46a0-82e1-898ce046d857.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/2fbd2ca9-e7b2-47a0-a8b2-575f3f7607d4.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/087dbf66-448d-4235-b7b8-17af48edc9db.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/0509e2d8-d657-4563-a7c8-b88b9180a6e8.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/c13b41e7-a45f-4600-96c0-18f84fb07771.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/65a1573e-cc90-412b-8db2-ba60731b0ea6.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/167dbbbc-a03a-4ebe-8e46-c34cc67f7d9d.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/7860f3fe-0db3-42d4-bf3d-7042ea5e5787.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/5fbd326d-328c-414e-a922-2d6963998962.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/84509667-1a94-4255-9e5f-b479075c1069.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/bbdbb83b-cbfe-49f7-b7d1-1126630a68b7.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/041e904a-33e5-45fd-b3f6-4ac95f1f8761.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/ae0fc3d3-c9ce-43e8-923a-a143db56d81e.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/064a3695-3197-4354-816b-65c7b952db9e.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/30499756-47d6-493c-9e57-ee3db2d9fa96.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/33835ef6-bc67-4bde-bf5f-5a857f195a57.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/5cfb9e8a-2f13-40bd-a527-c89bc596d299.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/d7d59290-3ee5-4c1b-b408-c38b21799aea.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/dc1b5908-da05-4eed-a988-c5e32fdb682d.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/6ee1c58c-a123-4cd6-8643-48b2f7ffb3e1.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/0ebe872d-7029-4292-88bc-ad3e2cf3772f.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/cac9e1c5-c3cb-47fa-8d4c-88b8559262d2.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/d8624de8-47fe-47c0-bea0-2d8329b628fe.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/0e861bb0-d926-4cdb-b2d6-d59336b8f5b3.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/a9725bd4-a2ad-479f-a29b-5e163cada399.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/63a8eb0d-f030-4bc6-a1e4-6998f23aa160.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/4f925033-4d52-4619-909c-9c47a687dc51.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/60579569-3633-42cb-ae6a-195080bf310d.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/54c7cff6-a032-43e1-9656-d4c24665f805.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/14ed86b4-ea45-4b1b-98a5-eb8f5f7da726.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/fc2bb2e1-739a-4a03-86a2-16ad55e90bd9.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/d3abca82-2ae2-4707-bf5e-cfc765ce9ff1.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/887dc342-c6bd-418b-9407-ab0e27deba36.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/068e22bd-8057-466b-9642-7cd2ca476158.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/a83fcddb-39d0-4c21-af38-76d2c935c3ca.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/1568dd08-cca0-4073-bfd8-e08a7fdc543e.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/23673f24-2594-43e9-9983-60a0be21bd76.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/baa4c6de-b7cf-4b12-b436-6e40ef44c8cb.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/69e0da8f-ca50-479d-b1a8-33a31426c512.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/81039988-1f84-4aa6-8039-0a64c2a301b4.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/7a8afaba-cc24-4306-b83f-d178f1a10ba2.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/1513498c-3091-461a-b321-e9b433218d28.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/b55f2e8e-dc76-4262-a0e3-45f02200ff0e.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/2f4d1c08-3695-41a7-a0a0-8db4a0e25233.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/56ae9f08-b8c9-4a0f-8f58-5dbcd63bef84.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/8ea88471-98e1-47e4-9f63-838c990ba2f4.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/f018b68f-d953-4238-81a3-94a0f39507e3.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/8def4bdd-4362-4ed6-a26f-7bf8f2c58839.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/0277b2d5-6e6f-4d97-9929-a5c4eab56fd7.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/93a604fe-0ec2-4a99-ab8c-7ef08f05555a.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/6567d3f3-42d0-4cfb-9606-9741ba60fa07.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/8fc4ca5f-6abc-4b30-9565-0bd91ac49420.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/e99ab54f-260e-4925-a70f-8fe0a92443ef.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/2453e322-a7e5-4905-ba1e-ac6ea60ff808.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/be26ca28-761d-4538-b78a-975eb47c680c.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/1118afbc-c48d-43ae-931a-87b38956d40b.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/34c7546c-d637-4b5d-96ab-93fb6ed07af8.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/ed6ae75a-828f-4fea-88fd-dead1145f1dd.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/3234ff41-8bec-40a3-b5cb-109c95f1c8ce.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/c3b912c2-7f5b-47ac-bd52-8c85a7667961.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/0da6faeb-d6c6-4f6e-9f49-06277493270b.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/867c08d5-bc47-404d-9a1b-0aec7a8d34eb.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/6bb23bce-54ea-4d3d-b07d-628ce0f2e4e3.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/cdd1dbc6-0004-4fcd-afd7-b67550de37ff.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/65f86cc7-f01e-4c42-967c-e5014709f2c5.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/6f95136f-6544-4722-a354-25a18ddb18a7.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/e9c22e0d-1f03-44da-a9d5-a9754ea53dc4.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/a4490248-cb97-4504-b7fb-f906afdb7437.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/45c6bfc7-4520-4d64-a158-730cd92eedbc.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/3aa571d2-2e4f-4e92-8a30-4312860efbe1.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/244bcb20-b194-41f3-afcc-63aef382b64c.html",
    "https://www.azadvertizer.net/azpolicyadvertizer/c0d8e23a-47be-4032-961f-8b0ff3957061.html"
    # Add or remove URLS as needed
]

# Create subdirectories
OUTPUT_DIR = Path(OUTPUT_DIRECTORY)
PROCESSED_DIR = OUTPUT_DIR / "processed"
ORIGINAL_DIR = OUTPUT_DIR / "original"
LOGS_DIR = OUTPUT_DIR / "logs"

# Create all directories
for dir_path in [PROCESSED_DIR, ORIGINAL_DIR, LOGS_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)

# Configure logging
log_file = LOGS_DIR / "azure-diag-policy-builder.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

def sanitize_filename(filename):
    """Sanitize filename to remove invalid characters."""
    # Replace forward slashes with underscores
    filename = filename.replace('/', '_')
    # Remove other invalid characters
    filename = re.sub(r'[<>:"|\\?*]', '', filename)
    # Remove extra spaces
    filename = re.sub(r'\s+', ' ', filename).strip()
    return filename

def extract_service_name_from_display_name(display_name):
    """
    Extract service name from displayName for file naming.
    Examples:
    - "Enable logging by category group for 1ES Hosted Pools (microsoft.cloudtest/hostedpools) to Log Analytics" → "1ES Hosted Pools"
    - "Enable logging by category group for Data Lake Analytics (microsoft.datalakeanalytics/accounts) to Log Analytics" → "Data Lake Analytics"
    - "Enable logging by category group for microsoft.autonomousdevelopmentplatform/workspaces to Log Analytics" → "microsoft.autonomousdevelopmentplatform_workspaces"
    """
    if not display_name:
        return "unknown-service"
    
    # Pattern 1: Service name before parentheses
    pattern1 = r"Enable logging by category group for ([^(]+?)\s*\(([^)]*)\)\s*to Log Analytics"
    match1 = re.search(pattern1, display_name, re.IGNORECASE)
    if match1:
        service_name = match1.group(1).strip()
        if service_name:
            return service_name
    
    # Pattern 2: Resource provider only (no parentheses)
    pattern2 = r"Enable logging by category group for (microsoft\.[^\s]+(?:/[^\s]+)*)\s*to Log Analytics"
    match2 = re.search(pattern2, display_name, re.IGNORECASE)
    if match2:
        resource_provider = match2.group(1).strip()
        return resource_provider
    
    # Pattern 3: General fallback
    pattern3 = r"Enable logging by category group for\s+(.+?)\s+to Log Analytics"
    match3 = re.search(pattern3, display_name, re.IGNORECASE)
    if match3:
        service_name = match3.group(1).strip()
        # Remove any trailing parentheses content
        service_name = re.sub(r'\s*\([^)]*\)\s*$', '', service_name).strip()
        if service_name:
            return service_name
    
    # Final fallback
    return "unknown-service"

def get_unique_filename(directory, base_name, extension=".json"):
    """Generate a unique filename to avoid overwrites."""
    filename = f"{base_name}{extension}"
    full_path = directory / filename
    
    if not full_path.exists():
        return filename
    
    # File exists, add numbering
    counter = 1
    while True:
        filename = f"{base_name} ({counter}){extension}"
        full_path = directory / filename
        if not full_path.exists():
            return filename
        counter += 1

def extract_policy_json(url):
    """Extract Azure Policy JSON from azadvertizer.net webpage."""
    try:
        logging.info(f"Fetching policy from: {url}")
        response = requests.get(url, timeout=30)
        response.raise_for_status()

        # Look for JSON in script tags
        script_pattern = re.compile(r'const obj = ({.*?});', re.DOTALL)
        match = script_pattern.search(response.text)

        if not match:
            logging.error(f"Could not find policy JSON in {url}")
            return None

        json_str = match.group(1)
        policy_json = json.loads(json_str)

        logging.info(f"Successfully extracted policy JSON from {url}")
        return policy_json

    except Exception as e:
        logging.error(f"Error extracting policy from {url}: {str(e)}")
        return None

def has_category_group_parameter(policy_json):
    """Check if categoryGroup parameter exists in any of the three locations."""
    # Check main parameters
    if "parameters" in policy_json and "categoryGroup" in policy_json["parameters"]:
        return True
    
    # Check deployment template parameters
    try:
        template_params = policy_json["policyRule"]["then"]["details"]["deployment"]["properties"]["template"]["parameters"]
        if "categoryGroup" in template_params:
            return True
    except (KeyError, TypeError):
        pass
    
    # Check deployment parameters
    try:
        deploy_params = policy_json["policyRule"]["then"]["details"]["deployment"]["properties"]["parameters"]
        if "categoryGroup" in deploy_params:
            return True
    except (KeyError, TypeError):
        pass
    
    return False

def modify_policy_json(policy_json):
    """Modify the Azure Policy JSON to add required parameters and properties."""
    try:
        # Get original display name for service extraction
        original_display_name = policy_json.get("displayName", "")
        
        # Change displayName to add "- Custom"
        policy_json["displayName"] = f"{original_display_name} - Custom"

        # Change policyType from BuiltIn to Custom
        policy_json["policyType"] = "Custom"

        # Add parameters if they don't exist
        if "parameters" not in policy_json:
            policy_json["parameters"] = {}

        # Add logAnalyticsDestinationType parameter
        if "logAnalyticsDestinationType" not in policy_json["parameters"]:
            policy_json["parameters"]["logAnalyticsDestinationType"] = {
                "type": "String",
                "metadata": {
                    "displayName": "Log Analytics Destination Type",
                    "description": "Destination type for Log Analytics - AzureDiagnostics or Dedicated."
                },
                "allowedValues": [
                    "AzureDiagnostics",
                    "Dedicated"
                ],
                "defaultValue": "Dedicated"
            }

        # Add collectMetrics parameter
        if "collectMetrics" not in policy_json["parameters"]:
            policy_json["parameters"]["collectMetrics"] = {
                "type": "String",
                "metadata": {
                    "displayName": "Collect Metrics",
                    "description": "Enable or disable metrics collection for diagnostic settings."
                },
                "allowedValues": [
                    "true",
                    "false"
                ],
                "defaultValue": "false"
            }

        # Add categoryGroup parameter if missing
        if "categoryGroup" not in policy_json["parameters"]:
            logging.info("Adding categoryGroup parameter to main parameters")
            policy_json["parameters"]["categoryGroup"] = {
                "type": "String",
                "metadata": {
                    "displayName": "Category Group",
                    "description": "Diagnostic category group - none, audit, or allLogs."
                },
                "allowedValues": [
                    "audit",
                    "allLogs"
                ],
                "defaultValue": "audit"
            }

        # Modify the policy rule deployment template
        if "policyRule" in policy_json and "then" in policy_json["policyRule"]:
            deployment = policy_json["policyRule"]["then"]["details"]["deployment"]

            # Add parameters to template parameters
            template_params = deployment["properties"]["template"]["parameters"]
            
            if "logAnalyticsDestinationType" not in template_params:
                template_params["logAnalyticsDestinationType"] = {
                    "type": "String"
                }

            if "collectMetrics" not in template_params:
                template_params["collectMetrics"] = {
                    "type": "String"
                }
            
            if "categoryGroup" not in template_params:
                logging.info("Adding categoryGroup to deployment template parameters")
                template_params["categoryGroup"] = {
                    "type": "String"
                }

            # Add parameters to deployment parameters
            deployment_params = deployment["properties"]["parameters"]
            
            if "logAnalyticsDestinationType" not in deployment_params:
                deployment_params["logAnalyticsDestinationType"] = {
                    "value": "[parameters('logAnalyticsDestinationType')]"
                }

            if "collectMetrics" not in deployment_params:
                deployment_params["collectMetrics"] = {
                    "value": "[parameters('collectMetrics')]"
                }
            
            if "categoryGroup" not in deployment_params:
                logging.info("Adding categoryGroup to deployment parameters")
                deployment_params["categoryGroup"] = {
                    "value": "[parameters('categoryGroup')]"
                }

            # Find and modify the diagnostic settings resource (PRESERVED FROM ORIGINAL)
            resources = deployment["properties"]["template"]["resources"]
            for resource in resources:
                if "diagnosticSettings" in resource.get("type", ""):
                    # Add logAnalyticsDestinationType property
                    resource["properties"]["logAnalyticsDestinationType"] = "[parameters('logAnalyticsDestinationType')]"

                    # Modify metrics property with conditional logic
                    resource["properties"]["metrics"] = "[if(equals(parameters('collectMetrics'), 'true'), createArray(createObject('timeGrain', json('null'), 'enabled', true(), 'retentionPolicy', createObject('days', 0, 'enabled', false()), 'category', 'AllMetrics')), createArray())]"

            # Add logAnalyticsDestinationType to existence condition (PRESERVED FROM ORIGINAL)
            if "existenceCondition" in policy_json["policyRule"]["then"]["details"]:
                existence_condition = policy_json["policyRule"]["then"]["details"]["existenceCondition"]
                if "allOf" in existence_condition:
                    # Check if already exists before adding
                    has_condition = any(
                        cond.get("field") == "Microsoft.Insights/diagnosticSettings/logAnalyticsDestinationType" 
                        for cond in existence_condition["allOf"]
                    )
                    if not has_condition:
                        existence_condition["allOf"].append({
                            "field": "Microsoft.Insights/diagnosticSettings/logAnalyticsDestinationType",
                            "equals": "[parameters('logAnalyticsDestinationType')]"
                        })

        logging.info("Successfully modified policy JSON")
        return policy_json, original_display_name

    except Exception as e:
        logging.error(f"Error modifying policy JSON: {str(e)}")
        return None, None

def save_policy_json(policy_json, original_display_name, url):
    """Save the modified policy JSON to a file with smart naming."""
    try:
        # Extract service name from original display name
        service_name = extract_service_name_from_display_name(original_display_name)
        sanitized_service_name = sanitize_filename(service_name)
        
        # Log the mapping for debugging
        logging.info(f"URL: {url} -> Service Name: '{sanitized_service_name}'")
        
        # Save original policy
        original_filename = get_unique_filename(ORIGINAL_DIR, f"{sanitized_service_name} - original")
        original_path = ORIGINAL_DIR / original_filename
        
        # For original, we need to unwrap from properties if it exists
        original_json = policy_json
        with open(original_path, 'w', encoding='utf-8') as f:
            json.dump(original_json, f, indent=4)
        
        # Generate filename for processed policy
        processed_filename = get_unique_filename(PROCESSED_DIR, f"{sanitized_service_name} - custom")
        processed_path = PROCESSED_DIR / processed_filename

        # Wrap in properties object for processed version
        final_json = {
            "properties": policy_json
        }

        # Save to file
        with open(processed_path, 'w', encoding='utf-8') as f:
            json.dump(final_json, f, indent=4)

        logging.info(f"Policy saved to: {processed_path}")
        return str(processed_path)

    except Exception as e:
        logging.error(f"Error saving policy JSON: {str(e)}")
        return None

def verify_modifications(policy_json):
    """Verify that all required modifications have been applied."""
    checks = []

    # Check if displayName was modified
    display_name = policy_json.get("displayName", "")
    checks.append(("DisplayName modified", "- Custom" in display_name))

    # Check if policyType was changed
    policy_type = policy_json.get("policyType", "")
    checks.append(("PolicyType changed to Custom", policy_type == "Custom"))

    # Check if parameters were added
    params = policy_json.get("parameters", {})
    checks.append(("logAnalyticsDestinationType parameter added", "logAnalyticsDestinationType" in params))
    checks.append(("collectMetrics parameter added", "collectMetrics" in params))
    checks.append(("categoryGroup parameter added", "categoryGroup" in params))

    # Log verification results
    logging.info("Verification Results:")
    for check_name, result in checks:
        status = "✓" if result else "✗"
        logging.info(f"  {status} {check_name}")

    return all(result for _, result in checks)

def main():
    """Main function to process all URLs."""
    logging.info("Starting Azure Diag Policy Builder")
    logging.info(f"Processing {len(URLS_TO_PROCESS)} URLs")
    logging.info(f"Output directory: {OUTPUT_DIRECTORY}")
    logging.info(f"Processed policies: {PROCESSED_DIR}")
    logging.info(f"Original policies: {ORIGINAL_DIR}")
    logging.info(f"Logs: {LOGS_DIR}")

    processed_count = 0
    error_count = 0

    # Check for duplicate URLs
    unique_urls = list(set(URLS_TO_PROCESS))
    if len(unique_urls) < len(URLS_TO_PROCESS):
        logging.warning(f"Found {len(URLS_TO_PROCESS) - len(unique_urls)} duplicate URLs")

    for i, url in enumerate(URLS_TO_PROCESS, 1):
        try:
            logging.info(f"\nProcessing {i}/{len(URLS_TO_PROCESS)}: {url}")
            
            # Extract policy JSON from webpage
            policy_json = extract_policy_json(url)
            if not policy_json:
                error_count += 1
                continue

            # Check if categoryGroup exists
            has_category_group = has_category_group_parameter(policy_json)
            logging.info(f"Policy has categoryGroup parameter: {has_category_group}")

            # Modify the policy JSON
            modified_policy, original_display_name = modify_policy_json(policy_json)
            if not modified_policy:
                error_count += 1
                continue

            # Verify modifications
            if not verify_modifications(modified_policy):
                logging.warning(f"Some modifications may not have been applied correctly for {url}")

            # Save to file
            saved_path = save_policy_json(modified_policy, original_display_name, url)
            if saved_path:
                processed_count += 1
                logging.info(f"Successfully processed: {url}")
            else:
                error_count += 1

        except Exception as e:
            logging.error(f"Unexpected error processing {url}: {str(e)}")
            error_count += 1

    # Summary
    logging.info(f"\nProcessing complete. Successfully processed: {processed_count}, Errors: {error_count}")
    logging.info(f"Check for duplicate service names if processed count is less than expected")

if __name__ == "__main__":
    main()