# Auto Tab Sorter - Burp Suite Extension

## Overview
Auto Tab Sorter is a Burp Suite extension that automatically categorizes HTTP requests based on predefined contexts. It creates separate tabs for different functionalities like Login, Profile, Admin, API, and more, allowing easier analysis and debugging.

## Features
- Automatically detects request contexts based on URL patterns
- Creates separate tabs for different request categories
- Displays categorized requests in a structured table
- Supports multiple categories, including Login, Signup, Profile, Admin, API, and more
- Works with Burp Suite Community and Professional editions

## Categories
The extension sorts requests into the following categories based on URL patterns:
- **Login**: login, signin
- **Signup**: signup, register
- **Profile**: profile, account
- **Dashboard**: dashboard, home
- **Search**: search, query
- **Admin**: admin, backend, panel
- **API**: api, graphql, rest
- **Settings**: settings, preferences, config
- **Files**: upload, download, files
- **Payments**: payment, checkout, billing
- **Logs**: logs, debug, trace
- **Tokens**: token, auth, jwt, session
- **Other**: Uncategorized requests

## Installation
1. Open Burp Suite and navigate to **Extensions** > **BApp Store**.
2. Download and install **Jython** if not already installed.
3. Go to **Extensions** > **Add Extension**.
4. Select **Extension Type** as **Python**.
5. Browse and select the `auto_tab_sorter.py` file.
6. Click **Next** and ensure the extension loads successfully.

## Usage
1. Enable **Intercept** and capture requests.
2. The extension will automatically sort the requests into categorized tabs.
3. Click on any tab to view the corresponding requests in a structured table.

## Dependencies
- **Burp Suite** (Community or Professional)
- **Jython** (Required for Python-based Burp extensions)

## License
This extension is open-source and released under the MIT License.

