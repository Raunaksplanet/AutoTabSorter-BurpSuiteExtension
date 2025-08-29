# Request Categorizer

A Burp Suite extension that automatically categorizes HTTP requests from proxy history based on user-defined keywords.

## Description

Request Categorizer allows you to organize HTTP traffic by creating custom categories with specific keywords. The extension scans Burp's proxy history and groups matching requests into separate tabs for easier analysis during security testing.

## Features

- Create custom categories with user-defined keywords
- Automatically scan proxy history for matching requests
- Search through URLs, request bodies, and response bodies
- View full request/response details with Burp's built-in editor
- Refresh functionality to rescan history for new categories
- Handle special characters in keywords safely

## Installation

1. Download the Python script
2. Open Burp Suite
3. Go to Extensions > Add
4. Select "Python" as extension type
5. Load the script file
6. The "Categorizer" tab will appear in Burp Suite

## Usage

1. Enter a keyword in the "Keyword" field
2. Enter a name for the tab in the "Tab Name" field
3. Click "Add Category" to create the category and scan proxy history
4. Matching requests will appear in the new tab
5. Click on any request to view full details
6. Use "Refresh All" to rescan proxy history for all categories
7. Use "Remove Category" to delete unwanted categories

## Requirements

- Burp Suite Professional or Community Edition
- Jython standalone JAR configured in Burp Suite

## Example Keywords

- `api` - Captures API endpoints
- `login` - Captures authentication requests  
- `"token":"` - Captures requests with token parameters
- `admin` - Captures admin panel requests

## Author

Created by Raunak Gupta - Security Researcher & Bug Bounty Hunter
