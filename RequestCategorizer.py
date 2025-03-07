from burp import IBurpExtender, IHttpListener, ITab, IMessageEditorController
from javax.swing import JPanel, JTabbedPane, JScrollPane, JTable, JSplitPane
from javax.swing.table import DefaultTableModel
import java.awt as awt
import re
from java.net import URL

class BurpExtender(IBurpExtender, IHttpListener, ITab, IMessageEditorController):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("RequestCategorizer")

        self.tabs = JTabbedPane()
        self.request_categories = {}
        self.request_entries = {}  # To track duplicate requests

        self._callbacks.addSuiteTab(self)
        self._callbacks.registerHttpListener(self)

    def getTabCaption(self):
        return "Categorizer"

    def getUiComponent(self):
        return self.tabs

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        request_info = self._helpers.analyzeRequest(messageInfo)
        url = request_info.getUrl().toString()
        method = request_info.getMethod()

        # Extract the correct host
        host = self.extract_host(messageInfo, url)
        
        category = self.categorize_request(url)

        # Ensure the category tab exists
        if category not in self.request_categories:
            self.create_category_tab(category)

        if not messageIsRequest:
            response_bytes = messageInfo.getResponse()
            response_info = self._helpers.analyzeResponse(response_bytes)
            status_code = response_info.getStatusCode()
            mime_type = response_info.getStatedMimeType() if response_info.getStatedMimeType() else "Unknown"
            response_length = len(response_bytes) if response_bytes else 0

            full_request = self._helpers.bytesToString(messageInfo.getRequest())
            full_response = self._helpers.bytesToString(response_bytes)

            # Prevent duplicate requests from being added
            request_key = (host, method, url, status_code)
            if request_key in self.request_entries:
                return  # Skip duplicate request

            self.request_entries[request_key] = True
            self.add_request_to_tab(category, host, method, url, status_code, response_length, mime_type, full_request, full_response, messageInfo)

    def extract_host(self, messageInfo, url):
        """ Extracts the correct hostname, avoiding burp.Zlq4@random_id issues. """
        try:
            host = messageInfo.getHttpService().getHost()  # First attempt
        except:
            host = None

        if not host or "burp.Zlq4@" in host:  # If still incorrect, parse from URL
            try:
                host = URL(url).getHost()
            except:
                host = None

        if not host or "burp.Zlq4@" in host:  # Last fallback: Extract manually
            host = url.split("//")[-1].split("/")[0].split(":")[0]

        print("[DEBUG] Extracted Host: {}".format(host))  # Jython-compatible string formatting

        return host

    def categorize_request(self, url):
        # Define context patterns (Expanded for bug bounty usage)
        category_patterns = {
            "Login": r"(?i)login|signin",
            "Signup": r"(?i)signup|register",
            "Profile": r"(?i)profile|account",
            "Dashboard": r"(?i)dashboard|home",
            "Search": r"(?i)search|query",
            "Admin": r"(?i)admin|backend|panel",
            "API": r"(?i)api|graphql|rest",
            "Settings": r"(?i)settings|preferences|config",
            "Files": r"(?i)upload|download|files",
            "Payments": r"(?i)payment|checkout|billing",
            "Logs": r"(?i)logs|debug|trace",
            "Tokens": r"(?i)token|auth|jwt|session",
            "Other": r".*"
        }

        for category, pattern in category_patterns.items():
            if re.search(pattern, url):
                return category
        return "Other"

    def create_category_tab(self, category):
        """ Creates a new tab for the categorized requests. """
        panel = JPanel(awt.BorderLayout())

        # Create Table
        table_model = DefaultTableModel(["Host", "Method", "URL", "Status", "Length", "MIME Type"], 0)
        table = JTable(table_model)
        scroll_pane = JScrollPane(table)

        # Create request/response tabs with Burp's built-in editor
        request_editor = self._callbacks.createMessageEditor(self, False)
        response_editor = self._callbacks.createMessageEditor(self, False)

        request_response_tabs = JTabbedPane()
        request_response_tabs.addTab("Request", request_editor.getComponent())
        request_response_tabs.addTab("Response", response_editor.getComponent())

        # SplitPane to mimic HTTP history layout
        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, scroll_pane, request_response_tabs)
        split_pane.setDividerLocation(200)

        panel.add(split_pane, awt.BorderLayout.CENTER)
        self.tabs.addTab(category, panel)

        self.request_categories[category] = {
            "table_model": table_model,
            "table": table,
            "request_editor": request_editor,
            "response_editor": response_editor
        }

        # Add listener for row selection
        table.getSelectionModel().addListSelectionListener(lambda event: self.update_request_response_details(category))

    def add_request_to_tab(self, category, host, method, url, status_code, response_length, mime_type, full_request, full_response, messageInfo):
        """ Adds a request entry to the corresponding category tab. """
        model = self.request_categories[category]["table_model"]
        table = self.request_categories[category]["table"]

        # Store request & response objects in table row metadata
        row_index = model.getRowCount()
        model.addRow([host, method, url, status_code, response_length, mime_type])
        table.setValueAt(messageInfo, row_index, 0)  # Store messageInfo for later retrieval

    def update_request_response_details(self, category):
        """ Updates the request-response panel when a row is selected. """
        table = self.request_categories[category]["table"]
        selected_row = table.getSelectedRow()
        if selected_row == -1:
            return

        messageInfo = table.getValueAt(selected_row, 0)
        if messageInfo:
            request_editor = self.request_categories[category]["request_editor"]
            response_editor = self.request_categories[category]["response_editor"]

            request_editor.setMessage(messageInfo.getRequest(), True)
            response_editor.setMessage(messageInfo.getResponse(), False)