from burp import IBurpExtender, ITab, IMessageEditorController
from javax.swing import JPanel, JTabbedPane, JScrollPane, JTable, JSplitPane, JTextField, JButton, JLabel, JOptionPane
from javax.swing.table import DefaultTableModel
import java.awt as awt
from java.awt.event import ActionListener
import re
from java.net import URL

class BurpExtender(IBurpExtender, ITab, IMessageEditorController):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("RequestCategorizer")
        
        # Main panel
        self.main_panel = JPanel(awt.BorderLayout())
        
        # Top panel for keyword management
        self.create_keyword_panel()
        
        # Tabs for categories
        self.tabs = JTabbedPane()
        self.main_panel.add(self.tabs, awt.BorderLayout.CENTER)
        
        self.request_categories = {}
        self.user_keywords = {}  # Store user-defined keywords {keyword: tab_name}
        
        self._callbacks.addSuiteTab(self)
    
    def create_keyword_panel(self):
        """Create the top panel for keyword management"""
        top_panel = JPanel(awt.FlowLayout(awt.FlowLayout.LEFT))
        
        top_panel.add(JLabel("Keyword:"))
        self.keyword_field = JTextField(15)
        top_panel.add(self.keyword_field)
        
        top_panel.add(JLabel("Tab Name:"))
        self.tab_name_field = JTextField(15)
        top_panel.add(self.tab_name_field)
        
        add_button = JButton("Add Category", actionPerformed=self.add_keyword_category)
        top_panel.add(add_button)
        
        remove_button = JButton("Remove Category", actionPerformed=self.remove_keyword_category)
        top_panel.add(remove_button)
        
        # Refresh button to re-scan proxy history
        refresh_button = JButton("Refresh All", actionPerformed=self.refresh_all_categories)
        top_panel.add(refresh_button)
        
        self.main_panel.add(top_panel, awt.BorderLayout.NORTH)
    
    def sanitize_keyword(self, keyword):
        """Sanitize keyword to handle special characters properly"""
        if not keyword:
            return ""
        keyword = str(keyword).strip()
        return keyword
    
    def safe_string_contains(self, text, keyword):
        """Safely check if text contains keyword, handling special characters"""
        try:
            text_str = str(text).lower() if text else ""
            keyword_str = str(keyword).lower() if keyword else ""
            return keyword_str in text_str
        except Exception as e:
            print("[DEBUG] Error in string matching: {}".format(str(e)))
            return False
    
    def get_proxy_history(self):
        """Get all requests from Burp's proxy history"""
        try:
            proxy_history = self._callbacks.getProxyHistory()
            print("[DEBUG] Found {} requests in proxy history".format(len(proxy_history)))
            return proxy_history
        except Exception as e:
            print("[ERROR] Failed to get proxy history: {}".format(str(e)))
            return []
    
    def add_keyword_category(self, event):
        """Add a new keyword-based category"""
        raw_keyword = self.keyword_field.getText()
        raw_tab_name = self.tab_name_field.getText()
        
        # Sanitize inputs
        keyword = self.sanitize_keyword(raw_keyword)
        tab_name = self.sanitize_keyword(raw_tab_name)
        
        if not keyword or not tab_name:
            JOptionPane.showMessageDialog(None, "Please enter both keyword and tab name")
            return
        
        if tab_name in self.request_categories:
            JOptionPane.showMessageDialog(None, "Tab with this name already exists")
            return
        
        # Store the keyword mapping
        self.user_keywords[keyword] = tab_name
        print("[DEBUG] Added keyword: '{}' for tab: '{}'".format(keyword, tab_name))
        
        # Create the tab
        self.create_category_tab(tab_name)
        
        # Scan proxy history for matching requests
        matched_count = self.scan_proxy_history_for_keyword(keyword, tab_name)
        
        # Clear the input fields
        self.keyword_field.setText("")
        self.tab_name_field.setText("")
        
        JOptionPane.showMessageDialog(None, "Category '{}' added successfully\nFound {} matching requests".format(tab_name, matched_count))
    
    def scan_proxy_history_for_keyword(self, keyword, tab_name):
        """Scan proxy history for requests matching the keyword"""
        proxy_history = self.get_proxy_history()
        matched_count = 0
        
        for messageInfo in proxy_history:
            try:
                # Get request details
                request_info = self._helpers.analyzeRequest(messageInfo)
                url = request_info.getUrl().toString()
                method = request_info.getMethod()
                host = self.extract_host(messageInfo, url)
                
                # Get response details
                response_bytes = messageInfo.getResponse()
                if not response_bytes:
                    continue
                    
                response_info = self._helpers.analyzeResponse(response_bytes)
                status_code = response_info.getStatusCode()
                mime_type = response_info.getStatedMimeType() if response_info.getStatedMimeType() else "Unknown"
                response_length = len(response_bytes)
                
                # Convert to strings for searching
                full_request = self._helpers.bytesToString(messageInfo.getRequest())
                full_response = self._helpers.bytesToString(response_bytes)
                
                # Check if keyword matches
                if (self.safe_string_contains(url, keyword) or
                    self.safe_string_contains(full_request, keyword) or
                    self.safe_string_contains(full_response, keyword)):
                    
                    self.add_request_to_tab(tab_name, host, method, url, status_code, response_length, mime_type, messageInfo)
                    matched_count += 1
                    
            except Exception as e:
                print("[ERROR] Failed to process request: {}".format(str(e)))
                continue
        
        print("[DEBUG] Added {} requests to category '{}'".format(matched_count, tab_name))
        return matched_count
    
    def refresh_all_categories(self, event):
        """Refresh all categories by re-scanning proxy history"""
        if not self.user_keywords:
            JOptionPane.showMessageDialog(None, "No categories defined")
            return
        
        total_matches = 0
        
        # Clear all existing tabs
        for tab_name in self.request_categories.keys():
            model = self.request_categories[tab_name]["table_model"]
            model.setRowCount(0)  # Clear existing data
        
        # Re-scan for all keywords
        for keyword, tab_name in self.user_keywords.items():
            matched_count = self.scan_proxy_history_for_keyword(keyword, tab_name)
            total_matches += matched_count
        
        JOptionPane.showMessageDialog(None, "Refreshed all categories\nTotal matches found: {}".format(total_matches))
    
    def remove_keyword_category(self, event):
        """Remove a keyword-based category"""
        raw_tab_name = self.tab_name_field.getText()
        tab_name = self.sanitize_keyword(raw_tab_name)
        
        if not tab_name:
            JOptionPane.showMessageDialog(None, "Please enter the tab name to remove")
            return
        
        if tab_name not in self.request_categories:
            JOptionPane.showMessageDialog(None, "Tab '{}' does not exist".format(tab_name))
            return
        
        # Remove from user keywords
        keyword_to_remove = None
        for keyword, name in self.user_keywords.items():
            if name == tab_name:
                keyword_to_remove = keyword
                break
        
        if keyword_to_remove:
            del self.user_keywords[keyword_to_remove]
            print("[DEBUG] Removed keyword: '{}'".format(keyword_to_remove))
        
        # Remove the tab
        tab_index = -1
        for i in range(self.tabs.getTabCount()):
            if self.tabs.getTitleAt(i) == tab_name:
                tab_index = i
                break
        
        if tab_index != -1:
            self.tabs.removeTabAt(tab_index)
            del self.request_categories[tab_name]
        
        self.tab_name_field.setText("")
        JOptionPane.showMessageDialog(None, "Category '{}' removed successfully".format(tab_name))

    def extract_host(self, messageInfo, url):
        """Extracts the correct hostname"""
        try:
            host = messageInfo.getHttpService().getHost()
        except:
            host = None
        
        if not host or "burp.Zlq4@" in str(host):
            try:
                host = URL(url).getHost()
            except:
                host = None
        
        if not host or "burp.Zlq4@" in str(host):
            try:
                host = str(url).split("//")[-1].split("/")[0].split(":")[0]
            except:
                host = "unknown"
        
        return str(host) if host else "unknown"

    def getTabCaption(self):
        return "Categorizer"

    def getUiComponent(self):
        return self.main_panel

    def create_category_tab(self, category):
        """Creates a new tab for the categorized requests"""
        if category in self.request_categories:
            return
        
        panel = JPanel(awt.BorderLayout())
        
        table_model = DefaultTableModel(["Host", "Method", "URL", "Status", "Length", "MIME Type"], 0)
        table = JTable(table_model)
        scroll_pane = JScrollPane(table)
        
        request_editor = self._callbacks.createMessageEditor(self, False)
        response_editor = self._callbacks.createMessageEditor(self, False)
        
        request_response_tabs = JTabbedPane()
        request_response_tabs.addTab("Request", request_editor.getComponent())
        request_response_tabs.addTab("Response", response_editor.getComponent())
        
        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, scroll_pane, request_response_tabs)
        split_pane.setDividerLocation(200)
        
        panel.add(split_pane, awt.BorderLayout.CENTER)
        self.tabs.addTab(category, panel)
        
        self.request_categories[category] = {
            "table_model": table_model,
            "table": table,
            "request_editor": request_editor,
            "response_editor": response_editor,
            "message_infos": []  # Store MessageInfo objects
        }
        
        table.getSelectionModel().addListSelectionListener(lambda event: self.update_request_response_details(category))

    def add_request_to_tab(self, category, host, method, url, status_code, response_length, mime_type, messageInfo):
        """Adds a request entry to the corresponding category tab"""
        if category not in self.request_categories:
            return
            
        try:
            model = self.request_categories[category]["table_model"]
            message_infos = self.request_categories[category]["message_infos"]
            
            model.addRow([str(host), str(method), str(url), str(status_code), str(response_length), str(mime_type)])
            message_infos.append(messageInfo)
        except Exception as e:
            print("[ERROR] Failed to add request to tab '{}': {}".format(category, str(e)))

    def update_request_response_details(self, category):
        """Updates the request-response panel when a row is selected"""
        try:
            table = self.request_categories[category]["table"]
            selected_row = table.getSelectedRow()
            
            if selected_row == -1:
                return
            
            message_infos = self.request_categories[category]["message_infos"]
            if selected_row < len(message_infos):
                messageInfo = message_infos[selected_row]
                
                request_editor = self.request_categories[category]["request_editor"]
                response_editor = self.request_categories[category]["response_editor"]
                
                request_editor.setMessage(messageInfo.getRequest(), True)
                response_editor.setMessage(messageInfo.getResponse(), False)
        except Exception as e:
            print("[ERROR] Failed to update request/response details: {}".format(str(e)))
