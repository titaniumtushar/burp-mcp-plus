# -*- coding: utf-8 -*-
# Deduped HTTP History + JS Exporter - Burp Suite Extension
#
# Tab 1 - "Deduped History":
#   Deduplicates HTTP history by Method+Host+Path.
#   Re-adds a row only when NEW parameter names are seen on the same endpoint.
#   Full request/response viewer. Export all unique requests to a text file.
#
# Tab 2 - "JS Exporter":
#   Scans proxy history (or live traffic) for JavaScript files.
#   Saves each unique JS file to:
#       <output_dir>/<project_name>/<host>/<path>.js
#   Detects a version string from the filename or URL path.
#   Writes a _manifest.csv alongside the files.

from burp import IBurpExtender, IHttpListener, ITab, IMessageEditorController
from java.io import PrintWriter, File
from javax import swing
from javax.swing import (
    JSplitPane, JTable, JScrollPane, JPanel, JButton,
    JTextField, JLabel, JCheckBox, JFileChooser, SwingUtilities,
    JOptionPane, JTabbedPane, JTextArea, JProgressBar, BoxLayout, Box
)
from javax.swing.table import AbstractTableModel
from java.awt import BorderLayout, Font, Dimension, FlowLayout, GridBagLayout, GridBagConstraints, Insets
import threading
import os
import re
import datetime


# ===========================================================================
# Helpers
# ===========================================================================

def _detect_version(filename, url_path):
    """
    Try to extract a version string from the filename or URL path.
    Examples:
        jquery-3.6.0.min.js          -> 3.6.0
        react.production.min-18.2.0  -> 18.2.0
        /v2/static/app.js            -> v2  (from path segment)
        chunk.abcdef12.js            -> abcdef12  (content hash, treated as version)
    Returns a string or empty string.
    """
    # Semver-like: digits.digits(.digits)*
    m = re.search(r'[-_v]?(\d+\.\d+(?:\.\d+)*)', filename)
    if m:
        return m.group(1)
    # Content hash: 8+ hex chars between dots or dashes
    m = re.search(r'[.\-_]([a-f0-9]{8,})[.\-_]', filename)
    if m:
        return m.group(1)
    # Version path segment like /v2/ or /1.0/
    m = re.search(r'/v?(\d[\d.]*?)/', url_path)
    if m:
        return m.group(1)
    return ""


def _sanitize_path(part):
    """Remove characters unsafe for filesystem paths."""
    return re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', part).strip(". ")


def _is_js_response(url_path, content_type):
    """Return True if this looks like a JavaScript file."""
    path_lower = url_path.lower().split("?")[0]
    if path_lower.endswith(".js") or path_lower.endswith(".mjs"):
        return True
    ct = (content_type or "").lower()
    return "javascript" in ct or "ecmascript" in ct


# ===========================================================================
# Deduped History table model
# ===========================================================================
class DedupeTableModel(AbstractTableModel):
    COLUMNS = ["#", "Method", "Host", "Path", "Parameters", "Status", "Length"]

    def __init__(self):
        self.rows = []

    def getColumnCount(self):
        return len(self.COLUMNS)

    def getColumnName(self, col):
        return self.COLUMNS[col]

    def getRowCount(self):
        return len(self.rows)

    def getValueAt(self, row, col):
        try:
            r = self.rows[row]
            if col == 0: return row + 1
            if col == 1: return r["method"]
            if col == 2: return r["host"]
            if col == 3: return r["path"]
            if col == 4: return r["params"]
            if col == 5: return r["status"]
            if col == 6: return r["length"]
        except Exception:
            return ""

    def isCellEditable(self, row, col):
        return False

    def addRow(self, row_dict):
        self.rows.append(row_dict)
        idx = len(self.rows) - 1
        self.fireTableRowsInserted(idx, idx)

    def clear(self):
        self.rows = []
        self.fireTableDataChanged()


# ===========================================================================
# JS Exporter table model
# ===========================================================================
class JsTableModel(AbstractTableModel):
    COLUMNS = ["#", "Host", "Path", "Version", "Size (bytes)", "Saved As"]

    def __init__(self):
        self.rows = []

    def getColumnCount(self):
        return len(self.COLUMNS)

    def getColumnName(self, col):
        return self.COLUMNS[col]

    def getRowCount(self):
        return len(self.rows)

    def getValueAt(self, row, col):
        try:
            r = self.rows[row]
            if col == 0: return row + 1
            if col == 1: return r["host"]
            if col == 2: return r["path"]
            if col == 3: return r["version"]
            if col == 4: return r["size"]
            if col == 5: return r["saved_as"]
        except Exception:
            return ""

    def isCellEditable(self, row, col):
        return False

    def addRow(self, row_dict):
        self.rows.append(row_dict)
        idx = len(self.rows) - 1
        self.fireTableRowsInserted(idx, idx)

    def clear(self):
        self.rows = []
        self.fireTableDataChanged()


# ===========================================================================
# Main extension
# ===========================================================================
class BurpExtender(IBurpExtender, IHttpListener, ITab):

    # IParameter types to track (exclude cookies = 2)
    TRACKED_PARAM_TYPES = {0, 1, 3, 5, 6}  # URL, BODY, XML, MULTIPART, JSON

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers   = callbacks.getHelpers()
        callbacks.setExtensionName("Deduped History")

        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        # --- dedup state ---
        self.seen_params = {}   # key -> set of param names
        self.request_log = []   # IHttpRequestResponse, parallel to dedup table rows
        self._lock       = threading.Lock()

        # --- JS exporter state ---
        self.js_seen       = set()    # set of (host, path) already saved
        self.js_log        = []       # list of row dicts for manifest
        self._js_lock      = threading.Lock()
        self.js_output_dir = [None]   # mutable cell: base output dir
        self.js_project    = [""]     # mutable cell: project name

        self._initUI()
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        self.stdout.println("[Deduped History] Loaded.")

    # ------------------------------------------------------------------
    # ITab  (wraps a JTabbedPane with two sub-tabs)
    # ------------------------------------------------------------------
    def getTabCaption(self):
        return "Deduped History"

    def getUiComponent(self):
        return self.root_panel

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------
    def _initUI(self):
        self.root_panel = JTabbedPane()
        self.root_panel.addTab("HTTP History (Deduped)", self._buildDedupTab())
        self.root_panel.addTab("JS Exporter",            self._buildJsTab())

    # ---- Dedup tab ---------------------------------------------------
    def _buildDedupTab(self):
        panel = JPanel(BorderLayout(0, 4))

        toolbar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))

        self.btn_process = JButton("Process Proxy History",
                                    actionPerformed=self._processHistory)
        self.btn_clear   = JButton("Clear",  actionPerformed=self._clear)
        self.btn_export  = JButton("Export", actionPerformed=self._export)

        self.chk_scope   = JCheckBox("In-Scope Only",      True)
        self.chk_options = JCheckBox("Exclude OPTIONS",    True)
        self.chk_ext     = JCheckBox("Exclude Extensions", True)

        self.fld_ext = JTextField(
            "js,css,png,jpg,jpeg,gif,ico,svg,woff,woff2,ttf,pdf,map,eot", 28)
        self.fld_ext.setMaximumSize(Dimension(320, 24))
        self.fld_ext.setPreferredSize(Dimension(320, 24))

        for w in [self.btn_process, self.btn_clear, self.btn_export,
                  JLabel("  "), self.chk_scope, self.chk_options, self.chk_ext,
                  JLabel("Ext:"), self.fld_ext]:
            toolbar.add(w)

        self.dedup_model = DedupeTableModel()
        self.dedup_table = JTable(self.dedup_model)
        self.dedup_table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN)
        self.dedup_table.setSelectionMode(swing.ListSelectionModel.SINGLE_SELECTION)
        self.dedup_table.setFont(Font("Consolas", Font.PLAIN, 12))
        self.dedup_table.getTableHeader().setFont(Font("SansSerif", Font.BOLD, 12))
        self.dedup_table.setRowHeight(18)

        for i, w in enumerate([40, 70, 200, 320, 260, 60, 70]):
            self.dedup_table.getColumnModel().getColumn(i).setPreferredWidth(w)

        self.dedup_table.getSelectionModel().addListSelectionListener(
            self._onDedupSelect)

        self._currentItem = [None]
        outer = self

        class MsgCtrl(IMessageEditorController):
            def getHttpService(self):
                item = outer._currentItem[0]
                return item.getHttpService() if item else None
            def getRequest(self):
                item = outer._currentItem[0]
                return item.getRequest() if item else None
            def getResponse(self):
                item = outer._currentItem[0]
                return item.getResponse() if item else None

        ctrl = MsgCtrl()
        self.reqViewer  = self.callbacks.createMessageEditor(ctrl, False)
        self.respViewer = self.callbacks.createMessageEditor(ctrl, False)

        msgTabs = JTabbedPane()
        msgTabs.addTab("Request",  self.reqViewer.getComponent())
        msgTabs.addTab("Response", self.respViewer.getComponent())

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                           JScrollPane(self.dedup_table), msgTabs)
        split.setDividerLocation(340)
        split.setResizeWeight(0.5)

        self.dedup_status = JLabel(
            " 0 unique requests | New row added when a new endpoint"
            " or new parameter name is seen.")
        self.dedup_status.setFont(Font("SansSerif", Font.ITALIC, 11))

        panel.add(toolbar,            BorderLayout.NORTH)
        panel.add(split,              BorderLayout.CENTER)
        panel.add(self.dedup_status,  BorderLayout.SOUTH)
        return panel

    # ---- JS Exporter tab ---------------------------------------------
    def _buildJsTab(self):
        panel = JPanel(BorderLayout(0, 6))

        # --- config bar ---
        cfg = JPanel(GridBagLayout())
        gc = GridBagConstraints()
        gc.insets  = Insets(4, 6, 4, 6)
        gc.fill    = GridBagConstraints.HORIZONTAL
        gc.gridy   = 0

        gc.gridx = 0; gc.weightx = 0
        cfg.add(JLabel("Project Name:"), gc)

        self.js_fld_project = JTextField("MyProject", 16)
        gc.gridx = 1; gc.weightx = 0.2
        cfg.add(self.js_fld_project, gc)

        gc.gridx = 2; gc.weightx = 0
        cfg.add(JLabel("Output Directory:"), gc)

        self.js_fld_dir = JTextField("(click Browse to choose)", 30)
        self.js_fld_dir.setEditable(False)
        gc.gridx = 3; gc.weightx = 0.6
        cfg.add(self.js_fld_dir, gc)

        self.js_btn_browse = JButton("Browse", actionPerformed=self._jsBrowse)
        gc.gridx = 4; gc.weightx = 0
        cfg.add(self.js_btn_browse, gc)

        # --- action bar ---
        actions = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))

        self.js_btn_scan  = JButton("Scan Proxy History",
                                     actionPerformed=self._jsScanHistory)
        self.js_btn_clear = JButton("Clear List",
                                     actionPerformed=self._jsClear)

        self.js_chk_scope = JCheckBox("In-Scope Only", True)
        self.js_chk_live  = JCheckBox("Capture Live Traffic", True)

        self.js_progress  = JProgressBar(0, 100)
        self.js_progress.setStringPainted(True)
        self.js_progress.setString("")
        self.js_progress.setPreferredSize(Dimension(220, 20))

        for w in [self.js_btn_scan, self.js_btn_clear,
                  JLabel("  "), self.js_chk_scope, self.js_chk_live,
                  JLabel("  "), self.js_progress]:
            actions.add(w)

        top = JPanel(BorderLayout())
        top.add(cfg,     BorderLayout.NORTH)
        top.add(actions, BorderLayout.SOUTH)

        # --- table ---
        self.js_model = JsTableModel()
        self.js_table = JTable(self.js_model)
        self.js_table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN)
        self.js_table.setFont(Font("Consolas", Font.PLAIN, 12))
        self.js_table.getTableHeader().setFont(Font("SansSerif", Font.BOLD, 12))
        self.js_table.setRowHeight(18)

        for i, w in enumerate([40, 180, 320, 100, 90, 300]):
            self.js_table.getColumnModel().getColumn(i).setPreferredWidth(w)

        # --- log area ---
        self.js_log_area = JTextArea(6, 80)
        self.js_log_area.setEditable(False)
        self.js_log_area.setFont(Font("Consolas", Font.PLAIN, 11))

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                           JScrollPane(self.js_table),
                           JScrollPane(self.js_log_area))
        split.setDividerLocation(300)
        split.setResizeWeight(0.7)

        self.js_status = JLabel(" 0 JS files captured")
        self.js_status.setFont(Font("SansSerif", Font.ITALIC, 11))

        panel.add(top,           BorderLayout.NORTH)
        panel.add(split,         BorderLayout.CENTER)
        panel.add(self.js_status, BorderLayout.SOUTH)
        return panel

    # ------------------------------------------------------------------
    # IHttpListener
    # ------------------------------------------------------------------
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return
        try:
            self._evaluateDedup(messageInfo)
            if self.js_chk_live.isSelected():
                self._evaluateJs(messageInfo)
        except Exception as e:
            self.stderr.println("[Deduped History] processHttpMessage: " + str(e))

    # ==================================================================
    # DEDUP logic
    # ==================================================================
    def _evaluateDedup(self, messageInfo):
        request = messageInfo.getRequest()
        if not request:
            return

        requestInfo = self.helpers.analyzeRequest(
            messageInfo.getHttpService(), request)
        url = requestInfo.getUrl()

        if self.chk_scope.isSelected() and not self.callbacks.isInScope(url):
            return

        headers = requestInfo.getHeaders()
        if not headers:
            return

        method = headers[0].split(" ")[0].upper()
        if self.chk_options.isSelected() and method == "OPTIONS":
            return

        path = url.getPath() or "/"
        host = url.getHost()

        if self.chk_ext.isSelected() and self._matchesExt(path):
            return

        param_names = self._getParamNames(requestInfo)
        key = method + "\x00" + host + "\x00" + path

        with self._lock:
            if key not in self.seen_params:
                self.seen_params[key] = set(param_names)
                self._dedupAddRow(messageInfo, method, host, path, param_names)
            else:
                existing = self.seen_params[key]
                new_ones = set(param_names) - existing
                if new_ones:
                    self.seen_params[key] = existing | set(param_names)
                    self._dedupAddRow(messageInfo, method, host, path, param_names)

    def _getParamNames(self, requestInfo):
        names = []
        try:
            for p in requestInfo.getParameters():
                if p.getType() in self.TRACKED_PARAM_TYPES:
                    name = p.getName().strip()
                    if name:
                        names.append(name)
        except Exception as e:
            self.stderr.println("[Deduped History] _getParamNames: " + str(e))
        return sorted(set(names))

    def _matchesExt(self, path):
        ext_text = self.fld_ext.getText().strip()
        if not ext_text:
            return False
        excluded = set(e.strip().lower() for e in ext_text.split(","))
        bare = path.split("?")[0]
        if "." in bare:
            ext = bare.rsplit(".", 1)[-1].lower()
            return ext in excluded
        return False

    def _dedupAddRow(self, messageInfo, method, host, path, param_names):
        status = ""
        length = ""
        try:
            resp = messageInfo.getResponse()
            if resp:
                ri     = self.helpers.analyzeResponse(resp)
                status = str(ri.getStatusCode())
                length = str(len(resp))
        except Exception:
            pass

        params_str = ", ".join(param_names) if param_names else "(none)"
        captured   = messageInfo

        def _edt():
            with self._lock:
                self.request_log.append(captured)
            self.dedup_model.addRow({
                "method": method, "host": host, "path": path,
                "params": params_str, "status": status, "length": length,
            })
            count = len(self.dedup_model.rows)
            self.dedup_status.setText(
                " {} unique request{} captured".format(
                    count, "s" if count != 1 else ""))

        SwingUtilities.invokeLater(_edt)

    def _onDedupSelect(self, event):
        if event.getValueIsAdjusting():
            return
        row = self.dedup_table.getSelectedRow()
        with self._lock:
            if 0 <= row < len(self.request_log):
                item = self.request_log[row]
            else:
                return
        self._currentItem[0] = item
        self.reqViewer.setMessage(item.getRequest() or b"", True)
        resp = item.getResponse()
        self.respViewer.setMessage(resp if resp else b"", False)

    def _clear(self, event):
        with self._lock:
            self.seen_params.clear()
            self.request_log = []
        self._currentItem[0] = None
        SwingUtilities.invokeLater(lambda: (
            self.dedup_model.clear(),
            self.dedup_status.setText(" 0 unique requests captured"),
            self.reqViewer.setMessage(b"", True),
            self.respViewer.setMessage(b"", False),
        ))

    def _processHistory(self, event):
        def run():
            history = self.callbacks.getProxyHistory()
            self.stdout.println(
                "[Deduped History] Processing {} items...".format(len(history)))
            for i, item in enumerate(history):
                try:
                    self._evaluateDedup(item)
                except Exception as e:
                    self.stderr.println("item {}: {}".format(i, e))
            self.stdout.println("[Deduped History] Done.")

        threading.Thread(target=run, name="Dedupe-Processor").start()

    def _export(self, event):
        chooser = JFileChooser()
        chooser.setSelectedFile(File("deduped_requests.txt"))
        if chooser.showSaveDialog(self.root_panel) != JFileChooser.APPROVE_OPTION:
            return
        filepath = chooser.getSelectedFile().getCanonicalPath()

        with self._lock:
            snapshot = list(zip(self.dedup_model.rows, self.request_log))

        # Convert Burp's Java byte[] to a plain Python bytearray safely.
        # Using bytearray(burp_bytes) preserves every raw byte without any
        # codec conversion, so non-ASCII response bodies never cause errors.
        def _safe_bytes(burp_bytes):
            if not burp_bytes:
                return b""
            try:
                return bytes(bytearray(burp_bytes))
            except Exception:
                s = self.helpers.bytesToString(burp_bytes)
                return s.encode("utf-8", errors="replace")

        def _txt(s):
            return s.encode("utf-8", errors="replace")

        try:
            with open(filepath, "wb") as fh:
                fh.write(_txt(
                    "# Deduped HTTP History Export\n"
                    "# Total unique requests: {}\n"
                    "#\n"
                    "# Each block contains:\n"
                    "#   -- REQUEST --   raw HTTP request\n"
                    "#   -- RESPONSE --  raw HTTP response (headers + body)\n"
                    "#\n\n".format(len(snapshot))
                ))

                for idx, (row, mi) in enumerate(snapshot, 1):
                    thick = _txt("=" * 72 + "\n")
                    thin  = _txt("-" * 72 + "\n")

                    fh.write(thick)
                    fh.write(_txt("# [{:04d}]  {} https://{}{}\n".format(
                        idx, row["method"], row["host"], row["path"])))
                    fh.write(_txt("#  Parameters : {}\n".format(row["params"])))
                    fh.write(_txt("#  Status     : {}   Length: {}\n".format(
                        row["status"], row["length"])))
                    fh.write(thick)

                    fh.write(_txt("-- REQUEST --\n"))
                    req = mi.getRequest()
                    fh.write(_safe_bytes(req) if req else _txt("(no request)\n"))

                    fh.write(_txt("\n") + thin)
                    fh.write(_txt("-- RESPONSE --\n"))
                    resp = mi.getResponse()
                    fh.write(_safe_bytes(resp) if resp else _txt("(no response)\n"))

                    fh.write(_txt("\n\n"))

            msg = "Exported {} request/response pairs to:\n{}".format(
                len(snapshot), filepath)
            self.stdout.println("[Deduped History] " + msg)
            JOptionPane.showMessageDialog(self.root_panel, msg,
                                          "Export Complete",
                                          JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            self.stderr.println("[Deduped History] Export error: " + str(e))
            JOptionPane.showMessageDialog(self.root_panel,
                                          "Export failed:\n" + str(e),
                                          "Export Error",
                                          JOptionPane.ERROR_MESSAGE)

    # ==================================================================
    # JS EXPORTER logic
    # ==================================================================
    def _jsBrowse(self, event):
        chooser = JFileChooser()
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        chooser.setDialogTitle("Select JS Output Base Directory")
        if chooser.showOpenDialog(self.root_panel) == JFileChooser.APPROVE_OPTION:
            path = chooser.getSelectedFile().getCanonicalPath()
            self.js_output_dir[0] = path
            self.js_fld_dir.setText(path)

    def _jsClear(self, event):
        with self._js_lock:
            self.js_seen.clear()
            self.js_log = []
        SwingUtilities.invokeLater(lambda: (
            self.js_model.clear(),
            self.js_status.setText(" 0 JS files captured"),
            self.js_log_area.setText(""),
        ))

    def _jsScanHistory(self, event):
        """Scan existing proxy history for JS files and save them."""
        output_dir = self.js_output_dir[0]
        project    = self.js_fld_project.getText().strip()

        if not output_dir:
            JOptionPane.showMessageDialog(
                self.root_panel,
                "Please select an output directory first (click Browse).",
                "No Output Directory", JOptionPane.WARNING_MESSAGE)
            return
        if not project:
            JOptionPane.showMessageDialog(
                self.root_panel,
                "Please enter a project name.",
                "No Project Name", JOptionPane.WARNING_MESSAGE)
            return

        def run():
            try:
                history = self.callbacks.getProxyHistory()
                total   = len(history)
                self._jsLog("Scanning {} proxy history items...".format(total))

                c_no_response  = 0
                c_no_request   = 0
                c_out_of_scope = 0
                c_status_304   = 0
                c_other_status = 0
                c_not_js       = 0
                c_duplicate    = 0
                c_saved        = 0

                def set_progress(pct, txt):
                    SwingUtilities.invokeLater(lambda: (
                        self.js_progress.setValue(pct),
                        self.js_progress.setString(txt),
                    ))

                for i, item in enumerate(history):
                    if i % 200 == 0:
                        pct = int(100.0 * i / total) if total else 100
                        set_progress(pct, "{}/{}".format(i, total))
                    try:
                        response = item.getResponse()
                        if not response:
                            c_no_response += 1
                            continue

                        request = item.getRequest()
                        if not request:
                            c_no_request += 1
                            continue

                        req_info = self.helpers.analyzeRequest(
                            item.getHttpService(), request)
                        url  = req_info.getUrl()
                        host = str(url.getHost() or "")
                        path = str(url.getPath() or "/")

                        if self.js_chk_scope.isSelected():
                            if not self.callbacks.isInScope(url):
                                c_out_of_scope += 1
                                continue

                        resp_info = self.helpers.analyzeResponse(response)
                        status    = resp_info.getStatusCode()
                        if status == 304:
                            c_status_304 += 1
                            continue
                        if status < 200 or status >= 300:
                            c_other_status += 1
                            continue

                        content_type = ""
                        for h in resp_info.getHeaders():
                            if h.lower().startswith("content-type:"):
                                content_type = h.split(":", 1)[1].strip()
                                break

                        if not _is_js_response(path, content_type):
                            c_not_js += 1
                            continue

                        js_key = (host, path)
                        with self._js_lock:
                            if js_key in self.js_seen:
                                c_duplicate += 1
                                continue
                            self.js_seen.add(js_key)

                        if self._saveJsFile(resp_info, response,
                                            host, path, url,
                                            output_dir, project):
                            c_saved += 1

                    except Exception as e:
                        self.stderr.println(
                            "[JS Exporter] item {}: {}".format(i, str(e)))

                set_progress(100, "Done - {} saved".format(c_saved))
                self._jsLog(
                    "Scan complete:\n"
                    "  Saved          : {}\n"
                    "  Duplicates     : {}\n"
                    "  Not JS (ext/ct): {}\n"
                    "  304 Cached     : {}\n"
                    "  Other non-2xx  : {}\n"
                    "  Out of scope   : {}\n"
                    "  No response    : {}\n"
                    "  No request     : {}".format(
                        c_saved, c_duplicate, c_not_js,
                        c_status_304, c_other_status,
                        c_out_of_scope, c_no_response, c_no_request)
                )
                if c_status_304 > 0 and c_saved == 0:
                    self._jsLog(
                        "TIP: {} JS responses were 304 Not Modified (browser "
                        "cache hit). Burp stores no body for those. Clear your "
                        "browser cache, reload the target pages, then scan "
                        "again.".format(c_status_304))
                if c_out_of_scope > 0:
                    self._jsLog(
                        "TIP: {} items skipped (out of scope). Uncheck "
                        "'In-Scope Only' or add the target to Target > "
                        "Scope.".format(c_out_of_scope))
                if c_not_js > 0 and c_saved == 0:
                    self._jsLog(
                        "TIP: {} items had non-JS paths/content-types. JS "
                        "detection looks for .js/.mjs extension in path OR "
                        "'javascript'/'ecmascript' in Content-Type.".format(
                            c_not_js))
                self._writeManifest(output_dir, project)

            except Exception as e:
                self.stderr.println("[JS Exporter] _jsScanHistory: " + str(e))
                self._jsLog("ERROR: " + str(e))

        threading.Thread(target=run, name="JsExporter-Scanner").start()

    def _evaluateJs(self, messageInfo, output_dir=None, project=None):
        """Live-traffic path: called from processHttpMessage on every response."""
        try:
            response = messageInfo.getResponse()
            if not response:
                return False

            request = messageInfo.getRequest()
            if not request:
                return False

            resp_info = self.helpers.analyzeResponse(response)
            status    = resp_info.getStatusCode()
            if status == 304 or status < 200 or status >= 300:
                return False

            req_info = self.helpers.analyzeRequest(
                messageInfo.getHttpService(), request)
            url  = req_info.getUrl()
            host = str(url.getHost() or "")
            path = str(url.getPath() or "/")

            if self.js_chk_scope.isSelected():
                if not self.callbacks.isInScope(url):
                    return False

            content_type = ""
            for h in resp_info.getHeaders():
                if h.lower().startswith("content-type:"):
                    content_type = h.split(":", 1)[1].strip()
                    break

            if not _is_js_response(path, content_type):
                return False

            out_dir = output_dir if output_dir else self.js_output_dir[0]
            proj    = project    if project    else self.js_fld_project.getText().strip()
            if not out_dir or not proj:
                return False

            js_key = (host, path)
            with self._js_lock:
                if js_key in self.js_seen:
                    return False
                self.js_seen.add(js_key)

            return self._saveJsFile(resp_info, response,
                                    host, path, url, out_dir, proj)

        except Exception as e:
            self.stderr.println("[JS Exporter] _evaluateJs: " + str(e))
            return False

    def _saveJsFile(self, resp_info, response,
                    host, path, url, output_dir, project):
        """Write JS body to disk and update the table. Returns True on success."""
        try:
            body_offset = resp_info.getBodyOffset()
            body_bytes  = response[body_offset:]
            size        = len(body_bytes)

            if size == 0:
                self._jsLog("SKIP (empty body): {}{}".format(host, path))
                return False

            filename = os.path.basename(path.split("?")[0]) or "index.js"
            if not filename.lower().endswith((".js", ".mjs")):
                filename = filename + ".js"

            version     = _detect_version(filename, path)
            version_str = version if version else "unknown"

            safe_host = _sanitize_path(host)
            safe_dir  = _sanitize_path(
                os.path.dirname(path).strip("/").replace("/", os.sep))

            save_dir = os.path.join(
                output_dir, _sanitize_path(project), safe_host, safe_dir)

            if not os.path.exists(save_dir):
                os.makedirs(save_dir)

            base, ext = os.path.splitext(filename)
            if version and version not in base:
                disk_filename = "{}.{}{}".format(base, version, ext)
            else:
                disk_filename = filename

            save_path = os.path.join(save_dir, disk_filename)
            if os.path.exists(save_path):
                counter = 1
                while os.path.exists(save_path):
                    save_path = os.path.join(
                        save_dir, "{}.dup{}{}".format(base, counter, ext))
                    counter += 1

            # Jython 2.7 quirk: response[body_offset:] returns an
            # array.array('b', [...]) — calling bytes()/str() on that yields
            # the literal repr "array('b', [10, 10, ...])", not raw bytes.
            # Wrap in bytearray() first to materialize the actual byte values,
            # matching the _safe_bytes idiom used in the dedup exporter above.
            with open(save_path, "wb") as f:
                f.write(bytes(bytearray(body_bytes)))

            rel_path = save_path[len(output_dir):].lstrip(os.sep)

            row_dict = {
                "host":      host,
                "path":      path,
                "version":   version_str,
                "size":      str(size),
                "saved_as":  rel_path,
                "full_url":  str(url),
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }

            with self._js_lock:
                self.js_log.append(row_dict)

            captured = row_dict
            def _edt():
                self.js_model.addRow(captured)
                count = len(self.js_model.rows)
                self.js_status.setText(
                    " {} JS file{} captured".format(
                        count, "s" if count != 1 else ""))

            SwingUtilities.invokeLater(_edt)
            self._jsLog("Saved: {} ({} bytes) ver={}".format(
                rel_path, size, version_str))
            self._writeManifest(output_dir, project)
            return True

        except Exception as e:
            self.stderr.println("[JS Exporter] _saveJsFile: " + str(e))
            return False

    def _writeManifest(self, output_dir, project):
        """Write/overwrite _manifest.csv in the project folder."""
        try:
            proj_dir = os.path.join(output_dir, _sanitize_path(project))
            if not os.path.exists(proj_dir):
                return

            manifest_path = os.path.join(proj_dir, "_manifest.csv")
            with self._js_lock:
                rows = list(self.js_log)

            with open(manifest_path, "wb") as f:
                f.write("index,timestamp,host,path,version,size_bytes,full_url,saved_as\n")
                for i, r in enumerate(rows, 1):
                    line = '{},{},{},{},{},{},{},{}\n'.format(
                        i,
                        r.get("timestamp", ""),
                        r.get("host", ""),
                        r.get("path", ""),
                        r.get("version", ""),
                        r.get("size", ""),
                        r.get("full_url", ""),
                        r.get("saved_as", ""),
                    )
                    f.write(line)

        except Exception as e:
            self.stderr.println("[JS Exporter] _writeManifest: " + str(e))

    def _jsLog(self, msg):
        """Append a message to the JS log area (thread-safe)."""
        def _edt():
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            self.js_log_area.append("[{}] {}\n".format(ts, msg))
            self.js_log_area.setCaretPosition(
                self.js_log_area.getDocument().getLength())

        SwingUtilities.invokeLater(_edt)
