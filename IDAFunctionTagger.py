import idc
import json
import webbrowser

from idautils import *
from idaapi import *
from idaapi import PluginForm

from PyQt5 import QtGui, QtCore, QtWidgets

open_tag = "[TagList:"
close_tag = "]"
tag_separator = ","

class TagManager(object):
    def __init__(self):
        self.clear()

    def _addTagToFunction(self, function_name, tag_name):
        global open_tag
        global close_tag
        global tag_separator

        function_address = LocByName(function_name)
        function_comment = GetFunctionCmt(function_address, 0)

        tag_list_start = function_comment.find(open_tag)
        if tag_list_start == -1:
            SetFunctionCmt(function_address, function_comment + open_tag + tag_name + close_tag, 0)
            return

        tag_list_end = function_comment.find(close_tag, tag_list_start)
        if tag_list_end == -1:
            print("Malformed tag list found at address 0x%X" % function_address)
            return

        tag_list = function_comment[tag_list_start : tag_list_end + 1]
        function_comment = function_comment.replace(tag_list, "")

        tag_list = tag_list[len(open_tag) : len(tag_list) - len(close_tag)]
        tag_list = tag_list.split(tag_separator)

        if tag_name not in tag_list:
            tag_list.append(tag_name)
        tag_list.sort()

        function_comment = function_comment + open_tag
        for tag in tag_list:
            function_comment = function_comment + tag + tag_separator
        function_comment = function_comment[ : -1] + close_tag

        SetFunctionCmt(function_address, function_comment, 0)

    def scanDatabase(self, json_configuration):
        configuration = ""

        try:
            configuration = json.loads(json_configuration)
        except:
            print("Invalid configuration file")
            return

        print("Loading configuration: %s" % configuration["name"])
        print("Configuration comment: %s" % configuration["comment"])

        for tag in configuration["tag_list"]:
            print("Scanning for tag '%s'..." % tag["name"])
            for imported_function in tag["import_list"]:
                function_address = LocByName(str(imported_function))
                if function_address == BADADDR:
                    continue

                cross_reference_list = CodeRefsTo(function_address, 0)
                for xref in cross_reference_list:
                    function_name = GetFunctionName(xref)
                    self._addTagToFunction(function_name, str(tag["name"]))

    def removeAllTags(self):
        global open_tag
        global close_tag

        entry_point = BeginEA()
        function_list = Functions(SegStart(entry_point), SegEnd(entry_point))

        for function_address in function_list:
            function_comment = GetFunctionCmt(function_address, 0)

            tag_list_start = function_comment.find(open_tag)
            if tag_list_start == -1:
                continue

            tag_list_end = function_comment.find(close_tag, tag_list_start)
            if tag_list_end == -1:
                continue

            SetFunctionCmt(function_address, function_comment.replace(function_comment[tag_list_start : tag_list_end + 1], ""), 0)

    def clear(self):
        self._tag_list = {}
        self._function_list = {}

    def update(self):
        global open_tag
        global close_tag
        global tag_separator

        self.clear()

        entry_point = BeginEA()
        function_list = Functions(SegStart(entry_point), SegEnd(entry_point))

        for function_address in function_list:
            function_comment = GetFunctionCmt(function_address, 0)

            tag_list_start = function_comment.find(open_tag)
            if tag_list_start == -1:
                continue

            tag_list_end = function_comment.find(close_tag, tag_list_start)
            if tag_list_end == -1:
                continue

            tag_list = function_comment[tag_list_start + len(open_tag) : tag_list_end]
            if len(tag_list) == 0:
                continue

            self._function_list[GetFunctionName(function_address)] = tag_list.split(tag_separator)

            tag_list = tag_list.split(tag_separator)
            for tag_name in tag_list:
                if tag_name not in self._tag_list:
                    self._tag_list[tag_name] = []

                self._tag_list[tag_name].append(GetFunctionName(function_address))

    def tagList(self):
        return self._tag_list

    def functionList(self):
        return self._function_list

class TagViewer_t(PluginForm):
    def Update(self):
        self._tag_list_model.clear();
        self._function_list_model.clear();

        self._tag_list_model.setHorizontalHeaderLabels(["Tag", "Function", "Address"])
        self._function_list_model.setHorizontalHeaderLabels(["Function", "Address", "Tags"])

        for tag_name in self._tag_manager.tagList().iterkeys():
            tag = self._tag_manager.tagList()[tag_name]

            tag_item = QtGui.QStandardItem(tag_name)
            self._tag_list_model.appendRow([tag_item])

            for function_name in tag:
                function_name_item = QtGui.QStandardItem(function_name)

                address = LocByName(function_name)
                address_item = QtGui.QStandardItem("0x%X" % address)

                tag_item.appendRow([QtGui.QStandardItem(), function_name_item, address_item])

        for function_name in self._tag_manager.functionList().iterkeys():
            tag_list = self._tag_manager.functionList()[function_name]

            function_name_item = QtGui.QStandardItem(function_name)
            address_item = QtGui.QStandardItem("0x%X" % LocByName(function_name))

            tag_list_string = ""
            for tag in tag_list:
                tag_list_string = tag_list_string + " " + tag

            tag_list_item = QtGui.QStandardItem(tag_list_string)

            self._function_list_model.appendRow([function_name_item, address_item, tag_list_item])

        self._function_list_view.expandAll()
        self._tag_list_view.expandAll()

        for i in range(0, 2):
            self._function_list_view.resizeColumnToContents(i)
            self._tag_list_view.resizeColumnToContents(i)

    def _onTagClick(self, model_index):
        function_address = BADADDR

        if model_index.column() == 2:
            try:
                function_address = int(model_index.data(), 16)
            except:
                pass

        elif model_index.column() == 1:
            function_address = LocByName(str(model_index.data()))

        else:
            return

        Jump(function_address)

    def _onFunctionClick(self, model_index):
        function_address = BADADDR

        if model_index.column() == 1:
            try:
                function_address = int(model_index.data(), 16)
            except:
                pass

        elif model_index.column() == 0:
            function_address = LocByName(str(model_index.data()))

        else:
            return

        Jump(function_address)

    def _onUpdateClick(self):
        self._tag_manager.update()
        self.Update()

    def _onScanDatabaseClick(self):
        file_path = QtWidgets.QFileDialog.getOpenFileName(self._parent_widget, 'Open configuration file', os.curdir, "*.json")
        if len(file_path[0]) == 0:
            return

        input_file = open(file_path[0], "r")
        file_buffer = input_file.read()
        input_file.close()

        self._tag_manager.scanDatabase(file_buffer)
        self._tag_manager.update()
        self.Update()

    def _onRemoveAllTagsClick(self):
        self._tag_manager.removeAllTags()
        self._tag_manager.update()
        self.Update()

    def _onHomepageClick(self):
        webbrowser.open("https://alessandrogar.io", new = 2, autoraise = True)

    def _onClearFilterClick(self):
        self._filter_box.clear()

    def _onFilterTextChanged(self, text):
        filter = QtCore.QRegExp(text, QtCore.Qt.CaseInsensitive, QtCore.QRegExp.Wildcard)

        self._function_list_model_filter.setFilterRegExp(filter)

        self._function_list_view.expandAll()
        self._tag_list_view.expandAll()

    def OnCreate(self, parent_form):
        self._tag_manager = TagManager()
        self._tag_manager.update()

        self._tag_list_model = QtGui.QStandardItemModel()

        self._function_list_model = QtGui.QStandardItemModel()
        self._function_list_model_filter = QtCore.QSortFilterProxyModel()
        self._function_list_model_filter.setSourceModel(self._function_list_model)
        self._function_list_model_filter.setFilterKeyColumn(2)

        layout = QtWidgets.QVBoxLayout()
        filter_layout = QtWidgets.QHBoxLayout()

        text_label = QtWidgets.QLabel()
        text_label.setText("Filter: ")
        filter_layout.addWidget(text_label)

        self._filter_box = QtWidgets.QLineEdit()
        self._filter_box.textChanged.connect(self._onFilterTextChanged)
        filter_layout.addWidget(self._filter_box)

        button = QtWidgets.QPushButton()
        button.setText("Clear")
        button.clicked.connect(self._onClearFilterClick)
        filter_layout.addWidget(button)

        layout.addLayout(filter_layout)

        self._parent_widget = self.FormToPyQtWidget(parent_form)
        splitter = QtWidgets.QSplitter()
        layout.addWidget(splitter)

        self._tag_list_view = QtWidgets.QTreeView()
        self._tag_list_view.setAlternatingRowColors(True)
        self._tag_list_view.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self._tag_list_view.setModel(self._tag_list_model)
        self._tag_list_view.setUniformRowHeights(True)
        self._tag_list_view.doubleClicked.connect(self._onTagClick)
        self._tag_list_view.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        splitter.addWidget(self._tag_list_view)

        self._function_list_view = QtWidgets.QTreeView()
        self._function_list_view.setAlternatingRowColors(True)
        self._function_list_view.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self._function_list_view.setModel(self._function_list_model_filter)
        self._function_list_view.setUniformRowHeights(True)
        self._function_list_view.doubleClicked.connect(self._onFunctionClick)
        self._function_list_view.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        splitter.addWidget(self._function_list_view)

        controls_layout = QtWidgets.QHBoxLayout()

        button = QtWidgets.QPushButton()
        button.setText("Homepage")
        button.clicked.connect(self._onHomepageClick)
        controls_layout.addWidget(button)

        controls_layout.insertStretch(1, -1)

        button = QtWidgets.QPushButton()
        button.setText("Update")
        button.clicked.connect(self._onUpdateClick)
        controls_layout.addWidget(button)

        button = QtWidgets.QPushButton()
        button.setText("Scan database")
        button.clicked.connect(self._onScanDatabaseClick)
        controls_layout.addWidget(button)

        button = QtWidgets.QPushButton()
        button.setText("Remove all tags")
        button.clicked.connect(self._onRemoveAllTagsClick)
        controls_layout.addWidget(button)

        layout.addLayout(controls_layout)        

        self.Update()

        self._parent_widget.setLayout(layout)

    def OnClose(self, parent_form):
        return

    def Show(self):
        return PluginForm.Show(self, "Function Tags", options = PluginForm.FORM_TAB)

def unloadScript():
    global TagViewer
    TagViewer.Close(0)

    if not uninstallMenus():
        print("Failed to uninstall the menus")

    del TagViewer

def openTagViewer():
    global TagViewer
    TagViewer.Show()

TagViewer = TagViewer_t()
TagViewer.Show()
