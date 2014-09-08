import idc
import json
import webbrowser

from idautils import *
from idaapi import *
from idaapi import PluginForm

from PySide import QtGui, QtCore

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
                function_address = LocByName(str(imported_function)) # 'unicode' to 'str'
                if function_address == BADADDR:
                    continue

                cross_reference_list = CodeRefsTo(function_address, 0)
                for xref in cross_reference_list:
                    function_name = GetFunctionName(xref)
                    self._addTagToFunction(function_name, str(tag["name"])) # 'unicode' to 'str'

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
        self._tag_list.clear();
        self._function_list.clear();

        root_item = QtGui.QTreeWidgetItem(self._tag_list)
        root_item.setText(0, "Tag List")

        for tag_name in self._tag_manager.tagList().iterkeys():
            tag = self._tag_manager.tagList()[tag_name]

            tag_item = QtGui.QTreeWidgetItem(root_item)
            tag_item.setText(0, tag_name)

            for function_name in tag:
                item = QtGui.QTreeWidgetItem(tag_item)
                item.setText(1, function_name)

                address = LocByName(function_name)
                item.setText(2, "0x%X" % address)

        root_item = QtGui.QTreeWidgetItem(self._function_list)
        root_item.setText(0, "Function List")

        for function_name in self._tag_manager.functionList().iterkeys():
            tag_list = self._tag_manager.functionList()[function_name]
            item = QtGui.QTreeWidgetItem(root_item)
            item.setText(0, function_name)

            address = LocByName(function_name)
            item.setText(1, "0x%X" % address)

            tag_list_string = ""
            for tag in tag_list:
                tag_list_string = tag_list_string + " " + tag

            item.setText(2, tag_list_string)

        self._function_list.expandAll()
        self._tag_list.expandAll()

        for i in range(0, 2):
            self._function_list.resizeColumnToContents(i)
            self._tag_list.resizeColumnToContents(i)

    def _onTagClick(self, item, column):
        function_address = int(item.text(2), 16)
        Jump(function_address)

    def _onFunctionClick(self, item, column):
        function_address = int(item.text(1), 16)
        Jump(function_address)

    def _onUpdateClick(self):
        self._tag_manager.update()
        self.Update()

    def _onScanDatabaseClick(self):
        file_path = QtGui.QFileDialog.getOpenFileName(self._parent_widget, 'Open configuration file', os.curdir, "*.json")
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
        webbrowser.open("http://alessandrogar.io", new = 2, autoraise = True)
        return

    def OnCreate(self, parent_form):
        self._tag_manager = TagManager()
        self._tag_manager.update()

        layout = QtGui.QVBoxLayout()

        self._parent_widget = self.FormToPySideWidget(parent_form)
        splitter = QtGui.QSplitter()
        layout.addWidget(splitter)

        self._tag_list = QtGui.QTreeWidget()
        self._tag_list.setHeaderLabels(["Tag", "Function", "Address"])
        self._tag_list.itemDoubleClicked.connect(self._onTagClick)
        splitter.addWidget(self._tag_list)

        self._function_list = QtGui.QTreeWidget()
        self._function_list.setHeaderLabels(["Function", "Address", "Tags"])
        self._function_list.itemDoubleClicked.connect(self._onFunctionClick)
        splitter.addWidget(self._function_list)

        buttons_layout = QtGui.QHBoxLayout()

        button = QtGui.QPushButton()
        button.setText("Homepage")
        button.clicked.connect(self._onHomepageClick)
        buttons_layout.addWidget(button)

        buttons_layout.insertStretch(1, -1)

        button = QtGui.QPushButton()
        button.setText("Update")
        button.clicked.connect(self._onUpdateClick)
        buttons_layout.addWidget(button)

        button = QtGui.QPushButton()
        button.setText("Scan database")
        button.clicked.connect(self._onScanDatabaseClick)
        buttons_layout.addWidget(button)

        button = QtGui.QPushButton()
        button.setText("Remove all tags")
        button.clicked.connect(self._onRemoveAllTagsClick)
        buttons_layout.addWidget(button)

        layout.addLayout(buttons_layout)        

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

open_dialog_menu_item = None
unload_script_menu_item = None

def initializeMenus():
    global open_dialog_menu_item
    global unload_script_menu_item

    if open_dialog_menu_item == None:
        open_dialog_menu_item = idaapi.add_menu_item("View/", "Function Tags", "", 0, openTagViewer, None)
        if open_dialog_menu_item is None:
            del open_dialog_menu_item
            open_dialog_menu_item = None
            return False

    if unload_script_menu_item == None:
        unload_script_menu_item = idaapi.add_menu_item("Edit/", "Unload Function Tags Plugin", "", 0, unloadScript, None)
        if unload_script_menu_item is None:
            del unload_script_menu_item
            unload_script_menu_item = None

            idaapi.del_menu_item(open_dialog_menu_item)
            del open_dialog_menu_item
            open_dialog_menu_item = None

            return False

    return True

def uninstallMenus():
    global open_dialog_menu_item
    global unload_script_menu_item

    if open_dialog_menu_item != None:
        idaapi.del_menu_item(open_dialog_menu_item)
        del open_dialog_menu_item
        open_dialog_menu_item = None

    if unload_script_menu_item != None:
        idaapi.del_menu_item(unload_script_menu_item)
        del unload_script_menu_item
        unload_script_menu_item = None

    return True

def main():
    global TagViewer

    try:
        TagViewer
        print("The script is already loaded")

    except:
        TagViewer = TagViewer_t()

        if not initializeMenus():
            del TagViewer
            print("Could not initialize the menus")

        TagViewer.Show()

main()
