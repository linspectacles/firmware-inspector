#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# LinSpectacles - Linux Inspection Suite
# Copyright (C) 2026 brunonlinespace
# GPL-3.0-or-later

APPLET_ID = 'linspectacles-firmware-inspector'
APPLET_NAME = 'Firmware Inspector'
APPLET_VERSION = '0.0.5'
APPLET_AUTHOR = 'brunonlinespace'
APPLET_EDITOR = 'brunonlinespace'

import json
import os
import platform
import struct
import subprocess
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import QSettings, Qt, QUrl
from PyQt6.QtGui import QBrush, QColor, QKeySequence, QPixmap, QShortcut, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QDialogButtonBox, QHBoxLayout,
    QLabel, QMessageBox, QPushButton, QTabWidget, QTextEdit, QVBoxLayout, QWidget,
)

from ._support import BaseInspectorTab, export_records_dialog, metadata_font_qss


CATEGORY_PLATFORM = 'Platform Firmware'
CATEGORY_DMI = 'DMI / SMBIOS'
CATEGORY_ACPI = 'ACPI Tables'
CATEGORY_EFI = 'EFI Variables'
CATEGORY_ESRT = 'Firmware Update Resources'
CATEGORY_FWUPD = 'fwupd Devices'
CATEGORY_HISTORY = 'Update History'
CATEGORY_MICROCODE = 'Microcode'
CATEGORY_DEVICE_TREE = 'Device Tree'


def _read_text(path):
    path = Path(path)
    try:
        return 'observed', path.read_text(encoding='utf-8', errors='replace').strip()
    except PermissionError:
        return 'restricted', ''
    except FileNotFoundError:
        return 'unavailable', ''
    except OSError as exc:
        return 'error', str(exc)


def _read_bytes(path, limit=None):
    path = Path(path)
    try:
        data = path.read_bytes()
        return 'observed', data if limit is None else data[:limit]
    except PermissionError:
        return 'restricted', b''
    except FileNotFoundError:
        return 'unavailable', b''
    except OSError as exc:
        return 'error', str(exc).encode('utf-8', errors='replace')


def _first_observed(*pairs):
    for state, value in pairs:
        if state == 'observed' and str(value).strip():
            return str(value).strip()
    return ''


def _decode_efi_scalar(name, payload):
    if not payload:
        return ''
    if name in {'SecureBoot', 'SetupMode', 'AuditMode', 'DeployedMode'}:
        value = payload[0]
        if name in {'SecureBoot', 'SetupMode'}:
            return 'Enabled' if value == 1 else 'Disabled' if value == 0 else str(value)
        return str(value)
    return ''


def _efi_filename_parts(filename):
    text = str(filename)
    if len(text) > 37 and text[-37] == '-':
        return text[:-37], text[-36:]
    return text, ''


def _acpi_header(path):
    state, data = _read_bytes(path, 36)
    if state != 'observed':
        return state, {}
    if len(data) < 36:
        return 'error', {'error': 'ACPI table header is shorter than 36 bytes.'}
    try:
        sig, length, revision, checksum, oem_id, oem_table_id, oem_revision, creator_id, creator_revision = struct.unpack(
            '<4sIBB6s8sI4sI', data[:36]
        )
    except struct.error as exc:
        return 'error', {'error': str(exc)}

    def dec(raw):
        return raw.decode('ascii', errors='replace').rstrip('\x00 ').strip()

    return 'observed', {
        'signature': dec(sig),
        'length': int(length),
        'revision': int(revision),
        'checksum': int(checksum),
        'oem_id': dec(oem_id),
        'oem_table_id': dec(oem_table_id),
        'oem_revision': int(oem_revision),
        'creator_id': dec(creator_id),
        'creator_revision': int(creator_revision),
    }


def _run_json_command(args, timeout=12):
    try:
        result = subprocess.run(args, capture_output=True, text=True, check=False, timeout=timeout)
    except FileNotFoundError:
        return 'unavailable', None, f'{args[0]} is not installed or not available in PATH.'
    except subprocess.TimeoutExpired:
        return 'error', None, f'{args[0]} timed out.'
    except Exception as exc:
        return 'error', None, str(exc)
    if result.returncode != 0:
        message = (result.stderr or result.stdout or '').strip() or f'Command exited with status {result.returncode}.'
        return 'error', None, message
    try:
        return 'observed', json.loads(result.stdout or '{}'), ''
    except json.JSONDecodeError as exc:
        return 'error', None, f'Could not parse JSON output: {exc}'


def _json_items(payload, likely_keys):
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in likely_keys:
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    # Some fwupd versions can return a single object-shaped record.
    if any(key in payload for key in ('Name', 'DeviceId', 'Version', 'Guid')):
        return [payload]
    return []


def _pick(mapping, *keys, default=''):
    if not isinstance(mapping, dict):
        return default
    for key in keys:
        value = mapping.get(key)
        if value not in (None, '', [], {}):
            if isinstance(value, list):
                return ', '.join(str(item) for item in value)
            if isinstance(value, dict):
                return json.dumps(value, ensure_ascii=False, sort_keys=True)
            return str(value)
    return default


def _fw_type_label(value):
    text = str(value).strip()
    return {
        '0': 'Unknown',
        '1': 'System Firmware',
        '2': 'Device Firmware',
        '3': 'UEFI Driver',
    }.get(text, text or 'Not reported')


def _esrt_attempt_status(value):
    text = str(value).strip()
    return {
        '0': 'Success',
        '1': 'Unsuccessful',
        '2': 'Insufficient resources',
        '3': 'Incorrect version',
        '4': 'Invalid image format',
        '5': 'Authentication error',
        '6': 'Power event / AC not connected',
        '7': 'Power event / insufficient battery',
    }.get(text, text or 'Not reported')


def _parse_cpuinfo():
    state, text = _read_text('/proc/cpuinfo')
    if state != 'observed':
        return []
    records = []
    current = {}
    for line in text.splitlines():
        if not line.strip():
            if current:
                records.append(current)
                current = {}
            continue
        if ':' not in line:
            continue
        key, value = line.split(':', 1)
        current[key.strip()] = value.strip()
    if current:
        records.append(current)
    return records


def _format_mtime(timestamp):
    try:
        return datetime.fromtimestamp(timestamp).astimezone().isoformat(timespec='seconds')
    except (OSError, OverflowError, ValueError):
        return 'Not reported'


def _microcode_files(root):
    root = Path(root)
    if not root.is_dir():
        return 'unavailable', []
    try:
        paths = sorted((p for p in root.rglob('*') if p.is_file()), key=lambda p: str(p).lower())
    except PermissionError:
        return 'restricted', []
    except OSError:
        return 'error', []
    output = []
    for path in paths:
        try:
            stat = path.stat()
            output.append({
                'path': str(path),
                'size': int(stat.st_size),
                'modified': _format_mtime(stat.st_mtime),
            })
        except PermissionError:
            output.append({'path': str(path), 'size': None, 'modified': 'Restricted'})
        except OSError as exc:
            output.append({'path': str(path), 'size': None, 'modified': f'Unavailable: {exc}'})
    return 'observed', output


def _decode_dt_strings(data):
    if not data or not data.endswith(b'\x00'):
        return None
    parts = data[:-1].split(b'\x00')
    try:
        values = [part.decode('utf-8', errors='strict') for part in parts]
    except UnicodeDecodeError:
        return None
    for value in values:
        if any(ord(ch) < 32 and ch not in '\t' for ch in value):
            return None
    return values


def _dt_common_value(path, name):
    state, data = _read_bytes(path)
    if state != 'observed':
        return state, ''
    if name in {'compatible', 'model', 'status', 'device_type'}:
        values = _decode_dt_strings(data)
        if values is None:
            return 'binary', ''
        return 'observed', ', '.join(values)
    if name in {'phandle', 'linux,phandle', '#address-cells', '#size-cells'} and len(data) == 4:
        return 'observed', str(int.from_bytes(data, 'big'))
    return 'binary', ''


def _dt_property_display(name, data, *, full_hex=False):
    if name in {'compatible', 'model', 'status', 'device_type'}:
        values = _decode_dt_strings(data)
        if values is not None:
            return 'String list' if len(values) > 1 else 'String', ', '.join(values)
    if name in {'phandle', 'linux,phandle', '#address-cells', '#size-cells'} and len(data) == 4:
        return '32-bit cell', str(int.from_bytes(data, 'big'))
    if not data:
        return 'Empty property', '<empty>'
    shown = data if full_hex else data[:64]
    value = shown.hex(' ')
    if not full_hex and len(data) > len(shown):
        value += f' … (+{len(data) - len(shown):,} bytes)'
    return 'Binary', value


class FirmwareOptionsDialog(QDialog):
    def __init__(self, owner):
        super().__init__(owner)
        self.owner = owner
        self.setWindowTitle('Options — Firmware Inspector')
        self.resize(980, 720)

        root = QVBoxLayout(self)
        tabs = QTabWidget()
        root.addWidget(tabs, 1)

        appearance_page = QWidget()
        appearance_layout = QVBoxLayout(appearance_page)
        appearance_layout.setContentsMargins(12, 12, 12, 12)
        appearance_layout.setSpacing(10)

        heading = QLabel('Metadata display')
        font = heading.font(); font.setBold(True); heading.setFont(font)
        appearance_layout.addWidget(heading)
        note = QLabel(
            'Choose how the inventory and Metadata Details panes are arranged. '
            'This Firmware Inspector setting is remembered.'
        )
        note.setWordWrap(True)
        appearance_layout.addWidget(note)

        layout_row = QHBoxLayout()
        layout_row.addWidget(QLabel('Record details layout:'))
        self.layout_combo = QComboBox()
        self.layout_combo.addItems(['Horizontal', 'Vertical'])
        self.layout_combo.setCurrentText('Vertical' if owner.details_orientation == 'vertical' else 'Horizontal')
        self.layout_combo.currentTextChanged.connect(self._layout_changed)
        layout_row.addWidget(self.layout_combo)
        layout_row.addStretch(1)
        appearance_layout.addLayout(layout_row)

        self.show_metadata_panel = QCheckBox('Show Metadata Details panel (F3)')
        self.show_metadata_panel.setChecked(owner.metadata_panel_visible)
        self.show_metadata_panel.toggled.connect(self._metadata_panel_changed)
        appearance_layout.addWidget(self.show_metadata_panel)

        shortcut_note = QLabel(
            'F3 hides/restores Metadata Details. Shift+F5 scans the firmware inventory or scans it again. '
            'Ctrl+L toggles Horizontal/Vertical layout. Ctrl+/ opens Options. '
            'Category: Ctrl+1 = Platform Firmware; Ctrl+2 = DMI / SMBIOS; Ctrl+3 = ACPI Tables; '
            'Ctrl+4 = EFI Variables; Ctrl+5 = Firmware Update Resources; Ctrl+6 = fwupd Devices; '
            'Ctrl+7 = Update History; Ctrl+8 = Microcode; Ctrl+9 = Device Tree; Ctrl+A = All Categories.'
        )
        shortcut_note.setWordWrap(True)
        appearance_layout.addWidget(shortcut_note)
        appearance_layout.addStretch(1)
        tabs.addTab(appearance_page, 'Appearance')

        sources_page = QWidget()
        sources_layout = QVBoxLayout(sources_page)
        sources_layout.setContentsMargins(12, 12, 12, 12)
        sources_layout.setSpacing(10)

        sources_heading = QLabel('Data Sources')
        shf = sources_heading.font(); shf.setBold(True); shf.setPointSize(max(shf.pointSize(), 11)); sources_heading.setFont(shf)
        sources_layout.addWidget(sources_heading)
        sources_note = QLabel('Linux interfaces used by this read-only firmware inspector.')
        sources_note.setWordWrap(True)
        sources_layout.addWidget(sources_note)

        sources_text = QTextEdit()
        sources_text.setReadOnly(True)
        sources_text.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        chosen_font = getattr(owner, '_metadata_font', None)
        if chosen_font is not None:
            sources_text.setFont(chosen_font)
            sources_text.document().setDefaultFont(chosen_font)
            sources_text.setCurrentFont(chosen_font)
            font_rule = metadata_font_qss(chosen_font)
        else:
            font_rule = ''
        sources_text.setStyleSheet(
            'QTextEdit { ' + font_rule +
            ' background-color: #151719; color: #dcdcdc; border: 1px solid #333333; }'
        )
        key_fmt = QTextCharFormat(); key_fmt.setForeground(QColor('#9cdcfe')); key_fmt.setFontWeight(600)
        value_fmt = QTextCharFormat(); value_fmt.setForeground(QColor('#dcdcdc'))
        cursor = sources_text.textCursor(); cursor.movePosition(QTextCursor.MoveOperation.End)
        for line in owner.sources_text().splitlines():
            cursor.insertText(line + '\n', key_fmt if line and not line[:1].isspace() else value_fmt)
        sources_text.setTextCursor(cursor)
        sources_text.moveCursor(QTextCursor.MoveOperation.Start)
        sources_layout.addWidget(sources_text, 1)
        tabs.addTab(sources_page, 'Sources')

        export_page = QWidget()
        export_layout = QVBoxLayout(export_page)
        export_layout.setContentsMargins(12, 12, 12, 12)
        export_layout.setSpacing(10)
        export_heading = QLabel('Export details')
        ef = export_heading.font(); ef.setBold(True); export_heading.setFont(ef)
        export_layout.addWidget(export_heading)
        export_note = QLabel('Select the Firmware Inspector details to include in the export.')
        export_note.setWordWrap(True)
        export_layout.addWidget(export_note)

        self.export_name = QCheckBox('Name')
        self.export_category = QCheckBox('Category')
        self.export_type = QCheckBox('Type')
        self.export_value = QCheckBox('Version / Value')
        self.export_state = QCheckBox('State')
        self.export_metadata = QCheckBox('Metadata Details')
        for checkbox in (self.export_name, self.export_category, self.export_type, self.export_value, self.export_state):
            checkbox.setChecked(True)
        self.export_metadata.setChecked(False)
        for checkbox in (self.export_name, self.export_category, self.export_type, self.export_value, self.export_state, self.export_metadata):
            export_layout.addWidget(checkbox)
        export_layout.addStretch(1)
        row = QHBoxLayout(); row.addStretch(1)
        export_button = QPushButton('Export...'); export_button.clicked.connect(self._export_selected); row.addWidget(export_button)
        export_layout.addLayout(row)
        tabs.addTab(export_page, 'Export')

        about_page = QWidget()
        about_layout = QVBoxLayout(about_page)
        about_layout.setContentsMargins(24, 20, 24, 18)
        about_layout.setSpacing(8)
        icon_label = QLabel(); icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter); icon_label.setFixedSize(112, 112)
        icon_path = Path(__file__).resolve().parent / 'icon.png'
        if icon_path.is_file():
            pixmap = QPixmap(str(icon_path))
            if not pixmap.isNull():
                icon_label.setPixmap(pixmap.scaled(112, 112, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
        about_layout.addWidget(icon_label, alignment=Qt.AlignmentFlag.AlignHCenter)
        name = QLabel("<h2 style='margin:0'>Firmware Inspector</h2>"); name.setAlignment(Qt.AlignmentFlag.AlignCenter); about_layout.addWidget(name)
        version = QLabel(f'Version {APPLET_VERSION}'); version.setAlignment(Qt.AlignmentFlag.AlignCenter); about_layout.addWidget(version)
        slogan = QLabel('<b>Expose. Explore. Explain.</b>'); slogan.setAlignment(Qt.AlignmentFlag.AlignCenter); about_layout.addWidget(slogan)
        description = QLabel(
            'A read-only LinSpectacles applet for inspecting platform firmware identity, '
            'firmware tables and variables, CPU microcode evidence, Device Tree, EFI update resources, and local fwupd state.'
        )
        description.setWordWrap(True); description.setAlignment(Qt.AlignmentFlag.AlignCenter); about_layout.addWidget(description)
        details = QLabel(
            "<b>Build:</b> Standalone LinSpectacles applet<br>"
            "<b>Organisation ID:</b> <a href='https://github.com/linspectacles/'>linspectacles</a><br>"
            f'<b>Applet ID:</b> {APPLET_ID}'
        )
        details.setWordWrap(True)
        details.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction | Qt.TextInteractionFlag.TextSelectableByMouse)
        details.setOpenExternalLinks(True); details.setAlignment(Qt.AlignmentFlag.AlignCenter); about_layout.addWidget(details)
        copyright_label = QLabel("Copyright © 2026 <a href='https://github.com/brunonlinespace'>brunonlinespace</a>")
        copyright_label.setOpenExternalLinks(True); copyright_label.setAlignment(Qt.AlignmentFlag.AlignCenter); about_layout.addWidget(copyright_label)
        license_label = QLabel('Licensed under GNU GPLv3 or later.'); license_label.setAlignment(Qt.AlignmentFlag.AlignCenter); about_layout.addWidget(license_label)
        root_dir = Path(__file__).resolve().parent.parent
        readme_url = QUrl.fromLocalFile(str(root_dir / 'README.md')).toString()
        license_url = QUrl.fromLocalFile(str(root_dir / 'LICENSE')).toString()
        links = QLabel(
            f"<a href='{readme_url}'>README</a> &nbsp;·&nbsp; "
            f"<a href='{license_url}'>License</a> &nbsp;·&nbsp; "
            "<a href='https://github.com/linspectacles/firmware-inspector'>Repository</a>"
        )
        links.setOpenExternalLinks(True); links.setAlignment(Qt.AlignmentFlag.AlignCenter); about_layout.addWidget(links)
        about_layout.addStretch(1)
        tabs.addTab(about_page, 'About')

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def _layout_changed(self, text):
        self.owner.set_details_orientation(str(text).strip().lower(), persist=True)

    def _metadata_panel_changed(self, visible):
        self.owner.set_metadata_panel_visible(bool(visible), persist=True)

    def _export_selected(self):
        selected = []
        if self.export_name.isChecked(): selected.append(('name', 'Name', 220, 'left'))
        if self.export_category.isChecked(): selected.append(('category', 'Category', 180, 'left'))
        if self.export_type.isChecked(): selected.append(('type', 'Type', 170, 'left'))
        if self.export_value.isChecked(): selected.append(('version_value', 'Version / Value', 160, 'left'))
        if self.export_state.isChecked(): selected.append(('state', 'State', 120, 'left'))
        if self.export_metadata.isChecked(): selected.append(('metadata_details', 'Metadata Details', 520, 'left'))
        if not selected:
            QMessageBox.information(self, 'Export', 'Select at least one detail to export.')
            return
        records = []
        include_metadata = self.export_metadata.isChecked()
        for record in self.owner.get_export_records():
            exported = dict(record)
            if include_metadata:
                exported['metadata_details'] = self.owner.metadata_details_for_export(record)
            records.append(exported)
        if not records:
            QMessageBox.information(self, 'Export', 'There is no collected data to export yet.')
            return
        path = export_records_dialog(self, APPLET_NAME, records, columns=selected)
        if path is not None:
            self.owner.set_status(f'Exported data to {path}')


class FirmwareTab(BaseInspectorTab):
    def __init__(self, parent=None):
        columns = [
            ('name', 'Name', 220, 'left'),
            ('category', 'Category', 180, 'left'),
            ('type', 'Type', 170, 'left'),
            ('version_value', 'Version / Value', 160, 'left'),
            ('state', 'State', 120, 'left'),
        ]
        categories = [
            'All Categories', CATEGORY_PLATFORM, CATEGORY_DMI, CATEGORY_ACPI,
            CATEGORY_EFI, CATEGORY_ESRT, CATEGORY_FWUPD, CATEGORY_HISTORY,
            CATEGORY_MICROCODE, CATEGORY_DEVICE_TREE,
        ]
        super().__init__('Total Firmware Records', columns, categories, parent)
        self.export_title = APPLET_NAME
        self._lazy_loaded = set()
        self._lazy_messages = {}
        self._metadata_export_mode = False
        try:
            self.category_dropdown.currentTextChanged.disconnect(self.filter_modules)
        except TypeError:
            pass
        self.category_dropdown.currentTextChanged.connect(self._category_changed)

        self.details_orientation = 'horizontal'
        self._load_details_orientation()
        self.metadata_panel_visible = True
        self._load_metadata_panel_visibility()

        self.export_btn.setText('Options...')
        try:
            self.export_btn.clicked.disconnect()
        except TypeError:
            pass
        self.export_btn.clicked.connect(self.show_options)
        self.export_btn.setEnabled(True)

        self.refresh_btn.setText('Scan')
        self.stats_label.setText(f'{self.total_label_text}: Not scanned')
        self.set_status('Not scanned. Select Scan to acquire the firmware inventory.')

        self._shortcuts = []
        self._install_shortcuts()

    def style_table_item(self, item, column_id, record):
        if column_id != 'category':
            return
        colors = {
            CATEGORY_PLATFORM: '#9cdcfe',
            CATEGORY_DMI: '#b5cea8',
            CATEGORY_ACPI: '#dcdcaa',
            CATEGORY_EFI: '#c586c0',
            CATEGORY_ESRT: '#ce9178',
            CATEGORY_FWUPD: '#4ec9b0',
            CATEGORY_HISTORY: '#9a9a9a',
            CATEGORY_MICROCODE: '#d7ba7d',
            CATEGORY_DEVICE_TREE: '#c8c8c8',
        }
        color = colors.get(record.get('category'))
        if color:
            item.setForeground(QBrush(QColor(color)))

    def load_modules(self):
        records = []
        errors = []
        records.extend(self._platform_records(errors))
        records.extend(self._dmi_records(errors))
        records.extend(self._acpi_records(errors))
        records.extend(self._efi_variable_records(errors))
        records.extend(self._esrt_records(errors))
        records.extend(self._fwupd_device_records(errors))
        records.extend(self._fwupd_history_records(errors))
        if CATEGORY_MICROCODE in self._lazy_loaded:
            records.extend(self._microcode_records(errors))
        if CATEGORY_DEVICE_TREE in self._lazy_loaded:
            records.extend(self._device_tree_records(errors))
        self.modules_data = records
        self.refresh_btn.setText('Scan Again')
        self.stats_label.setText(f'{self.total_label_text}: {len(self.modules_data)}')
        self.clear_info()
        self.filter_modules()
        if errors:
            self.set_status(f'Scanned firmware inventory: {len(records)} record(s); {len(errors)} source(s) unavailable or returned an error.')
        else:
            self.set_status(f'Scanned firmware inventory: {len(records)} record(s).')

    def _category_changed(self, category):
        category = str(category or '')
        if category in {CATEGORY_MICROCODE, CATEGORY_DEVICE_TREE} and category not in self._lazy_loaded:
            errors = []
            if category == CATEGORY_MICROCODE:
                records = self._microcode_records(errors)
            else:
                records = self._device_tree_records(errors)
            self._lazy_loaded.add(category)
            self.modules_data.extend(records)
            self.stats_label.setText(f'{self.total_label_text}: {len(self.modules_data)}')
            if errors:
                self._lazy_messages[category] = f'{len(errors)} source(s) unavailable or returned an error.'
            else:
                self._lazy_messages[category] = ''
        self.filter_modules()
        if category == CATEGORY_MICROCODE:
            suffix = self._lazy_messages.get(category, '')
            self.set_status('Microcode evidence acquired.' + (f' {suffix}' if suffix else ''))
        elif category == CATEGORY_DEVICE_TREE:
            suffix = self._lazy_messages.get(category, '')
            self.set_status('Device Tree inventory acquired.' + (f' {suffix}' if suffix else ''))

    def _platform_records(self, errors):
        dmi = Path('/sys/class/dmi/id')
        vendor = _read_text(dmi / 'bios_vendor')
        version = _read_text(dmi / 'bios_version')
        date = _read_text(dmi / 'bios_date')
        interface = 'UEFI' if Path('/sys/firmware/efi').is_dir() else 'Legacy / non-EFI'
        secure_boot, setup_mode = self._secure_boot_values()
        firmware_version = _first_observed(version) or 'Not reported'
        details = {
            'Firmware Interface': interface,
            'BIOS / Firmware Vendor': _first_observed(vendor) or 'Not reported',
            'Firmware Version': firmware_version,
            'Firmware Release Date': _first_observed(date) or 'Not reported',
            'EFI Runtime Services': 'Exposed' if Path('/sys/firmware/efi/runtime').exists() else ('Not exposed' if interface == 'UEFI' else 'Not applicable'),
            'Secure Boot': secure_boot,
            'Setup Mode': setup_mode,
            'Source': '/sys/firmware/efi and /sys/class/dmi/id',
        }
        return [{
            'name': 'System Firmware', 'category': CATEGORY_PLATFORM,
            'type': f'{interface} Firmware' if interface == 'UEFI' else 'Platform Firmware',
            'version_value': firmware_version, 'state': 'Present', '_details': details,
        }]

    def _secure_boot_values(self):
        root = Path('/sys/firmware/efi/efivars')
        if not root.is_dir():
            return 'Not available', 'Not available'
        values = {}
        try:
            entries = list(root.iterdir())
        except PermissionError:
            return 'Restricted', 'Restricted'
        except OSError:
            return 'Unavailable', 'Unavailable'
        for entry in entries:
            name, _guid = _efi_filename_parts(entry.name)
            if name not in {'SecureBoot', 'SetupMode'}:
                continue
            state, data = _read_bytes(entry)
            if state == 'observed' and len(data) >= 5:
                values[name] = _decode_efi_scalar(name, data[4:]) or 'Not reported'
            elif state == 'restricted':
                values[name] = 'Restricted'
        return values.get('SecureBoot', 'Not reported'), values.get('SetupMode', 'Not reported')

    def _dmi_records(self, errors):
        root = Path('/sys/class/dmi/id')
        if not root.is_dir():
            return []
        groups = [
            ('BIOS', 'BIOS Information', [('Vendor', 'bios_vendor'), ('Version', 'bios_version'), ('Release Date', 'bios_date'), ('Revision', 'bios_revision')]),
            ('System', 'System Information', [('Manufacturer', 'sys_vendor'), ('Product Name', 'product_name'), ('Product Version', 'product_version'), ('Product UUID', 'product_uuid'), ('Product Serial', 'product_serial')]),
            ('Baseboard', 'Baseboard Information', [('Vendor', 'board_vendor'), ('Name', 'board_name'), ('Version', 'board_version'), ('Serial', 'board_serial')]),
            ('Chassis', 'Chassis Information', [('Vendor', 'chassis_vendor'), ('Type', 'chassis_type'), ('Version', 'chassis_version'), ('Serial', 'chassis_serial')]),
        ]
        output = []
        for name, record_type, fields in groups:
            details = {'Source': '/sys/class/dmi/id'}
            observed = False
            restricted = False
            primary = ''
            for label, filename in fields:
                state, value = _read_text(root / filename)
                if state == 'observed' and value:
                    details[label] = value
                    observed = True
                    if not primary and label in {'Version', 'Product Name', 'Name', 'Type'}:
                        primary = value
                elif state == 'restricted':
                    details[label] = 'Restricted'
                    restricted = True
            if observed or restricted:
                output.append({
                    'name': name, 'category': CATEGORY_DMI, 'type': record_type,
                    'version_value': primary or 'Reported', 'state': 'Restricted' if restricted and not observed else 'Reported',
                    '_details': details,
                })
        return output

    def _acpi_records(self, errors):
        output = []
        for root, kind in ((Path('/sys/firmware/acpi/tables'), 'Static ACPI Table'), (Path('/sys/firmware/acpi/tables/dynamic'), 'Dynamic ACPI Table')):
            if not root.is_dir():
                continue
            try:
                entries = [p for p in root.iterdir() if p.is_file()]
            except PermissionError:
                errors.append(str(root))
                continue
            except OSError as exc:
                errors.append(f'{root}: {exc}')
                continue
            seen = {}
            for path in sorted(entries, key=lambda p: p.name.lower()):
                seen[path.name] = seen.get(path.name, 0) + 1
                display_name = path.name if seen[path.name] == 1 else f'{path.name} ({seen[path.name]})'
                state, header = _acpi_header(path)
                details = {'Source Path': str(path), 'Table Class': kind}
                if state == 'observed':
                    details.update({
                        'Signature': header.get('signature') or path.name,
                        'Length': str(header.get('length', 'Not reported')),
                        'Revision': str(header.get('revision', 'Not reported')),
                        'Checksum': str(header.get('checksum', 'Not reported')),
                        'OEM ID': header.get('oem_id') or 'Not reported',
                        'OEM Table ID': header.get('oem_table_id') or 'Not reported',
                        'OEM Revision': str(header.get('oem_revision', 'Not reported')),
                        'Creator ID': header.get('creator_id') or 'Not reported',
                        'Creator Revision': str(header.get('creator_revision', 'Not reported')),
                    })
                    value = f"Rev {header.get('revision', '?')}"
                    row_state = 'Readable'
                elif state == 'restricted':
                    details['Access'] = 'Restricted'
                    value = 'Restricted'
                    row_state = 'Restricted'
                else:
                    details['Access'] = header.get('error', 'Unavailable') if isinstance(header, dict) else 'Unavailable'
                    value = 'Unavailable'
                    row_state = 'Unavailable'
                output.append({
                    'name': display_name, 'category': CATEGORY_ACPI, 'type': kind,
                    'version_value': value, 'state': row_state, '_details': details,
                })
        return output

    def _efi_variable_records(self, errors):
        root = Path('/sys/firmware/efi/efivars')
        if not root.is_dir():
            return []
        try:
            entries = sorted((p for p in root.iterdir() if p.is_file()), key=lambda p: p.name.lower())
        except PermissionError:
            errors.append(str(root))
            return []
        except OSError as exc:
            errors.append(f'{root}: {exc}')
            return []
        output = []
        for path in entries:
            name, guid = _efi_filename_parts(path.name)
            state, data = _read_bytes(path)
            details = {'Name': name, 'Vendor GUID': guid or 'Not parsed', 'Source Path': str(path)}
            if state == 'observed':
                attrs = int.from_bytes(data[:4], 'little') if len(data) >= 4 else None
                payload = data[4:] if len(data) >= 4 else b''
                details['Attributes'] = f'0x{attrs:08x}' if attrs is not None else 'Not reported'
                details['Data Size'] = f'{len(payload):,} bytes'
                decoded = _decode_efi_scalar(name, payload)
                if decoded:
                    details['Known Interpretation'] = decoded
                    value = decoded
                else:
                    details['Known Interpretation'] = 'No generic interpretation applied'
                    value = f'{len(payload):,} B'
                row_state = 'Readable'
            elif state == 'restricted':
                details['Access'] = 'Restricted'
                value = 'Restricted'; row_state = 'Restricted'
            else:
                details['Access'] = 'Unavailable'
                value = 'Unavailable'; row_state = 'Unavailable'
            output.append({
                'name': name, 'category': CATEGORY_EFI, 'type': 'EFI Variable',
                'version_value': value, 'state': row_state, '_details': details,
            })
        return output

    def _esrt_records(self, errors):
        root = Path('/sys/firmware/efi/esrt/entries')
        if not root.is_dir():
            return []
        try:
            entries = sorted((p for p in root.iterdir() if p.is_dir()), key=lambda p: p.name.lower())
        except PermissionError:
            errors.append(str(root)); return []
        except OSError as exc:
            errors.append(f'{root}: {exc}'); return []
        output = []
        fields = [
            ('Firmware Class GUID', 'fw_class'), ('Firmware Type', 'fw_type'), ('Current Firmware Version', 'fw_version'),
            ('Lowest Supported Version', 'lowest_supported_fw_version'), ('Capsule Flags', 'capsule_flags'),
            ('Last Attempt Version', 'last_attempt_version'), ('Last Attempt Status', 'last_attempt_status'),
        ]
        for entry in entries:
            details = {'Source Path': str(entry)}
            raw = {}
            for label, filename in fields:
                state, value = _read_text(entry / filename)
                if state == 'observed': raw[filename] = value
                elif state == 'restricted': raw[filename] = 'Restricted'
                details[label] = raw.get(filename, 'Not reported')
            details['Firmware Type'] = _fw_type_label(raw.get('fw_type', ''))
            details['Last Attempt Status'] = _esrt_attempt_status(raw.get('last_attempt_status', ''))
            name = raw.get('fw_class') or entry.name
            version = raw.get('fw_version') or 'Not reported'
            output.append({
                'name': name, 'category': CATEGORY_ESRT, 'type': details['Firmware Type'],
                'version_value': version, 'state': details['Last Attempt Status'] if raw.get('last_attempt_status') else 'Reported',
                '_details': details,
            })
        return output

    def _fwupd_device_records(self, errors):
        state, payload, message = _run_json_command(['fwupdmgr', 'get-devices', '--json'])
        if state == 'unavailable':
            return []
        if state != 'observed':
            errors.append(f'fwupdmgr get-devices: {message}')
            return []
        output = []
        for device in _json_items(payload, ('Devices', 'devices')):
            name = _pick(device, 'Name', 'DeviceName', default='Unnamed fwupd device')
            version = _pick(device, 'Version', 'VersionRaw', default='Not reported')
            flags = _pick(device, 'Flags', 'DeviceFlags', default='')
            update_state = _pick(device, 'UpdateState', 'State', default='')
            problems = _pick(device, 'Problems', 'Problem', default='')
            state_text = update_state or ('Problem' if problems else 'Reported')
            details = {
                'Device': name,
                'Vendor': _pick(device, 'Vendor', 'VendorId', default='Not reported'),
                'Current Firmware Version': version,
                'Device ID': _pick(device, 'DeviceId', 'DeviceID', 'Id', default='Not reported'),
                'GUIDs': _pick(device, 'Guid', 'Guids', 'GUIDs', default='Not reported'),
                'Protocols': _pick(device, 'Protocol', 'Protocols', default='Not reported'),
                'Device Flags': flags or 'Not reported',
                'Update State': update_state or 'Not reported',
                'Problems / Inhibitions': problems or _pick(device, 'Inhibits', 'Inhibitions', default='None reported'),
                'Source': 'fwupdmgr get-devices --json',
            }
            output.append({
                'name': name, 'category': CATEGORY_FWUPD, 'type': _pick(device, 'Plugin', 'Protocol', default='fwupd Device'),
                'version_value': version, 'state': state_text, '_details': details,
            })
        return output

    def _fwupd_history_records(self, errors):
        state, payload, message = _run_json_command(['fwupdmgr', 'get-history', '--json'])
        if state == 'unavailable':
            return []
        if state != 'observed':
            # Some systems have fwupd but no history or a version without JSON history support.
            errors.append(f'fwupdmgr get-history: {message}')
            return []
        output = []
        for item in _json_items(payload, ('Devices', 'History', 'Results', 'devices', 'history')):
            name = _pick(item, 'Name', 'DeviceName', default='Firmware Update')
            old_version = _pick(item, 'VersionOld', 'OldVersion', 'PreviousVersion', default='')
            new_version = _pick(item, 'Version', 'VersionNew', 'NewVersion', default='Not reported')
            transition = f'{old_version} → {new_version}' if old_version else new_version
            update_state = _pick(item, 'UpdateState', 'State', default='Reported')
            details = {
                'Device': name,
                'Previous Version': old_version or 'Not reported',
                'Installed Version': new_version,
                'Update State': update_state,
                'Update Error': _pick(item, 'UpdateError', 'Error', default='None reported'),
                'Timestamp': _pick(item, 'Created', 'Modified', 'Timestamp', default='Not reported'),
                'Device ID': _pick(item, 'DeviceId', 'DeviceID', 'Id', default='Not reported'),
                'GUIDs': _pick(item, 'Guid', 'Guids', 'GUIDs', default='Not reported'),
                'Source': 'fwupdmgr get-history --json',
            }
            output.append({
                'name': name, 'category': CATEGORY_HISTORY, 'type': 'Firmware Update',
                'version_value': transition, 'state': update_state, '_details': details,
            })
        return output

    def _microcode_records(self, errors):
        cpuinfo = _parse_cpuinfo()
        cpu_by_id = {}
        for block in cpuinfo:
            processor = str(block.get('processor', '')).strip()
            if processor:
                cpu_by_id[processor] = block

        cpu_root = Path('/sys/devices/system/cpu')
        cpu_ids = set(cpu_by_id)
        if cpu_root.is_dir():
            try:
                for entry in cpu_root.iterdir():
                    if entry.is_dir() and entry.name.startswith('cpu') and entry.name[3:].isdigit():
                        cpu_ids.add(entry.name[3:])
            except OSError as exc:
                errors.append(f'{cpu_root}: {exc}')

        intel_state, intel_files = _microcode_files('/lib/firmware/intel-ucode')
        amd_state, amd_files = _microcode_files('/lib/firmware/amd-ucode')
        firmware = {
            'GenuineIntel': ('/lib/firmware/intel-ucode', intel_state, intel_files),
            'AuthenticAMD': ('/lib/firmware/amd-ucode', amd_state, amd_files),
        }

        groups = {}
        for cpu_id in sorted(cpu_ids, key=lambda value: int(value)):
            info = cpu_by_id.get(cpu_id, {})
            sys_cpu = cpu_root / f'cpu{cpu_id}'
            package_state, package = _read_text(sys_cpu / 'topology' / 'physical_package_id')
            package = package if package_state == 'observed' and package else 'Not reported'
            revision_state, revision = _read_text(sys_cpu / 'microcode' / 'version')
            revision_source = str(sys_cpu / 'microcode' / 'version')
            if revision_state != 'observed' or not revision:
                revision = str(info.get('microcode', '')).strip()
                revision_source = '/proc/cpuinfo' if revision else 'Not reported'
            vendor = str(info.get('vendor_id') or info.get('CPU implementer') or platform.processor() or 'Not reported').strip()
            family = str(info.get('cpu family') or info.get('CPU architecture') or '').strip()
            model = str(info.get('model') or info.get('CPU part') or '').strip()
            model_name = str(info.get('model name') or info.get('Processor') or '').strip()
            key = (package, vendor, revision or 'Not reported')
            group = groups.setdefault(key, {
                'cpus': [], 'package': package, 'vendor': vendor, 'revision': revision or 'Not reported',
                'family': set(), 'model': set(), 'model_name': set(), 'evidence': [],
            })
            group['cpus'].append(cpu_id)
            if family: group['family'].add(family)
            if model: group['model'].add(model)
            if model_name: group['model_name'].add(model_name)
            group['evidence'].append(f'CPU {cpu_id}: revision {revision or "Not reported"}; source {revision_source}')

        if not groups:
            return [{
                'name': 'CPU Microcode', 'category': CATEGORY_MICROCODE, 'type': 'CPU Firmware',
                'version_value': 'Not reported', 'state': 'Unavailable',
                '_details': {
                    'Architecture': platform.machine() or 'Not reported',
                    'Loaded Revision': 'No CPU microcode revision evidence was reported by the implemented local sources.',
                    'Loader Interface': 'Present' if (cpu_root / 'microcode').exists() else 'Not reported',
                    'Runtime Reload Interface': 'Present (informational only)' if (cpu_root / 'microcode' / 'reload').exists() else 'Not reported',
                    'Early-load Evidence': 'Not independently determined from configured read-only sources',
                },
            }]

        output = []
        for (_package, vendor, _revision), group in sorted(groups.items(), key=lambda item: (item[0][0], item[0][1], item[0][2])):
            fw_path, fw_state, fw_files = firmware.get(vendor, ('No vendor-specific directory selected', 'unavailable', []))
            files_text = []
            for item in fw_files:
                size = 'Restricted' if item['size'] is None else f"{item['size']:,} bytes"
                files_text.append(f"{item['path']} | {size} | modified {item['modified']}")
            details = {
                'Architecture': platform.machine() or 'Not reported',
                'CPU Package': group['package'],
                'Logical CPUs': ', '.join(group['cpus']),
                'Vendor': group['vendor'],
                'Family': ', '.join(sorted(group['family'])) or 'Not reported',
                'Model': ', '.join(sorted(group['model'])) or 'Not reported',
                'Model Name': ', '.join(sorted(group['model_name'])) or 'Not reported',
                'Reported Microcode Revision': group['revision'],
                'Per-CPU Evidence': '\n'.join(group['evidence']),
                'Loader Interface': 'Present' if (cpu_root / 'microcode').exists() else 'Not reported',
                'Runtime Reload Interface': 'Present (informational only)' if (cpu_root / 'microcode' / 'reload').exists() else 'Not reported',
                'Early-load Evidence': 'Not independently determined from configured read-only sources',
                'Vendor Firmware Directory': fw_path,
                'Firmware Directory State': fw_state.capitalize(),
                'Firmware Files': str(len(fw_files)),
                'Firmware File Evidence': '\n'.join(files_text) if files_text else 'No local files reported from the vendor-specific firmware directory.',
            }
            name = f"Package {group['package']}" if group['package'] != 'Not reported' else f"CPU {group['cpus'][0]}"
            output.append({
                'name': name, 'category': CATEGORY_MICROCODE, 'type': 'CPU Microcode',
                'version_value': group['revision'],
                'state': 'Reported' if group['revision'] != 'Not reported' else 'Revision not reported',
                '_details': details,
            })
        return output

    def _device_tree_records(self, errors):
        root = Path('/sys/firmware/devicetree/base')
        if not root.is_dir() and Path('/proc/device-tree').is_dir():
            root = Path('/proc/device-tree')
        if not root.is_dir():
            return [{
                'name': 'Device Tree', 'category': CATEGORY_DEVICE_TREE, 'type': 'Firmware Device Tree',
                'version_value': 'Not reported', 'state': 'Unavailable',
                '_details': {
                    'Source': str(root),
                    'Status': 'Device Tree not reported by this system.',
                    'Architecture': platform.machine() or 'Not reported',
                },
            }]

        output = []
        try:
            walker = os.walk(root, topdown=True, followlinks=False)
            for current, dirs, files in walker:
                dirs.sort(key=str.lower)
                files.sort(key=str.lower)
                current_path = Path(current)
                try:
                    relative = current_path.relative_to(root)
                except ValueError:
                    continue
                full_path = '/' if str(relative) == '.' else '/' + relative.as_posix()
                node_name = '/' if full_path == '/' else current_path.name
                parent_path = '/' if full_path == '/' or current_path.parent == root else '/' + current_path.parent.relative_to(root).as_posix()
                common = {}
                for property_name in ('compatible', 'model', 'status', 'device_type', 'phandle', 'linux,phandle'):
                    property_path = current_path / property_name
                    if not property_path.is_file():
                        continue
                    state, value = _dt_common_value(property_path, property_name)
                    if state == 'observed':
                        common[property_name] = value
                compatible = common.get('compatible', '')
                model = common.get('model', '')
                status = common.get('status', '')
                value = compatible or model or status or f'{len(files)} properties'
                details = {
                    'Full Path': full_path,
                    'Node Name': node_name,
                    'Parent Path': parent_path,
                    'Child Count': str(len(dirs)),
                    'Property Count': str(len(files)),
                    'Compatible': compatible or 'Not reported',
                    'Model': model or 'Not reported',
                    'Status': status or 'Not reported',
                    'Device Type': common.get('device_type', 'Not reported'),
                    'Phandle': common.get('phandle') or common.get('linux,phandle') or 'Not reported',
                    'Source Path': str(current_path),
                }
                output.append({
                    'name': full_path, 'category': CATEGORY_DEVICE_TREE, 'type': 'Device Tree Node',
                    'version_value': value, 'state': status or 'Reported', '_details': details,
                    '_dt_node_path': str(current_path),
                })
        except PermissionError:
            errors.append(f'{root}: permission denied')
        except OSError as exc:
            errors.append(f'{root}: {exc}')
        if not output:
            output.append({
                'name': 'Device Tree', 'category': CATEGORY_DEVICE_TREE, 'type': 'Firmware Device Tree',
                'version_value': 'Unavailable', 'state': 'Restricted',
                '_details': {'Source': str(root), 'Status': 'Device Tree exists but its node inventory could not be read.'},
            })
        return output

    def _render_device_tree_properties(self, record):
        node_path = record.get('_dt_node_path')
        if not node_path:
            return
        path = Path(node_path)
        try:
            properties = sorted((item for item in path.iterdir() if item.is_file()), key=lambda item: item.name.lower())
        except PermissionError:
            self.append_info('\n--- Raw Properties ---\n')
            self.append_key_value('Access', 'Restricted')
            return
        except OSError as exc:
            self.append_info('\n--- Raw Properties ---\n')
            self.append_key_value('Access', f'Unavailable: {exc}')
            return
        self.append_info('\n--- Raw Properties ---\n')
        if not properties:
            self.append_info('No properties reported.\n')
            return
        for property_path in properties:
            state, data = _read_bytes(property_path)
            if state == 'observed':
                kind, decoded = _dt_property_display(property_path.name, data, full_hex=self._metadata_export_mode)
                self.append_key_value(property_path.name, f'{decoded} [{kind}; {len(data):,} bytes]')
            elif state == 'restricted':
                self.append_key_value(property_path.name, 'Restricted')
            else:
                self.append_key_value(property_path.name, 'Unavailable')

    def on_module_select(self):
        record = self.current_record()
        if not record:
            return
        self._render_record_details(record)
        self.set_status(f"Inspecting firmware record [{record.get('name', 'record')}].")

    def _render_record_details(self, record):
        self.clear_info()
        self.append_info(f"--- {record.get('category', 'Firmware')} ---\n")
        self.append_key_value('Name', record.get('name', ''))
        self.append_key_value('Type', record.get('type', ''))
        self.append_key_value('Version / Value', record.get('version_value', ''))
        self.append_key_value('State', record.get('state', ''))
        details = record.get('_details') or {}
        if details:
            self.append_info('\n--- Reported Details ---\n')
            for key, value in details.items():
                self.append_key_value(key, value)
        if record.get('category') == CATEGORY_EFI:
            self.append_info('\nEFI variable data is inspected read-only. Firmware Inspector does not write efivarfs or modify boot/Secure Boot state.\n')
        elif record.get('category') in {CATEGORY_FWUPD, CATEGORY_HISTORY}:
            self.append_info('\nfwupd data is queried read-only. Firmware Inspector does not refresh remotes, install, downgrade, activate, or modify firmware.\n')
        elif record.get('category') == CATEGORY_MICROCODE:
            self.append_info('\n--- Interpretation ---\n')
            self.append_info('Loaded revision is reported state. Local firmware-file presence does not prove that a blob was applied or that a newer compatible revision exists. Firmware Inspector produces no “up to date” or vulnerability-mitigation verdict from microcode revision alone. It never writes the runtime microcode reload control.\n')
        elif record.get('category') == CATEGORY_DEVICE_TREE:
            self._render_device_tree_properties(record)
            self.append_info('\nDevice Tree describes firmware-provided platform data. compatible is not treated as proof of active driver binding, and Firmware Inspector never applies overlays or writes DT properties.\n')
        self.info_text.moveCursor(QTextCursor.MoveOperation.Start)
        self.info_text.verticalScrollBar().setValue(0)

    @staticmethod
    def sources_text():
        return (
            'Firmware Inspector is read-only. Its displayed facts come from these interfaces.\n\n'
            'Platform firmware mode and runtime exposure\n'
            '  /sys/firmware/efi\n\n'
            'DMI / SMBIOS platform identity exposed by the kernel\n'
            '  /sys/class/dmi/id\n\n'
            'ACPI table inventory and table headers\n'
            '  /sys/firmware/acpi/tables\n'
            '  /sys/firmware/acpi/tables/dynamic\n\n'
            'EFI variables, including SecureBoot and SetupMode where exposed\n'
            '  /sys/firmware/efi/efivars\n\n'
            'EFI System Resource Table firmware update resources\n'
            '  /sys/firmware/efi/esrt/entries\n\n'
            'Firmware devices and locally recorded update history\n'
            '  fwupdmgr get-devices --json\n'
            '  fwupdmgr get-history --json\n\n'
            'Acquisition\n'
            '  Platform, DMI/SMBIOS, ACPI, EFI, ESRT, fwupd Devices, and Update History are acquired only when Scan is invoked.\n'
            '  Scan Again refreshes those sources and any lazy category already opened in this session.\n'
            '  Microcode and Device Tree remain lazy and are acquired only when selected.\n\n'
            'CPU microcode loaded-revision and loader evidence (lazy)\n'
            '  /sys/devices/system/cpu/cpu*/microcode/version\n'
            '  /proc/cpuinfo\n'
            '  /sys/devices/system/cpu/microcode/reload (presence only; never written)\n'
            '  /lib/firmware/intel-ucode\n'
            '  /lib/firmware/amd-ucode\n\n'
            'Firmware Device Tree (lazy)\n'
            '  /sys/firmware/devicetree/base\n'
            '  /proc/device-tree (fallback where exposed)\n\n'
            'Important boundaries\n'
            '  Firmware Inspector does not flash firmware, modify EFI variables, change Secure Boot, refresh fwupd remotes, or alter firmware settings.\n'
            '  Boot configuration remains the responsibility of Boot Loaders; hardware topology remains the responsibility of Hardware Topology.\n'
            '  Microcode is never reloaded or compared with online vendor data; CPU Vulnerabilities remains the vulnerability/mitigation authority.\n'
            '  Device Tree is never modified and is not treated as a substitute for Hardware Topology.\n'
            '  Unavailable or permission-restricted sources are reported rather than elevated automatically.'
        )

    def show_options(self):
        FirmwareOptionsDialog(self).exec()

    def _add_shortcut(self, sequence, callback):
        shortcut = QShortcut(QKeySequence(sequence), self)
        shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        shortcut.activated.connect(callback)
        self._shortcuts.append(shortcut)
        return shortcut

    def _install_shortcuts(self):
        self._add_shortcut('F3', self.toggle_metadata_panel)
        self._add_shortcut('Ctrl+L', self.toggle_details_orientation)
        self._add_shortcut('Ctrl+/', self.show_options)
        self._add_shortcut('Shift+F5', self.load_modules)
        self._add_shortcut('Ctrl+A', lambda: self._select_category(0))
        for index in range(1, 10):
            self._add_shortcut(f'Ctrl+{index}', lambda i=index: self._select_category(i))

    def _select_category(self, index):
        if 0 <= index < self.category_dropdown.count():
            self.category_dropdown.setCurrentIndex(index)

    def toggle_details_orientation(self):
        target = 'vertical' if self.details_orientation == 'horizontal' else 'horizontal'
        self.set_details_orientation(target, persist=True)

    def _settings(self):
        return QSettings('brunonlinespace', 'Firmware Inspector')

    def _load_metadata_panel_visibility(self):
        value = self._settings().value('metadata_panel_visible', True)
        visible = value.strip().lower() not in {'0', 'false', 'no', 'off'} if isinstance(value, str) else bool(value)
        self.set_metadata_panel_visible(visible, persist=False)

    def set_metadata_panel_visible(self, visible, *, persist=True):
        self.metadata_panel_visible = bool(visible)
        details_panel = self.splitter.widget(1)
        if details_panel is not None:
            details_panel.setVisible(self.metadata_panel_visible)
        if self.metadata_panel_visible:
            self.set_details_orientation(self.details_orientation, persist=False)
        if persist:
            settings = self._settings(); settings.setValue('metadata_panel_visible', self.metadata_panel_visible); settings.sync()

    def toggle_metadata_panel(self):
        self.set_metadata_panel_visible(not self.metadata_panel_visible, persist=True)

    def _load_details_orientation(self):
        orientation = str(self._settings().value('details_orientation', 'horizontal') or 'horizontal').lower()
        if orientation not in {'horizontal', 'vertical'}:
            orientation = 'horizontal'
        self.set_details_orientation(orientation, persist=False)

    def set_details_orientation(self, orientation, *, persist=True):
        orientation = str(orientation or 'horizontal').lower()
        if orientation not in {'horizontal', 'vertical'}:
            orientation = 'horizontal'
        self.details_orientation = orientation
        details_panel = self.splitter.widget(1)
        details_layout = details_panel.layout() if details_panel is not None else None
        if orientation == 'vertical':
            self.splitter.setOrientation(Qt.Orientation.Vertical)
            if details_layout is not None: details_layout.setContentsMargins(0, 8, 0, 0)
            self.splitter.setSizes([430, 330])
        else:
            self.splitter.setOrientation(Qt.Orientation.Horizontal)
            if details_layout is not None: details_layout.setContentsMargins(8, 0, 0, 0)
            self.splitter.setSizes([480, 700])
        if persist:
            settings = self._settings(); settings.setValue('details_orientation', orientation); settings.sync()

    def metadata_details_for_export(self, record):
        original = self.info_text
        previous_export_mode = self._metadata_export_mode
        temp = QTextEdit()
        self.info_text = temp
        self._metadata_export_mode = True
        try:
            self._render_record_details(record)
            return temp.toPlainText()
        finally:
            self._metadata_export_mode = previous_export_mode
            self.info_text = original


def create_applet(parent=None):
    return FirmwareTab(parent=parent)


def run_standalone():
    import sys
    from PyQt6.QtGui import QIcon
    from PyQt6.QtWidgets import QApplication, QMainWindow
    from ._support import STANDALONE_STYLESHEET
    app = QApplication(sys.argv)
    app.setApplicationName(APPLET_NAME)
    app.setOrganizationName(APPLET_AUTHOR)
    icon_path = Path(__file__).resolve().parent / 'icon.png'
    if icon_path.is_file():
        app.setWindowIcon(QIcon(str(icon_path)))
    app.setStyleSheet(STANDALONE_STYLESHEET)
    window = QMainWindow()
    if icon_path.is_file():
        window.setWindowIcon(QIcon(str(icon_path)))
    window.setWindowTitle(f'{APPLET_NAME} {APPLET_VERSION} — LinSpectacles Applet')
    window.resize(1200, 780)
    window.setCentralWidget(create_applet())
    window.show()
    return app.exec()
