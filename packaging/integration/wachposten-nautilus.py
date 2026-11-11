# SPDX-License-Identifier: GPL-3.0-or-later
"""Nautilus (GNOME Files) extension: "Check with Wachposten" in the context menu of files and
folders. Needs nautilus-python; installed to /usr/share/nautilus-python/extensions/."""

import locale
import subprocess

from gi.repository import GObject, Nautilus

LABEL = (
    "Mit Wachposten prüfen"
    if (locale.getlocale()[0] or "").startswith("de")
    else "Check with Wachposten"
)


class WachpostenMenu(GObject.GObject, Nautilus.MenuProvider):
    def _scan(self, _item, files):
        paths = [f.get_location().get_path() for f in files]
        paths = [p for p in paths if p]
        if paths:
            subprocess.Popen(["wachposten", "scan-file", "--notify", "--", *paths])

    def get_file_items(self, *args):
        files = args[-1]
        if not files or any(f.get_uri_scheme() != "file" for f in files):
            return []
        item = Nautilus.MenuItem(
            name="Wachposten::scan", label=LABEL, icon="wachposten"
        )
        item.connect("activate", self._scan, files)
        return [item]
