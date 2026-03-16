#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# (C) Copyright 2019-2025 Stephane Neveu, Luc Bonnafoux
#
# PDF sanitization script for keysas-analyze.
# Removes dangerous PDF actions and structures using pikepdf.
#
# Usage: pdf_sanitize.py <input.pdf> <output.pdf>
# Exit codes:
#   0 = file modified and saved to output
#   1 = nothing to remove (file already clean)
#   2 = error (parse failure, write error, etc.)
#
# Stdout on exit 0: JSON {"removed": ["/OpenAction", ...]}
# Stderr on exit 2: JSON {"error": "..."}

import pikepdf
import sys
import json

# --------------------------------------------------------------------------- #
# Éléments à supprimer du catalogue racine
ROOT_KEYS_TO_REMOVE = [
    '/OpenAction',   # Action exécutée à l'ouverture
    '/AA',           # Additional Actions (automatiques)
    '/JavaScript',   # Bloc JavaScript global
    '/JS',           # Alias /JavaScript
    '/Names',        # Table des noms (contient souvent JS et EmbeddedFiles)
]

# Éléments à supprimer dans chaque page
PAGE_KEYS_TO_REMOVE = [
    '/AA',           # Additional Actions de page
]

# Types d'actions à neutraliser lors du parcours récursif
DANGEROUS_ACTION_TYPES = {
    '/Launch',
    '/JavaScript',
    '/JS',
    '/URI',
    '/SubmitForm',
    '/ImportData',
    '/GoToR',
    '/GoToE',
    '/RichMedia',
    '/Movie',
    '/Sound',
    '/Rendition',
}
# --------------------------------------------------------------------------- #


def is_dangerous_action(obj: pikepdf.Object) -> bool:
    """Return True if obj is a PDF Action dictionary with a dangerous /S type."""
    try:
        return (
            isinstance(obj, pikepdf.Dictionary)
            and '/S' in obj
            and str(obj['/S']) in DANGEROUS_ACTION_TYPES
        )
    except Exception:
        return False


def neutralize_action(obj: pikepdf.Dictionary, removed: list) -> None:
    """Empty a dangerous Action dictionary in place."""
    action_type = str(obj.get('/S', '?'))
    for key in list(obj.keys()):
        del obj[key]
    removed.append(f"Action{action_type}")


def walk_and_clean(obj: pikepdf.Object, removed: list, visited: set) -> None:
    """
    Recursively walk a PDF object graph.
    Neutralize any Action dictionary whose /S value is in DANGEROUS_ACTION_TYPES.
    """
    obj_id = id(obj)
    if obj_id in visited:
        return
    visited.add(obj_id)

    if isinstance(obj, pikepdf.Dictionary):
        if is_dangerous_action(obj):
            neutralize_action(obj, removed)
            return
        for key in list(obj.keys()):
            try:
                walk_and_clean(obj[key], removed, visited)
            except Exception:
                pass
    elif isinstance(obj, pikepdf.Array):
        for item in obj:
            try:
                walk_and_clean(item, removed, visited)
            except Exception:
                pass


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: pdf_sanitize.py <input.pdf> <output.pdf>", file=sys.stderr)
        sys.exit(2)

    input_path  = sys.argv[1]
    output_path = sys.argv[2]
    removed: list = []

    try:
        with pikepdf.open(input_path) as pdf:

            # 1. Supprimer les clés dangereuses du catalogue racine
            for key in ROOT_KEYS_TO_REMOVE:
                if key in pdf.Root:
                    del pdf.Root[key]
                    removed.append(key)

            # 2. Supprimer les clés dangereuses dans chaque page
            for page in pdf.pages:
                for key in PAGE_KEYS_TO_REMOVE:
                    if key in page:
                        del page[key]
                        label = f"Page{key}"
                        if label not in removed:
                            removed.append(label)

            # 3. Parcourir tous les objets indirects et neutraliser les actions
            visited: set = set()
            for obj in pdf.objects:
                try:
                    walk_and_clean(obj, removed, visited)
                except Exception:
                    pass

            if removed:
                pdf.save(output_path)
                print(json.dumps({"removed": removed}))
                sys.exit(0)
            else:
                sys.exit(1)   # Fichier propre, rien à faire

    except Exception as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
