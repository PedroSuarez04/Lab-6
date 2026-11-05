#!/usr/bin/env python3
from doc_inventory.inventory import generate_inventory
import json
import pathlib

if __name__ == "__main__":
    test_folder = pathlib.Path("test_documents")
    if test_folder.exists():
        print(f"Scanning inventory for folder: {test_folder.resolve()}")
        inventory = generate_inventory(test_folder)
        print(json.dumps(inventory, indent=2))
    else:
        print(f"Test folder {test_folder} not found.")
