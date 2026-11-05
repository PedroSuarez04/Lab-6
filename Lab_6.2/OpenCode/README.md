# Document Inventory Application

A simple, safe Python application and unit-testing suite that inventories documents within a strictly bounded test folder.

## Features
- **Safe Directory Traversal**: Ensures all operations and file paths remain strictly inside the user-specified test folder, preventing path traversal attacks.
- **Inventory Generation**: Scans supported document formats (e.g. `.pdf`, `.txt`, `.docx`, etc.), recording metadata such as file name, relative path, file size, extension, and last modified timestamp.
- **Unit Testing**: Comprehensive test suite powered by `pytest`.

## Getting Started & Commands

1. **Create the virtual environment**:
   ```bash
   python3 -m venv venv
   ```

2. **Activate the virtual environment**:
   ```bash
   source venv/bin/activate
   ```

3. **Install dependencies and development tools**:
   ```bash
   pip install --upgrade pip
   pip install -e .[dev]
   ```

4. **Run unit tests**:
   ```bash
   pytest
   ```

5. **Run the inventory tool programmatically or via CLI**:
   ```python
   from doc_inventory.inventory import generate_inventory
   inventory = generate_inventory("test_documents")
   print(inventory)
   ```
