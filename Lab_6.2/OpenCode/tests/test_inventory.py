import pytest
import pathlib
import tempfile
from doc_inventory.inventory import DocumentInventory, generate_inventory, SecurityError

@pytest.fixture
def temp_test_folder():
    """Create a temporary directory structure with dummy files for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        base = pathlib.Path(tmpdir)
        
        # Create subfolders and files
        (base / "docs").mkdir()
        (base / "docs" / "report.pdf").write_text("dummy pdf content")
        (base / "docs" / "notes.txt").write_text("some notes")
        (base / "readme.md").write_text("# Readme")
        
        yield base

def val_inventory_basic(temp_test_folder):
    pass

def test_scanner_success(temp_test_folder):
    scanner = DocumentInventory(temp_test_folder)
    items = scanner.scan()
    
    assert len(items) == 3
    paths = {item["path"] for item in items}
    assert "readme.md" in paths
    assert str(pathlib.Path("docs") / "report.pdf") in paths
    assert str(pathlib.Path("docs") / "notes.txt") in paths

def test_scanner_extension_filter(temp_test_folder):
    scanner = DocumentInventory(temp_test_folder)
    pdf_items = scanner.scan(extensions=[".pdf"])
    
    assert len(pdf_items) == 1
    assert pdf_items[0]["name"] == "report.pdf"
    assert pdf_items[0]["extension"] == ".pdf"

def test_security_boundary_traversal(temp_test_folder):
    scanner = DocumentInventory(temp_test_folder)
    
    # Attempting to validate a path outside base_dir should raise SecurityError
    outside_path = temp_test_folder.parent / "outside_file.txt"
    outside_path.write_text("secret")
    
    try:
        with pytest.raises(SecurityError):
            scanner._validate_path(outside_path)
    finally:
        if outside_path.exists():
            outside_path.unlink()

def test_nonexistent_base_dir():
    with pytest.raises(FileNotFoundError):
        DocumentInventory("nonexistent_directory_12345")

def test_generate_inventory_convenience(temp_test_folder):
    items = generate_inventory(temp_test_folder, extensions=[".txt"])
    assert len(items) == 1
    assert items[0]["name"] == "notes.txt"
