import os
import sys
import argparse
import unittest
import tempfile
from pathlib import Path

def find_pdfs(directory_path):
    """
    Lists PDF files within the explicit directory path provided.
    Operates only within the supplied directory (non-recursive).
    Does not read, upload, delete, or modify file contents.
    """
    target_dir = Path(directory_path)
    if not target_dir.is_dir():
        raise NotADirectoryError(f"{directory_path} is not a valid directory.")
    
    pdf_files = []
    # Iterate only over the immediate contents of the directory
    for item in target_dir.iterdir():
        if item.is_file() and item.suffix.lower() == '.pdf':
            pdf_files.append(item.name)
            
    return pdf_files

def main():
    parser = argparse.ArgumentParser(description="List PDF files in a specified directory.")
    parser.add_argument("directory", type=str, help="Path to the directory to search.")
    args = parser.parse_args()
    
    try:
        pdfs = find_pdfs(args.directory)
        for pdf in pdfs:
            print(pdf)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

class TestFindPdfs(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.test_path = Path(self.test_dir.name)
        
        # Create some dummy files
        (self.test_path / "document1.pdf").touch()
        (self.test_path / "document2.PDF").touch()
        (self.test_path / "text.txt").touch()
        
        # Create a subdirectory to test non-recursiveness
        sub_dir = self.test_path / "subdir"
        sub_dir.mkdir()
        (sub_dir / "document3.pdf").touch()

    def tearDown(self):
        self.test_dir.cleanup()

    def test_find_pdfs(self):
        pdfs = find_pdfs(self.test_path)
        # Should find document1.pdf and document2.PDF, but not document3.pdf or text.txt
        expected = {"document1.pdf", "document2.PDF"}
        self.assertEqual(set(pdfs), expected)

    def test_invalid_directory(self):
        with self.assertRaises(NotADirectoryError):
            find_pdfs(self.test_path / "nonexistent_dir_xyz")

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'test':
        sys.argv.pop(1)
        unittest.main()
    else:
        main()
