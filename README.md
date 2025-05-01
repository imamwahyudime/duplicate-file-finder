# Duplicate File Finder GUI

[![Release Date](https://img.shields.io/badge/Release-Mei%2001,%202025-brightgreen.svg)](https://github.com/imamwahyudime/duplicate-file-finder/releases/tag/v1.2.0)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A cross-platform graphical (GUI) application built with Python and Tkinter to find duplicate files within a selected directory (and optionally subdirectories). It identifies duplicates based on file content (SHA-256 hash) and provides options for managing them.

![Screenshot Placeholder](https://placehold.co/600x400/EEE/31343C?text=App+Screenshot+Here)
*(Replace the placeholder above with an actual screenshot of the application)*

## Features

* **Cross-Platform:** Works on Windows, macOS, and Linux.
* **GUI Interface:** Easy-to-use graphical interface built with Tkinter.
* **Content-Based Detection:** Finds files with identical content using SHA-256 hashing, regardless of filename.
* **Recursive Scan:** Option to scan subdirectories or only the top-level directory.
* **Efficient Hashing:** Groups files by size first to avoid unnecessary hashing of unique files.
* **Clear Results:** Displays duplicate sets in an expandable tree view, showing filename, file path, size, and date modified.
* **File Management Options:**
    * Permanently delete selected duplicates.
    * Move selected duplicates to the system Trash/Recycle Bin (requires `send2trash` library).
    * Move selected duplicates to a specific folder chosen by the user.
* **Interactive File Actions:**
    * Double-click a file in the results to open it with the default system application.
    * Right-click context menu for quick actions (Open, Copy Path, Move, Rename, Delete, Properties).
    * Tooltips show the full file path on hover.
* **Informative About Dialog:** Includes version, author, and clickable links to GitHub/LinkedIn profiles.

## Prerequisites

* **Python 3:** Ensure you have Python 3 installed (version 3.6 or newer recommended). Tkinter is usually included with standard Python installations.
* **`send2trash` library (Optional but Recommended):** Needed for the "Move to Trash" functionality. Install it using pip:
    ```bash
    pip install send2trash
    ```

## How to Run

1.  **Save:** Save the Python script (e.g., as `gui_find_duplicates.py`).
2.  **Install Prerequisite (Optional):** If you want the "Move to Trash" feature, run `pip install send2trash` in your terminal.
3.  **Run from Terminal:**
    * Navigate to the directory where you saved the script using the `cd` command.
    * Execute the script using Python:
        ```bash
        python gui_find_duplicates.py
        ```
4.  **Use the Application:**
    * Click "Browse..." to select the directory to scan.
    * Check/uncheck "Scan Subfolders" as needed (default is checked).
    * Click "Scan".
    * Review the duplicate sets found in the results list.
    * Select the individual files you want to remove/manage (use Ctrl+Click or Shift+Click for multiple selections).
    * Use the action buttons on the right or the right-click context menu to manage the selected files.
    * Double-click a file to open it.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file (you would need to create this file with the MIT license text) for details.

## Author

* **Imam Wahyudi**
    * GitHub: [https://github.com/imamwahyudime](https://github.com/imamwahyudime)
    * LinkedIn: [https://www.linkedin.com/in/imam-wahyudi/](https://www.linkedin.com/in/imam-wahyudi/)

