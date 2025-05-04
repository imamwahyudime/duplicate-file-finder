import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import os
import hashlib
import sys      # Needed for platform checks (sys.platform)
import collections
import shutil
import threading
import queue
import time
import datetime
import subprocess # Needed for opening files cross-platform
import webbrowser # For opening links in About dialog

# Attempt to import send2trash for Recycle Bin/Trash functionality
try:
    import send2trash
    SEND2TRASH_AVAILABLE = True
except ImportError:
    SEND2TRASH_AVAILABLE = False
    print("Warning: 'send2trash' library not found. 'Move to Trash' feature will be disabled.")
    print("Install it using: pip install send2trash")


# --- Configuration ---
APP_VERSION = "1.3.0" # Incremented version for stop button feature
# *** Change 1: Define fixed release date ***
APP_RELEASE_DATE = "2025-05-01 (Thursday)"
CHUNK_SIZE = 65536      # Read files in 64KB chunks for hashing
TOOLTIP_DELAY = 600     # Milliseconds before tooltip appears


# --- Core Logic ---
def calculate_hash(filepath, stop_event, progress_queue=None, file_index=0, total_files=1):
    """Calculates the SHA-256 hash of a file, reporting progress and checking for stop signal."""
    hasher = hashlib.sha256()
    try:
        with open(filepath, 'rb') as file:
            while True:
                # *** Change 2: Check stop event during file read ***
                if stop_event.is_set():
                    return "STOPPED" # Signal that hashing was interrupted

                chunk = file.read(CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except (IOError, OSError) as e:
        if progress_queue:
            # Report errors non-fatally during hashing
            progress_queue.put({"type": "status", "message": f"Warn: Cannot hash {os.path.basename(filepath)}: {e}"}) # Changed to status warn # noqa E701
        return None

# *** Change 3: Add stop_event parameter ***
def find_duplicate_files_thread(directory_to_scan, scan_subfolders, progress_queue, stop_event):
    """
    Finds duplicate files based on size and then hash.
    Runs in a separate thread and reports progress via a queue.
    Checks for a stop event periodically.
    """
    try:
        # --- Initial Checks ---
        if stop_event.is_set(): return # Check before starting
        if not os.path.isdir(directory_to_scan):
            progress_queue.put({"type": "error", "message": f"Directory not found: {directory_to_scan}"})
            progress_queue.put({"type": "finished"})
            return

        # --- Step 0: Gather file list ---
        progress_queue.put({"type": "status", "message": "Step 1/3: Scanning files..."})
        progress_queue.put({"type": "progress", "value": 0})
        all_files_to_scan = []
        status_msg_prefix = "Gathering file list"
        if scan_subfolders:
            progress_queue.put({"type":"status", "message": f"{status_msg_prefix} (including subfolders)..."})
            # Use scandir for potentially better performance, handle errors gracefully
            # Wrap directory iteration in try...except for top-level access errors
            try:
                for entry in os.scandir(directory_to_scan):
                    # *** Change 4: Check stop event in outer loop ***
                    if stop_event.is_set(): return

                    try:
                        if entry.is_dir():
                            # Walk through subdirectories
                            for root, _, filenames in os.walk(entry.path, topdown=True): # Use topdown=True
                                # *** Change 5: Check stop event in inner loop (walk) ***
                                if stop_event.is_set(): return
                                for filename in filenames:
                                    if stop_event.is_set(): return # Check frequently
                                    filepath = os.path.join(root, filename)
                                    try:
                                        # Check if it's a regular file and not a symlink
                                        if os.path.isfile(filepath) and not os.path.islink(filepath):
                                            all_files_to_scan.append(filepath)
                                    except OSError as e_inner:
                                        progress_queue.put({"type": "status", "message": f"Warn: Cannot access {filepath}: {e_inner}"}) # noqa E701
                        elif entry.is_file() and not entry.is_symlink():
                            all_files_to_scan.append(entry.path)
                    except OSError as e_outer:
                        progress_queue.put({"type": "status", "message": f"Warn: Cannot access {entry.path}: {e_outer}"}) # noqa E701
            except OSError as e_scan: # Catch errors scanning the top directory
                progress_queue.put({"type": "error", "message": f"Error scanning directory {directory_to_scan}: {e_scan}"})
                progress_queue.put({"type": "finished"})
                return
        else: # Scan top-level only
            progress_queue.put({"type":"status", "message": f"{status_msg_prefix} (top-level only)..."})
            try:
                for entry in os.scandir(directory_to_scan):
                    # *** Change 6: Check stop event in non-recursive loop ***
                    if stop_event.is_set(): return
                    try:
                        # Check if it's a regular file and not a symlink in the top level
                        if entry.is_file() and not entry.is_symlink():
                            all_files_to_scan.append(entry.path)
                    except OSError as e_inner:
                        progress_queue.put({"type": "status", "message": f"Warn: Cannot access {entry.path}: {e_inner}"}) # noqa E701
            except OSError as e_outer:
                progress_queue.put({"type": "error", "message": f"Error listing directory {directory_to_scan}: {e_outer}"}) # noqa E701
                progress_queue.put({"type": "finished"})
                return

        total_files_found = len(all_files_to_scan)
        if total_files_found == 0 and not stop_event.is_set(): # Only report 'no files' if not stopped
            progress_queue.put({"type": "status", "message": "No files found to scan."})
            progress_queue.put({"type": "result", "data": {}}) # Send empty result
            progress_queue.put({"type": "finished"})
            return

        # --- Step 1: Group by size ---
        if stop_event.is_set(): return # Check before next step
        progress_queue.put({"type": "status", "message": f"Found {total_files_found} files. Step 2/3: Grouping by size..."}) # noqa E701
        files_by_size = collections.defaultdict(list)
        total_files_processed_size = 0
        update_interval_size = max(1, total_files_found // 100 if total_files_found > 100 else 10)
        for i, filepath in enumerate(all_files_to_scan):
            # *** Change 7: Check stop event during size grouping ***
            if stop_event.is_set(): return
            try:
                filesize = os.path.getsize(filepath)
                if filesize > 0: # Only consider files with size > 0
                    files_by_size[filesize].append(filepath)
            except OSError as e:
                progress_queue.put({"type": "status", "message": f"Warn: Cannot get size for {os.path.basename(filepath)}: {e}"}) # noqa E701
            total_files_processed_size += 1
            if total_files_processed_size % update_interval_size == 0:
                progress = (total_files_processed_size / total_files_found) * 33.3 # Progress within Step 1 (0-33.3%)
                progress_queue.put({"type": "progress", "value": progress})

        # --- Step 2: Calculate Hashes for potential duplicates ---
        if stop_event.is_set(): return # Check before hashing
        progress_queue.put({"type": "progress", "value": 33.3}) # Mark end of size grouping
        progress_queue.put({"type": "status", "message": "Step 3/3: Calculating hashes..."})
        files_by_hash = collections.defaultdict(list)
        potential_duplicates_paths = [
            fp for size, fps in files_by_size.items() if len(fps) > 1 for fp in fps
        ]
        total_to_hash = len(potential_duplicates_paths)
        hashed_count = 0
        update_interval_hash = max(1, total_to_hash // 100 if total_to_hash > 100 else 10)

        if total_to_hash == 0 and not stop_event.is_set():
            progress_queue.put({"type": "status", "message": "No potential duplicates found based on size."})
        elif not stop_event.is_set():
             progress_queue.put({"type": "status", "message": f"Hashing {total_to_hash} potential duplicate files..."}) # noqa E701

        for i, filepath in enumerate(potential_duplicates_paths):
            # *** Change 8: Check stop event before hashing each file ***
            if stop_event.is_set(): return
            # *** Change 9: Pass stop_event to calculate_hash ***
            file_hash = calculate_hash(filepath, stop_event, progress_queue, i, total_to_hash)

            # *** Change 10: Handle "STOPPED" signal from calculate_hash ***
            if file_hash == "STOPPED":
                return # Stop requested during hashing of this file

            if file_hash:
                files_by_hash[file_hash].append(filepath)

            hashed_count += 1
            if total_to_hash > 0 and hashed_count % update_interval_hash == 0:
                progress = 33.3 + (hashed_count / total_to_hash) * 66.6 # Progress within Step 2 (33.3-100%)
                progress_queue.put({"type": "progress", "value": progress})

        # --- Step 3: Identify actual duplicate sets ---
        if stop_event.is_set(): return # Check before final step
        progress_queue.put({"type": "progress", "value": 99.9}) # Almost done
        progress_queue.put({"type": "status", "message": "Identifying duplicate sets..."})
        duplicates_found = collections.defaultdict(list)
        for file_hash, filepaths in files_by_hash.items():
            if len(filepaths) > 1:
                duplicates_found[file_hash] = sorted(filepaths)

        # --- Final Report ---
        progress_queue.put({"type": "progress", "value": 100})
        progress_queue.put({"type": "result", "data": dict(duplicates_found)})
        num_sets = len(duplicates_found)
        num_files = sum(len(fps) for fps in duplicates_found.values())
        if num_sets > 0:
            final_message = f"Scan complete. Found {num_sets} duplicate set(s) involving {num_files} files."
        else:
            final_message = "Scan complete. No duplicates found."
        progress_queue.put({"type": "status", "message": final_message})

    except Exception as e:
        # Catch unexpected errors during the scan process
        # Check if stop was requested *before* the exception occurred
        if not stop_event.is_set():
            progress_queue.put({"type": "error", "message": f"An unexpected error occurred during scan: {e}"}) # noqa E701
            import traceback
            traceback.print_exc(file=sys.stderr) # Log the full traceback for debugging
        # Else, if stop was requested, the stop message takes precedence

    finally:
        # *** Change 11: Check if stopped and send appropriate message if necessary ***
        if stop_event.is_set():
             # Make sure a stop message is sent if the thread exits due to the flag
             progress_queue.put({"type": "status", "message": "Scan stopped by user."})

        # Always signal completion, regardless of how the thread exits
        progress_queue.put({"type": "finished"})


# --- GUI Application Class ---
class DuplicateFinderApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"Duplicate File Finder v{APP_VERSION}")
        self.root.geometry("950x650") # Width adjusted for file path column

        # Configure styles for ttk widgets
        self.style = ttk.Style()
        try:
            # Use native theme if available (e.g., 'vista' on Windows, 'aqua' on macOS)
            if sys.platform == "win32": self.style.theme_use('vista')
            elif sys.platform == "darwin": self.style.theme_use('aqua')
            else: self.style.theme_use('clam') # 'clam' is a decent cross-platform default
        except tk.TclError:
            self.style.theme_use('default') # Fallback

        # --- Application State Variables ---
        self.scan_directory = tk.StringVar()
        self.scan_subfolders_var = tk.BooleanVar(value=True)
        self.duplicates_data = {} # Stores the found duplicate sets {hash: [path1, path2,...]}
        self.tree_item_to_path = {} # Maps treeview item IDs to full file paths
        self.scan_thread = None      # Holds the background scanning thread
        self.progress_queue = queue.Queue() # Queue for thread communication
        # *** Change 12: Add threading event for stopping scan ***
        self.stop_scan_event = threading.Event()

        # Tooltip related variables
        self.tooltip_window = None
        self.tooltip_label = None
        self.tooltip_after_id = None
        self.last_hovered_item = None

        # --- Menu Bar ---
        self.menubar = tk.Menu(self.root)
        self.help_menu = tk.Menu(self.menubar, tearoff=0)
        self.help_menu.add_command(label="About", command=self.show_about_dialog)
        self.menubar.add_cascade(label="Help", menu=self.help_menu)
        self.root.config(menu=self.menubar)

        # --- Top Frame (Directory Selection & Scan Button) ---
        self.top_frame = ttk.Frame(root, padding="10")
        self.top_frame.pack(fill=tk.X, side=tk.TOP)
        self.top_frame.columnconfigure(1, weight=1) # Allow entry field to expand

        ttk.Label(self.top_frame, text="Directory:").grid(row=0, column=0, padx=(0, 5), sticky="w")
        self.dir_entry = ttk.Entry(self.top_frame, textvariable=self.scan_directory, width=60)
        self.dir_entry.grid(row=0, column=1, sticky="ew")
        self.browse_button = ttk.Button(self.top_frame, text="Browse...", command=self.browse_directory)
        self.browse_button.grid(row=0, column=2, padx=(5, 5))
        self.scan_button = ttk.Button(self.top_frame, text="Scan", command=self.start_scan)
        self.scan_button.grid(row=0, column=3, padx=(0, 5))
        self.subfolder_check = ttk.Checkbutton(self.top_frame, text="Scan Subfolders", variable=self.scan_subfolders_var) # noqa E701
        self.subfolder_check.grid(row=0, column=4, padx=(10, 0))

        # --- Middle Frame (Status Label, Progress Bar & Stop Button) ---
        self.middle_frame = ttk.Frame(root, padding=(10, 5, 10, 10))
        self.middle_frame.pack(fill=tk.X, side=tk.TOP)
        self.middle_frame.columnconfigure(0, weight=1) # Status label expands

        self.status_label = ttk.Label(self.middle_frame, text="Ready.", anchor="w")
        self.status_label.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        self.progress_bar = ttk.Progressbar(self.middle_frame, orient="horizontal", length=200, mode="determinate") # noqa E701
        self.progress_bar.grid(row=0, column=1, padx=(5,5))
        # *** Change 13: Add Stop Button ***
        self.stop_button = ttk.Button(self.middle_frame, text="Stop", command=self.request_stop_scan, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=2, padx=(5,0))


        # --- Bottom Frame (Results Treeview & Action Buttons) ---
        self.bottom_frame = ttk.Frame(root, padding=(10, 0, 10, 10))
        self.bottom_frame.pack(fill=tk.BOTH, expand=True, side=tk.TOP)
        self.bottom_frame.columnconfigure(0, weight=1) # Treeview area expands
        self.bottom_frame.rowconfigure(0, weight=1)     # Treeview area expands

        # Treeview Frame (contains tree and scrollbars)
        self.tree_frame = ttk.Frame(self.bottom_frame)
        self.tree_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        self.tree_frame.columnconfigure(0, weight=1) # Tree expands horizontally
        self.tree_frame.rowconfigure(0, weight=1)    # Tree expands vertically

        # Configure Treeview Widget
        self.tree = ttk.Treeview(
            self.tree_frame,
            columns=("filepath", "size", "modified"), # Define column identifiers
            show="tree headings", # Show tree column (#0) and headings
            selectmode="extended" # Allow selecting multiple items
        )

        # Define Headings (visible text)
        self.tree.heading("#0", text="Duplicate Sets / Files") # Special tree column
        self.tree.heading("filepath", text="File Path")
        self.tree.heading("size", text="Size")
        self.tree.heading("modified", text="Date Modified")

        # Configure Column Properties
        self.tree.column("#0", width=250, stretch=tk.YES, anchor='w') # Anchor text left
        self.tree.column("filepath", width=400, stretch=tk.YES, anchor='w') # Give path more space
        self.tree.column("size", width=100, stretch=tk.NO, anchor='e') # Anchor text right (numbers)
        self.tree.column("modified", width=150, stretch=tk.NO, anchor='w') # Date/time on left

        # Scrollbars
        self.vsb = ttk.Scrollbar(self.tree_frame, orient="vertical", command=self.tree.yview)
        self.hsb = ttk.Scrollbar(self.tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=self.vsb.set, xscrollcommand=self.hsb.set)

        # Place Treeview and Scrollbars in grid
        self.tree.grid(row=0, column=0, sticky='nsew')
        self.vsb.grid(row=0, column=1, sticky='ns') # Vertical scrollbar
        self.hsb.grid(row=1, column=0, sticky='ew') # Horizontal scrollbar

        # Bind Events to Treeview
        self.tree.bind('<Enter>', self.schedule_tooltip) # Mouse enters treeview area
        self.tree.bind('<Leave>', self.hide_tooltip)     # Mouse leaves treeview area
        self.tree.bind('<Motion>', self.schedule_tooltip) # Mouse moves within treeview
        self.tree.bind('<Double-Button-1>', self.open_file_for_event) # Double left-click
        self.tree.bind('<Button-3>', self.show_context_menu) # Right-click

        # --- Action Buttons Frame (Right side) ---
        self.action_frame = ttk.Frame(self.bottom_frame)
        self.action_frame.grid(row=0, column=1, sticky="ns") # Stick to top and bottom

        self.delete_button = ttk.Button(self.action_frame, text="Delete Selected Permanently", command=self.delete_selected, state=tk.DISABLED) # noqa E701
        self.delete_button.pack(pady=5, fill=tk.X) # Pad vertically, fill horizontally

        self.trash_button = ttk.Button(self.action_frame, text="Move Selected to Trash", command=self.trash_selected, state=tk.DISABLED) # noqa E701
        self.trash_button.pack(pady=5, fill=tk.X)
        if not SEND2TRASH_AVAILABLE:
            # Indicate if send2trash is missing
            ttk.Label(self.action_frame, text="('send2trash' not found)", font=("Arial", 8)).pack(pady=(0,5)) # noqa E701
            self.trash_button.state(['disabled']) # Ensure it's disabled

        self.move_button = ttk.Button(self.action_frame, text="Move Selected to Folder...", command=self.move_selected, state=tk.DISABLED) # noqa E701
        self.move_button.pack(pady=5, fill=tk.X)

        ttk.Separator(self.action_frame, orient='horizontal').pack(pady=10, fill=tk.X)

        # Informational label about selection
        ttk.Label(self.action_frame, text="Select individual files\n(not sets) to remove.", wraplength=150, justify=tk.CENTER).pack(pady=10) # noqa E701

        # Start checking the progress queue periodically
        self.check_queue()
    # --- End of __init__ ---

    def browse_directory(self):
        """Opens a dialog to select the directory to scan."""
        dir_path = filedialog.askdirectory(title="Select Directory to Scan", parent=self.root)
        if dir_path:
            self.scan_directory.set(dir_path)
            self.clear_results() # Clear previous results when a new dir is selected
            self.status_label.config(text=f"Selected directory: {dir_path}")

    def clear_results(self):
        """Clears the Treeview and resets related data."""
        # Delete all items from the tree
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.duplicates_data = {}   # Clear found duplicates data
        self.tree_item_to_path = {} # Clear item ID to path mapping
        self.progress_bar['value'] = 0 # Reset progress bar
        # Disable action buttons as there's nothing selected/found
        self.delete_button.config(state='disabled')
        self.trash_button.config(state='disabled') # Always disable initially
        if SEND2TRASH_AVAILABLE and self.duplicates_data: # Re-enable later if needed
             pass # Will be enabled after scan if results are found
        self.move_button.config(state='disabled')
        self.hide_tooltip() # Hide any lingering tooltip

    def set_ui_state(self, state):
        """Enables or disables UI elements during scanning."""
        tk_state = tk.DISABLED if state == 'disabled' else tk.NORMAL
        scan_running = (state == 'disabled')

        # Disable/enable input elements
        self.dir_entry.config(state=tk_state)
        self.browse_button.config(state=tk_state)
        self.scan_button.config(state=tk_state)
        self.subfolder_check.config(state=tk_state)

        # *** Change 14: Manage Stop Button state ***
        self.stop_button.config(state=tk.NORMAL if scan_running else tk.DISABLED)

        # Always disable action buttons when scan starts
        if scan_running:
            self.delete_button.config(state='disabled')
            self.trash_button.config(state='disabled')
            self.move_button.config(state='disabled')
        # Note: Action buttons are re-enabled based on results in check_queue's "finished" handler

    # *** Change 15: Add method to request stop ***
    def request_stop_scan(self):
        """Signals the background thread to stop scanning."""
        if self.scan_thread and self.scan_thread.is_alive():
            self.stop_scan_event.set() # Set the event flag
            self.stop_button.config(state=tk.DISABLED) # Disable stop button immediately
            self.status_label.config(text="Stopping scan...") # Provide feedback

    def start_scan(self):
        """Starts the duplicate file scan in a background thread."""
        dir_path = self.scan_directory.get()
        if not dir_path or not os.path.isdir(dir_path):
            messagebox.showerror("Error", "Please select a valid directory first.", parent=self.root)
            return
        # Prevent starting multiple scans concurrently
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showwarning("Scan in Progress", "A scan is already running. Please wait or stop the current scan.", parent=self.root) # noqa E701
            return

        self.clear_results()
        # *** Change 16: Clear stop event before starting ***
        self.stop_scan_event.clear()
        self.set_ui_state('disabled') # Disable UI during scan, enable Stop button
        self.status_label.config(text="Starting scan...")
        self.progress_bar['value'] = 0
        self.root.update_idletasks() # Ensure UI updates before thread starts

        scan_subs = self.scan_subfolders_var.get()
        # Create and start the background thread
        self.scan_thread = threading.Thread(
            target=find_duplicate_files_thread,
            # *** Change 17: Pass stop_event to the thread target ***
            args=(dir_path, scan_subs, self.progress_queue, self.stop_scan_event),
            daemon=True # Allows the app to exit even if the thread is running
        )
        self.scan_thread.start()

    def check_queue(self):
        """Periodically checks the queue for messages from the scan thread."""
        try:
            while True: # Process all available messages in the queue
                message = self.progress_queue.get_nowait()
                msg_type = message.get("type")

                if msg_type == "status":
                    # Avoid overwriting "Stopping..." message if user clicked Stop
                    if not (self.stop_scan_event.is_set() and self.status_label.cget("text") == "Stopping scan..."):
                         self.status_label.config(text=message.get("message", "..."))
                elif msg_type == "progress":
                    self.progress_bar['value'] = message.get("value", 0)
                elif msg_type == "error":
                    error_msg = message.get('message', 'Unknown error during scan')
                    self.status_label.config(text=f"Error: {error_msg}")
                    messagebox.showerror("Scan Error", error_msg, parent=self.root)
                    # Error might occur *after* stop was requested, ensure UI resets
                    if not self.stop_scan_event.is_set():
                        self.set_ui_state('normal') # Ensure UI is re-enabled on error
                    self.stop_button.config(state=tk.DISABLED) # Always disable stop on error
                elif msg_type == "result":
                    # Only update results if scan wasn't stopped prematurely
                    if not self.stop_scan_event.is_set():
                        self.duplicates_data = message.get("data", {})
                        self.populate_treeview() # Display the results
                elif msg_type == "finished":
                    self.set_ui_state('normal') # Re-enable UI controls, disable Stop button
                    # Enable action buttons only if duplicates were found AND scan wasn't stopped
                    action_state = tk.DISABLED
                    if not self.stop_scan_event.is_set() and self.duplicates_data:
                         action_state = tk.NORMAL

                    self.delete_button.config(state=action_state)
                    trash_state = action_state if SEND2TRASH_AVAILABLE else tk.DISABLED
                    self.trash_button.config(state=trash_state)
                    self.move_button.config(state=action_state)

                    # Update status if not already showing an error or stop message
                    current_status = self.status_label.cget("text")
                    is_error = current_status.startswith("Error:")
                    is_stopping = current_status == "Stopping scan..."
                    is_stopped = current_status == "Scan stopped by user."

                    if not is_error and not is_stopping and not is_stopped:
                        if not self.stop_scan_event.is_set(): # Only show completion message if not stopped
                             num_sets = len(self.duplicates_data)
                             if num_sets > 0:
                                 num_files = sum(len(fps) for fps in self.duplicates_data.values())
                                 final_msg = f"Scan complete. Found {num_sets} duplicate set(s) involving {num_files} files." # noqa E701
                             else:
                                 final_msg = "Scan complete. No duplicates found."
                             self.status_label.config(text=final_msg)
                             # Briefly show 100% progress then reset after a delay
                             self.progress_bar['value'] = 100
                             self.root.after(2500, lambda: self.progress_bar.config(value=0) if not self.scan_thread or not self.scan_thread.is_alive() else None) # noqa E701
                        # If it *was* stopped, the "Scan stopped..." message is already set by the thread or queue checker
                    elif is_stopped:
                        self.progress_bar['value'] = 0 # Reset progress bar on stop

        except queue.Empty:
            pass # No messages currently in the queue
        except Exception as e:
            # Catch errors in the queue processing itself
            print(f"Error processing queue message: {e}", file=sys.stderr)
            self.status_label.config(text="Error displaying results.")
            self.set_ui_state('normal') # Ensure UI is usable after display error
            self.stop_button.config(state=tk.DISABLED)
        finally:
            # Schedule the next check
            self.root.after(100, self.check_queue) # Check again in 100ms

    def populate_treeview(self):
        """Populates the Treeview with the found duplicate sets."""
        # Clear existing items before populating
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.tree_item_to_path = {}

        # Configure alternating row colors (optional styling)
        self.tree.tag_configure('oddrow', background='#F0F0F0')
        self.tree.tag_configure('evenrow', background='#FFFFFF')

        set_count = 0
        for file_hash, filepaths in self.duplicates_data.items():
            set_count += 1
            tag = 'oddrow' if set_count % 2 == 1 else 'evenrow' # Apply alternating tag

            # Insert the "Set" heading row (parent item)
            set_id = self.tree.insert(
                "", tk.END, # Insert at the top level, at the end
                text=f"Set {set_count} ({len(filepaths)} files, Hash: {file_hash[:8]}...)",
                open=True, # Start with sets expanded
                tags=(tag,)
            )
            # Insert the individual file rows under the set heading
            for filepath in filepaths:
                try:
                    # Get file metadata
                    stat_info = os.stat(filepath)
                    filesize = stat_info.st_size
                    filesize_str = f"{filesize:,}" # Format size with commas
                    mod_time = datetime.datetime.fromtimestamp(stat_info.st_mtime)
                    # Format date/time concisely
                    mod_time_str = mod_time.strftime("%Y-%m-%d %H:%M")
                except OSError:
                    # Handle cases where file might become inaccessible after scan
                    filesize_str = "N/A"
                    mod_time_str = "N/A"
                filename = os.path.basename(filepath)

                # Insert the file item under its set (set_id)
                item_id = self.tree.insert(
                    set_id, tk.END, # Insert under parent 'set_id', at the end
                    text=f"  {filename}", # Indent filename slightly
                    # Values correspond to the columns defined: ("filepath", "size", "modified")
                    values=(filepath, filesize_str, mod_time_str),
                    tags=(tag,)
                )
                # Store mapping from the unique tree item ID to its full path
                self.tree_item_to_path[item_id] = filepath

        # Update status if tree is now empty (e.g., after action cleared all)
        if not self.tree.get_children():
            # Check if scan was stopped - if so, status is already set
            current_status = self.status_label.cget("text")
            if "stopped" not in current_status.lower() and "stopping" not in current_status.lower():
                 self.status_label.config(text="No duplicates found or list cleared.")


    def get_selected_file_paths(self, show_warning=True):
        """Gets the paths of the selected file items in the Treeview."""
        selected_items = self.tree.selection() # Get IDs of selected items
        file_paths = []
        if not selected_items:
            if show_warning:
                messagebox.showinfo("No Selection", "Please select one or more files.", parent=self.root)
            return None

        valid_selection = True
        for item_id in selected_items:
            # Check if the selected item is a file (has a parent which is a set header)
            if not self.tree.parent(item_id):
                if show_warning:
                    set_text = self.tree.item(item_id, 'text') # Get text of the invalid item
                    messagebox.showwarning("Invalid Selection", f"Select individual files, not set headings (e.g., '{set_text}').", parent=self.root) # noqa E701
                valid_selection = False
                break # Stop processing if an invalid item is selected
            else:
                # Get the path using the stored mapping
                path = self.tree_item_to_path.get(item_id)
                if path:
                    file_paths.append((item_id, path)) # Store (item_id, path) tuple
                else:
                    # This shouldn't happen if mapping is correct, but log if it does
                    print(f"Warning: No path found for selected item ID {item_id}", file=sys.stderr)

        if not valid_selection:
            return None # Invalid selection encountered
        if not file_paths and selected_items:
            # If items were selected but no paths were retrieved (e.g., mapping error)
             if show_warning:
                 messagebox.showinfo("No Files Selected", "Selected items are not valid file entries.", parent=self.root) # noqa E701
             return None
        return file_paths


    def update_treeview_after_action(self, processed_item_ids):
        """Removes processed items from Treeview and checks if sets need removal."""
        parents_to_check = set() # Keep track of sets that might become empty
        for item_id in processed_item_ids:
            if item_id in self.tree_item_to_path:
                parent_id = self.tree.parent(item_id)
                if parent_id:
                    parents_to_check.add(parent_id)
                # Remove the item from the tree if it exists
                if self.tree.exists(item_id):
                    self.tree.delete(item_id)
                # Remove from the path mapping
                del self.tree_item_to_path[item_id]

        # Check sets that had items removed
        for parent_id in parents_to_check:
            if self.tree.exists(parent_id):
                children = self.tree.get_children(parent_id)
                # If a set has 1 or 0 files left, it's no longer a duplicate set
                if len(children) <= 1:
                    # Remove remaining children (if any) and their path mapping
                    for child_id in children:
                        if self.tree.exists(child_id):
                            self.tree.delete(child_id)
                        self.tree_item_to_path.pop(child_id, None)
                    # Remove the now empty/invalid set header itself
                    self.tree.delete(parent_id)

        # After potential removals, check if the tree is completely empty
        if not self.tree.get_children():
            self.delete_button.config(state='disabled')
            trash_state = 'disabled' # Always disable if empty
            self.trash_button.config(state=trash_state)
            self.move_button.config(state='disabled')
            # Check if scan was stopped before overwriting status
            current_status = self.status_label.cget("text")
            if "stopped" not in current_status.lower() and "stopping" not in current_status.lower():
                 self.status_label.config(text="List cleared or no duplicates remain.")


    # --- Action Methods (Delete, Trash, Move) ---

    def delete_selected(self):
        """Permanently deletes selected files."""
        selected_files = self.get_selected_file_paths() # Get (item_id, path) tuples
        if not selected_files: return # No valid selection

        num_files = len(selected_files)
        # Show a strong warning for permanent deletion
        if not messagebox.askyesno(
            "Confirm Permanent Deletion",
            f"PERMANENTLY DELETE {num_files} selected file(s)?\nThis cannot be undone.",
            icon='warning', parent=self.root
        ):
            return

        processed_ids, errors = [], []
        self.status_label.config(text=f"Deleting {num_files} file(s)...")
        self.root.update_idletasks() # Update status immediately

        for item_id, path in selected_files:
            try:
                # Normalize path before checking existence and deleting
                normalized_path = os.path.normpath(os.path.abspath(path))
                if os.path.exists(normalized_path):
                    os.remove(normalized_path)
                    processed_ids.append(item_id) # Mark for removal from treeview
                else:
                    # File already gone, report as warning/error but still remove from list
                    errors.append(f"Not found (already deleted?): {os.path.basename(path)}") # noqa E701
                    processed_ids.append(item_id)
            except Exception as e:
                # Catch permission errors, etc.
                errors.append(f"Error deleting {os.path.basename(path)}: {e}")
                # Do not add to processed_ids if deletion failed, leave it in the list

        self.update_treeview_after_action(processed_ids) # Update GUI

        # Report results
        if errors:
            messagebox.showerror("Deletion Errors", "Some errors occurred:\n\n" + "\n".join(errors), parent=self.root) # noqa E701
            self.status_label.config(text=f"Deletion finished with {len(errors)} error(s).")
        else:
            self.status_label.config(text=f"Deletion complete. {len(processed_ids)} file(s) removed.")


    def trash_selected(self):
        """Moves selected files to the system trash/recycle bin."""
        if not SEND2TRASH_AVAILABLE:
            messagebox.showerror("Error", "'send2trash' library is not installed.\nCannot move files to trash.", parent=self.root) # noqa E701
            return
        selected_files = self.get_selected_file_paths()
        if not selected_files: return

        num_files = len(selected_files)
        # Optional: Add confirmation dialog for trashing
        # if not messagebox.askyesno("Confirm Trash", f"Move {num_files} selected file(s) to the Trash/Recycle Bin?", parent=self.root): # noqa E701
        #     return

        processed_ids, errors = [], []
        self.status_label.config(text=f"Moving {num_files} file(s) to trash...")
        self.root.update_idletasks()

        for item_id, path in selected_files:
            try:
                # Normalize path for robustness, especially on Windows
                normalized_path = os.path.normpath(os.path.abspath(path))
                if os.path.exists(normalized_path):
                    send2trash.send2trash(normalized_path) # Use the library function
                    processed_ids.append(item_id)
                else:
                    errors.append(f"Not found (already moved/deleted?): {os.path.basename(path)}") # noqa E701
                    processed_ids.append(item_id) # Still remove from list if not found
            except Exception as e:
                # Catch potential errors from send2trash (permissions, etc.)
                errors.append(f"Error moving {os.path.basename(path)} to trash: {e}")
                # Do not mark as processed if trashing failed

        self.update_treeview_after_action(processed_ids)

        # Report results
        if errors:
            messagebox.showerror("Trash Errors", "Some errors occurred moving files to trash:\n\n" + "\n".join(errors), parent=self.root) # noqa E701
            self.status_label.config(text=f"Trash operation finished with {len(errors)} error(s).") # noqa E701
        else:
            self.status_label.config(text=f"Trash complete. {len(processed_ids)} file(s) moved.")


    def move_selected(self):
        """Moves selected files to a chosen folder."""
        selected_files = self.get_selected_file_paths()
        if not selected_files: return

        num_files = len(selected_files)
        # Ask user for destination folder
        dest_folder = filedialog.askdirectory(title=f"Move {num_files} file(s) to folder:", parent=self.root) # noqa E701
        if not dest_folder: return # User cancelled

        processed_ids, errors = [], []
        self.status_label.config(text=f"Moving {num_files} file(s)...")
        self.root.update_idletasks()

        for item_id, path in selected_files:
            try:
                # Normalize source path
                normalized_path = os.path.normpath(os.path.abspath(path))
                if not os.path.exists(normalized_path):
                    errors.append(f"Not found (already moved?): {os.path.basename(path)}") # noqa E701
                    processed_ids.append(item_id)
                    continue # Skip to next file

                base_name = os.path.basename(normalized_path)
                dest_path_base = os.path.normpath(os.path.join(dest_folder, base_name))
                dest_path = dest_path_base
                counter = 1
                # Handle potential filename conflicts in the destination
                while os.path.exists(dest_path):
                    # Check if source and destination are identical (avoid error)
                    try:
                        # Use try-except for samefile in case one vanishes
                        if os.path.samefile(normalized_path, dest_path):
                            errors.append(f"Cannot move '{base_name}': source and destination are the same.") # noqa E701
                            break # Exit inner loop for this file
                    except FileNotFoundError:
                         errors.append(f"Cannot compare '{base_name}': source or destination file missing during check.")
                         break # Exit inner loop

                    # Append counter to filename if conflict exists
                    name, ext = os.path.splitext(base_name)
                    dest_path = os.path.normpath(os.path.join(dest_folder, f"{name}_{counter}{ext}")) # noqa E701
                    counter += 1
                else:
                     # No conflict or conflict resolved, attempt move
                     try:
                         shutil.move(normalized_path, dest_path)
                         processed_ids.append(item_id)
                     except Exception as e_move:
                         errors.append(f"Error moving {base_name}: {e_move}")
                     continue # Move to next file in the outer loop

                # This continue is reached if the samefile check broke the inner while loop
                continue

            except Exception as e_outer:
                 # Catch errors before move (e.g., path normalization)
                 errors.append(f"Error preparing move for {os.path.basename(path)}: {e_outer}") # noqa E701

        self.update_treeview_after_action(processed_ids)

        # Report results
        if errors:
            messagebox.showerror("Move Errors", "Some errors occurred moving files:\n\n" + "\n".join(errors), parent=self.root) # noqa E701
            self.status_label.config(text=f"Move finished with {len(errors)} error(s).")
        else:
            self.status_label.config(text=f"Move complete. {len(processed_ids)} file(s) moved to {os.path.basename(dest_folder)}.") # noqa E701


    # --- Event Handlers ---

    def open_file_for_event(self, event):
        """Handler for double-click event to open the selected file."""
        self.hide_tooltip() # Hide tooltip if visible
        item_id = self.tree.identify_row(event.y) if event else self.tree.focus() # Get item from event or focus # noqa E701
        if not item_id: return

        # Ensure the double-clicked item is a file item (has a parent)
        if self.tree.parent(item_id):
            path = self.tree_item_to_path.get(item_id)
            if path:
                try:
                    # Normalize path for robustness
                    normalized_path = os.path.normpath(os.path.abspath(path))

                    if not os.path.exists(normalized_path):
                        messagebox.showwarning("Open Error", f"File no longer exists at:\n{normalized_path}", parent=self.root) # noqa E701
                        # Optionally, remove the item from the tree if it doesn't exist
                        self.update_treeview_after_action([item_id])
                        return

                    # Platform-specific open command
                    if sys.platform == "win32":
                        os.startfile(normalized_path) # Easiest on Windows
                    elif sys.platform == "darwin": # macOS
                        subprocess.run(['open', normalized_path], check=True)
                    else: # Linux and other Unix-like (requires xdg-utils)
                        subprocess.run(['xdg-open', normalized_path], check=True)

                except FileNotFoundError:
                    # Handles os.startfile error if file vanished between check and open,
                    # or xdg-open/open command not found
                    messagebox.showerror("Open Error", f"Could not open file.\nFile not found or required system utility (like xdg-open or associated application) is missing:\n{normalized_path}", parent=self.root) # noqa E701
                except subprocess.CalledProcessError as e:
                    # Handles errors from 'open' or 'xdg-open' if they fail
                    messagebox.showerror("Open Error", f"Failed to open file using system command:\n{normalized_path}\n\nError: {e}", parent=self.root) # noqa E701
                except Exception as e:
                    # Catch any other unexpected errors
                    messagebox.showerror("Open Error", f"An unexpected error occurred trying to open:\n{normalized_path}\n\nError: {e}", parent=self.root) # noqa E701
            else:
                 # Path not found in mapping (shouldn't normally happen)
                 messagebox.showwarning("Open Error", "Could not determine the file path for the selected item.", parent=self.root) # noqa E701
        # else: Do nothing if a set header or empty space is double-clicked


    def show_context_menu(self, event):
        """Shows a context menu on right-click."""
        self.hide_tooltip() # Hide any active tooltip
        # Identify the item under the cursor
        item_id = self.tree.identify_row(event.y)
        current_selection = self.tree.selection()

        # If the clicked item is not already selected, select only that item
        if item_id and item_id not in current_selection:
            self.tree.selection_set(item_id)
            current_selection = self.tree.selection() # Update selection reference

        # Get paths only for selected *file* items
        selected_files = []
        for sel_id in current_selection:
            # Check if it's a file item (has a parent)
            if self.tree.parent(sel_id):
                path = self.tree_item_to_path.get(sel_id)
                if path:
                    selected_files.append((sel_id, path))

        num_selected = len(selected_files)
        if num_selected == 0: return # No valid files selected, do nothing

        # Create the context menu
        context_menu = tk.Menu(self.root, tearoff=0)

        if num_selected == 1:
            # --- Menu for single file selection ---
            item_id, path = selected_files[0]
            # Use lambda to capture current item_id and path for commands
            context_menu.add_command(label="Open File", command=lambda i=item_id: self.open_file_for_event(None)) # Pass None event # noqa E701
            context_menu.add_separator()
            context_menu.add_command(label="Copy Path", command=self.copy_selected_paths)
            context_menu.add_command(label="Move...", command=self.move_selected)
            context_menu.add_command(label="Rename...", command=lambda i=item_id, p=path: self.rename_selected_file(i, p)) # noqa E701
            context_menu.add_separator()
            # Trash option depends on send2trash availability
            trash_state = tk.NORMAL if SEND2TRASH_AVAILABLE else tk.DISABLED
            context_menu.add_command(label="Move to Trash", command=self.trash_selected, state=trash_state) # noqa E701
            context_menu.add_command(label="Delete Permanently", command=self.delete_selected)
            context_menu.add_separator()
            context_menu.add_command(label="Properties", command=lambda i=item_id, p=path: self.show_properties(i, p)) # noqa E701

        elif num_selected > 1:
            # --- Menu for multiple file selection ---
            context_menu.add_command(label=f"Copy {num_selected} Paths", command=self.copy_selected_paths) # noqa E701
            context_menu.add_command(label=f"Move {num_selected} Files...", command=self.move_selected) # noqa E701
            context_menu.add_separator()
            trash_state = tk.NORMAL if SEND2TRASH_AVAILABLE else tk.DISABLED
            context_menu.add_command(label=f"Move {num_selected} to Trash", command=self.trash_selected, state=trash_state) # noqa E701
            context_menu.add_command(label=f"Delete {num_selected} Permanently", command=self.delete_selected) # noqa E701
            # 'Open File', 'Rename', 'Properties' don't make sense for multiple files

        # Display the menu at the cursor position
        try:
            context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            # Release the grab to ensure proper menu closing behavior
            context_menu.grab_release()


    # --- Helper & Utility Methods ---

    def copy_selected_paths(self):
        """Copies the full paths of selected files to the clipboard."""
        # Get paths without showing warning if none selected (handled by context menu logic)
        selected_files = self.get_selected_file_paths(show_warning=False)
        if not selected_files: return

        paths = [path for _, path in selected_files] # Extract paths from tuples
        clipboard_text = "\n".join(paths) # Join paths with newline for easy pasting

        try:
            self.root.clipboard_clear() # Clear previous clipboard content
            self.root.clipboard_append(clipboard_text) # Append new content
            self.status_label.config(text=f"Copied {len(paths)} path(s) to clipboard.")
        except tk.TclError:
            messagebox.showwarning("Clipboard Error", "Could not access the system clipboard.", parent=self.root) # noqa E701
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred copying paths: {e}", parent=self.root) # noqa E701

    def rename_selected_file(self, item_id, old_path):
        """Renames a selected file using a dialog."""
        # Ensure the file still exists before attempting rename
        if not os.path.exists(old_path):
            messagebox.showerror("Rename Error", f"File no longer exists:\n{old_path}", parent=self.root) # noqa E701
            self.update_treeview_after_action([item_id]) # Remove missing item
            return

        old_dirname = os.path.dirname(old_path)
        old_filename = os.path.basename(old_path)

        # Ask user for new filename
        new_filename = simpledialog.askstring(
            "Rename File",
            f"Enter new name for:\n{old_filename}",
            initialvalue=old_filename, # Pre-fill with current name
            parent=self.root
        )

        # If user cancels or enters the same name, do nothing
        if not new_filename or new_filename == old_filename:
            return

        new_path = os.path.join(old_dirname, new_filename)

        # Check if a file with the new name already exists
        if os.path.exists(new_path):
            messagebox.showerror("Rename Error", f"A file with the name '{new_filename}' already exists in this location.", parent=self.root) # noqa E701
            return

        try:
            # Perform the rename operation
            os.rename(old_path, new_path)
            # Update the Treeview display
            self.tree.item(item_id, text=f"  {new_filename}") # Update display text
            # Update the path mapping
            self.tree_item_to_path[item_id] = new_path
            # Update the values in the other columns (specifically the path column)
            current_values = list(self.tree.item(item_id, 'values'))
            if current_values:
                 current_values[0] = new_path # Update filepath column (index 0)
                 self.tree.item(item_id, values=tuple(current_values))
            self.status_label.config(text=f"Renamed '{old_filename}' to '{new_filename}'")
        except OSError as e:
            messagebox.showerror("Rename Error", f"Could not rename file:\n{e}", parent=self.root) # noqa E701
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred during rename: {e}", parent=self.root) # noqa E701


    def show_properties(self, item_id, path):
        """Displays file properties in a message box."""
        self.hide_tooltip() # Hide tooltip first
        # Double-check path retrieval if needed (should be passed by context menu)
        if not path: path = self.tree_item_to_path.get(item_id)
        if not path:
            messagebox.showwarning("Properties", "Could not determine file path.", parent=self.root) # noqa E701
            return

        if os.path.exists(path):
            try:
                stat_info = os.stat(path)
                size = stat_info.st_size
                # Use datetime for clearer time formatting
                modified_time = datetime.datetime.fromtimestamp(stat_info.st_mtime)
                created_time = datetime.datetime.fromtimestamp(stat_info.st_ctime)
                accessed_time = datetime.datetime.fromtimestamp(stat_info.st_atime)
                # Format times consistently
                time_format = "%Y-%m-%d %H:%M:%S"
                modified_str = modified_time.strftime(time_format)
                created_str = created_time.strftime(time_format)
                accessed_str = accessed_time.strftime(time_format)

                # Construct details string
                details = (
                    f"Full Path: {path}\n\n"
                    f"Size: {size:,} bytes\n"
                    f"Date Modified: {modified_str}\n"
                    f"Date Created: {created_str}\n"
                    f"Date Accessed: {accessed_str}"
                )
                messagebox.showinfo(f"Properties: {os.path.basename(path)}", details, parent=self.root) # noqa E701
            except OSError as e:
                messagebox.showerror("Error", f"Could not get properties for:\n{path}\n\nError: {e}", parent=self.root) # noqa E701
            except Exception as e:
                 messagebox.showerror("Error", f"Unexpected error getting properties:\n{e}", parent=self.root) # noqa E701
        else:
             messagebox.showwarning("Properties", f"File no longer exists:\n{path}", parent=self.root) # noqa E701


    # --- Tooltip Methods ---

    def _create_tooltip_window(self):
        """Creates the tooltip Toplevel window if it doesn't exist."""
        # Ensure only one tooltip window exists
        if not self.tooltip_window or not self.tooltip_window.winfo_exists():
            self.tooltip_window = tk.Toplevel(self.root)
            # Make it borderless and hide from taskbar
            self.tooltip_window.overrideredirect(True)
            self.tooltip_window.withdraw() # Start hidden
            self.tooltip_label = tk.Label(
                self.tooltip_window,
                text="",
                justify='left',
                background="#ffffe0", # Pale yellow background
                relief='solid',
                borderwidth=1,
                wraplength=500 # Wrap long paths
            )
            self.tooltip_label.pack(ipadx=5, ipady=3) # Internal padding

    def schedule_tooltip(self, event):
        """Schedules the tooltip to appear after a delay."""
        self._create_tooltip_window() # Ensure window exists
        # Cancel any pending tooltip display
        if self.tooltip_after_id:
            self.root.after_cancel(self.tooltip_after_id)
            self.tooltip_after_id = None

        # Identify item under cursor
        item_id = self.tree.identify_row(event.y)
        # Hide tooltip immediately if mouse moved to a different item or empty space
        if item_id != self.last_hovered_item:
            self.hide_tooltip()
        self.last_hovered_item = item_id
        if not item_id: return # Mouse is over empty space

        # Check if the cursor is over the first (#0) or second ('filepath') column
        column = self.tree.identify_column(event.x)
        # Show tooltip only for file items (which have a parent)
        if self.tree.parent(item_id):
            path = self.tree_item_to_path.get(item_id)
            # Trigger tooltip if path exists and hovering relevant columns
            if path and column in ('#0', '#1'): # #0 is Tree, #1 is filepath
                 # Schedule _show_tooltip to run after TOOLTIP_DELAY ms
                 self.tooltip_after_id = self.root.after(
                      TOOLTIP_DELAY,
                      self._show_tooltip, event.x_root, event.y_root, path # Pass coords and path # noqa E701
                 )
        else:
            # Don't show tooltip for set headers
            self.hide_tooltip()

    def _show_tooltip(self, x, y, text):
        """Displays the tooltip window with the given text at specified coordinates."""
        if not self.tooltip_window or not self.tooltip_window.winfo_exists():
            self._create_tooltip_window() # Recreate if necessary

        # Update text and position
        self.tooltip_label.config(text=text)
        # Position slightly offset from cursor
        x_pos = x + 15
        y_pos = y + 10
        self.tooltip_window.geometry(f"+{x_pos}+{y_pos}")
        self.tooltip_window.deiconify() # Show the window

    def hide_tooltip(self, event=None):
        """Hides the tooltip window and cancels pending display."""
        # Cancel any scheduled appearance
        if self.tooltip_after_id:
            self.root.after_cancel(self.tooltip_after_id)
            self.tooltip_after_id = None
        # Hide the window if it exists
        if self.tooltip_window and self.tooltip_window.winfo_exists():
            self.tooltip_window.withdraw()
        self.last_hovered_item = None # Reset last hovered item


    # --- About Dialog (with Clickable Links) ---
    def show_about_dialog(self):
        """Displays the About dialog box with clickable links."""
        # Create a top-level window for the dialog
        about_window = tk.Toplevel(self.root)
        about_window.title("About Duplicate Finder")
        about_window.grab_set() # Make it modal (grab focus)
        about_window.transient(self.root) # Associate with main window

        # Basic centering logic
        self.root.update_idletasks()
        main_x, main_y = self.root.winfo_x(), self.root.winfo_y()
        main_w, main_h = self.root.winfo_width(), self.root.winfo_height()
        about_window.update_idletasks()
        # Estimate size needed (can be refined)
        dlg_w = about_window.winfo_reqwidth() + 100
        dlg_h = about_window.winfo_reqheight() + 100 # More vertical space
        center_x = main_x + (main_w // 2) - (dlg_w // 2)
        center_y = main_y + (main_h // 2) - (dlg_h // 2)
        about_window.geometry(f"{dlg_w}x{dlg_h}+{center_x}+{center_y}")
        about_window.resizable(False, False)

        # Use a Text widget for rich text features
        text_widget = tk.Text(
            about_window, wrap="word", height=10, width=50,
            borderwidth=0, relief="flat",
            background=self.root.cget('background') # Match main window bg
        )
        text_widget.pack(pady=15, padx=20, expand=True, fill="both")

        # Define tags for formatting
        text_widget.tag_configure("header", font=("Arial", 12, "bold"), justify='center')
        text_widget.tag_configure("link", foreground="blue", underline=True)
        text_widget.tag_configure("center", justify='center')
        text_widget.tag_configure("normal", font=("Arial", 10))

        # Content
        # *** Change 18: Use fixed release date constant ***
        #today_date = datetime.date.today().strftime("%Y-%m-%d") # Get current date
        app_name = "Duplicate File Finder"
        version_info = f"Version: {APP_VERSION}"
        #release_info = f"Release Date: {today_date}"
        release_info = f"Release Date: {APP_RELEASE_DATE}" # Use the constant
        author_info = "Author: Imam Wahyudi"
        github_url = "https://github.com/imamwahyudime"
        linkedin_url = "https://www.linkedin.com/in/imam-wahyudi/"

        # Insert content using tags
        text_widget.insert(tk.END, f"{app_name}\n\n", ("header", "center"))
        text_widget.insert(tk.END, f"{version_info}\n", ("normal", "center"))
        text_widget.insert(tk.END, f"{release_info}\n\n", ("normal", "center"))
        text_widget.insert(tk.END, f"{author_info}\n", ("normal", "center"))

        # Insert links - embed URL in tag name for easy retrieval
        text_widget.insert(tk.END, "\n", ("normal", "center")) # Separator
        text_widget.insert(tk.END, "Links: ", ("normal", "center"))
        text_widget.insert(tk.END, "\n", ("normal", "center")) # Separator
        github_tag = f"link_{github_url}"
        linkedin_tag = f"link_{linkedin_url}"
        text_widget.insert(tk.END, "\n", ("normal", "center")) # Separator
        text_widget.insert(tk.END, "github.com/imamwahyudime", ("link", github_tag))
        text_widget.tag_configure(github_tag, foreground="blue", underline=True)
        text_widget.insert(tk.END, "\n", ("normal", "center")) # Separator
        text_widget.insert(tk.END, "\n", ("normal", "center")) # Separator
        text_widget.insert(tk.END, "linkedin.com/in/imam-wahyudi", ("link", linkedin_tag))
        text_widget.tag_configure(linkedin_tag, foreground="blue", underline=True)
        text_widget.insert(tk.END, "\n", ("normal", "center"))

        # Make text widget read-only
        text_widget.config(state=tk.DISABLED)

        # --- Link Click Handling ---
        def _handle_link_click(event):
            # Get all tags at the clicked position
            tags = text_widget.tag_names(f"@{event.x},{event.y}")
            for tag in tags:
                if tag.startswith("link_"):
                    url = tag[len("link_"):] # Extract URL from tag name
                    try:
                        webbrowser.open_new_tab(url)
                    except Exception as e:
                        messagebox.showerror("Error", f"Could not open link:\n{url}\n\n{e}", parent=about_window) # noqa E701
                    return # Handled

        # Bind events to the general 'link' tag for hover effect
        text_widget.tag_bind("link", "<Enter>", lambda e: text_widget.config(cursor="hand2"))
        text_widget.tag_bind("link", "<Leave>", lambda e: text_widget.config(cursor=""))
        # Bind click to the specific link tags via the general tag handler
        text_widget.tag_bind("link", "<Button-1>", _handle_link_click)

        # Add an OK button
        ok_button = ttk.Button(about_window, text="OK", command=about_window.destroy)
        ok_button.pack(pady=(5, 15)) # Padding below text and above bottom

        about_window.wait_window() # Wait for dialog to close


# --- Main Execution ---
if __name__ == "__main__":
    root = tk.Tk()
    app = DuplicateFinderApp(root)
    root.mainloop()
