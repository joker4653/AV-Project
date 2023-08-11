import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import yara
import requests
import os
import subprocess

def update_rules():
    update_button.config(state=tk.DISABLED)
    status_label.config(text="Updating...")

    # Repository URL
    repo_url = 'https://github.com/yourusername/yourrepo.git'
    local_path = 'rules'

    # Open a new dialog to show the progress bar
    update_dialog = tk.Toplevel(root)
    update_dialog.title("Updating Rules")
    progress_bar = ttk.Progressbar(update_dialog, orient="horizontal", length=200, mode="indeterminate")
    progress_bar.pack(padx=10, pady=10)
    progress_bar.start()

    # Clone or pull the repository
    if os.path.exists(local_path):
        subprocess.run(["git", "pull"], cwd=local_path)
    else:
        subprocess.run(["git", "clone", repo_url, local_path])

    # Compile the YARA rules
    rule_files = [os.path.join(local_path, f) for f in os.listdir(local_path) if f.endswith('.yara')]
    global yara_rules
    yara_rules = yara.compile(filepaths=rule_files)

    # Close the progress bar dialog
    update_dialog.destroy()
    update_button.config(state=tk.NORMAL)
    status_label.config(text="Idle")
    messagebox.showinfo("Update Complete", "YARA rules updated successfully.")

def scan_files():
    file_paths = filedialog.askopenfilenames(title="Select files to scan")
    scan_button.config(state=tk.DISABLED)
    status_label.config(text="Scanning...")
    root.update()

    infected_files = []
    for file_path in file_paths:
        matches = yara_rules.match(file_path)
        if matches:
            infected_files.append(file_path)

    if infected_files:
        result = "Threats found in the following files:\n" + "\n".join(infected_files)
    else:
        result = "No threats found."

    messagebox.showinfo("Scan Complete", result)
    scan_button.config(state=tk.NORMAL)
    status_label.config(text="Idle")

root = tk.Tk()
root.title("Antivirus")

main_frame = tk.Frame(root, padx=10, pady=10)
main_frame.pack(padx=5, pady=5)

scan_button = tk.Button(main_frame, text="Scan Files", command=scan_files, width=15)
scan_button.grid(row=0, column=0, padx=5, pady=5)

update_button = tk.Button(main_frame, text="Update YARA Rules", command=update_rules, width=20)
update_button.grid(row=0, column=1, padx=5, pady=5)

status_label = tk.Label(main_frame, text="Idle")
status_label.grid(row=1, column=0, columnspan=2, pady=5)

# Initial update of rules
update_rules()

root.mainloop()
