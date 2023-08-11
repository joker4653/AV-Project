import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import yara
import requests
import os
import subprocess


directory = 'rules'
repo_url = 'https://github.com/Yara-Rules/rules.git'
yara_rules = None

def update_rules():
    update_button.config(state=tk.DISABLED)
    status_label.config(text="Updating...")


    # Open a new dialog to show the progress bar
    update_dialog = tk.Toplevel(root)
    update_dialog.title("Updating Rules")
    progress_bar = ttk.Progressbar(update_dialog, orient="horizontal", length=200, mode="indeterminate")
    progress_bar.pack(padx=10, pady=10)
    progress_bar.start()


    rule_files_dict = {}
    for root_dir, _, files in os.walk(directory):
        for file_name in files:
            if file_name.endswith('.yara'):
                file_path = os.path.join(root_dir, file_name)
                rule_files_dict[file_name] = file_path
    yara_rules = yara.compile(filepaths=rule_files_dict)


    # Close the progress bar dialog
    update_dialog.destroy()
    update_button.config(state=tk.NORMAL)
    status_label.config(text="Idle")
    messagebox.showinfo("Update Complete", "YARA rules updated successfully.")
    
    return yara_rules

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


def on_update_rules():
    try:
        

        # Clone or pull the repository
        if os.path.exists(directory) and len(os.listdir(directory)) != 0:
            subprocess.run(["git", "pull"], cwd=directory)
        else:
            subprocess.run(["git", "clone", repo_url, directory])

        yara_rules = update_rules()
        messagebox.showinfo('Update Complete', 'YARA rules updated successfully.')
    except Exception as e:
        messagebox.showerror('Update Failed', f'An error occurred: {str(e)}')



root = tk.Tk()
root.title("Antivirus")

main_frame = tk.Frame(root, padx=10, pady=10)
main_frame.pack(padx=5, pady=5)

scan_button = tk.Button(main_frame, text="Scan Files", command=scan_files, width=15)
scan_button.grid(row=0, column=0, padx=5, pady=5)

update_button = tk.Button(main_frame, text="Update YARA Rules", command=on_update_rules, width=20)
update_button.grid(row=0, column=1, padx=5, pady=5)

status_label = tk.Label(main_frame, text="Idle")
status_label.grid(row=1, column=0, columnspan=2, pady=5)



if __name__ == "__main__":
    on_update_rules()

    root.mainloop()
