import tkinter as tk
from tkinter import ttk, messagebox
from encryption import generate_key
from vault import save_vault, load_vault
from utils import generate_password
from auth import is_first_run, save_master_password, verify_master_password
import pyperclip
import threading
import time


class PasswordManagerApp:
    def __init__(self, root, master_password):
        self.root = root
        self.root.title("🔐 Secure Password Manager")
        self.root.geometry("800x520")
        self.root.configure(bg="#f0f2f5")

        self.master_password = master_password
        self.key = generate_key(self.master_password)

        try:
            self.vault_data = load_vault(self.key)
        except Exception as e:
            messagebox.showerror("Error", f"Incorrect password or corrupt vault.\n\nDetails:\n{e}")
            root.destroy()
            return

        self.entries = self.vault_data.splitlines() if self.vault_data else []

        self.build_ui()
        self.load_entries_to_table()

    def build_ui(self):
        container = tk.Frame(self.root)
        canvas = tk.Canvas(container, height=370)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        self.scrollable_frame = tk.Frame(canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        container.pack(fill="both", expand=True, padx=10, pady=10)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Buttons frame
        btn_frame = tk.Frame(self.root, bg="#f0f2f5")
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="➕ Add Entry", command=self.add_entry).grid(row=0, column=0, padx=10)
        ttk.Button(btn_frame, text="💾 Save Vault", command=self.save_entries).grid(row=0, column=1, padx=10)
        ttk.Button(btn_frame, text="🔁 Refresh", command=self.refresh_table).grid(row=0, column=2, padx=10)

    def load_entries_to_table(self):
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()

        for idx, entry in enumerate(self.entries):
            parts = entry.split(" | ")
            if len(parts) == 3:
                service, username, password = parts

                row = tk.Frame(self.scrollable_frame)
                row.pack(fill="x", pady=2, padx=5)

                tk.Label(row, text=service, width=20, anchor="w").pack(side="left", padx=5)
                tk.Label(row, text=username, width=20, anchor="w").pack(side="left", padx=5)

                pwd_var = tk.StringVar(value="*" * len(password))
                pwd_label = tk.Label(row, textvariable=pwd_var, width=20, anchor="w")
                pwd_label.pack(side="left", padx=5)

                toggle_text = tk.StringVar(value="Show")

                def make_toggle(var, real_pwd, toggle_var):
                    def toggle():
                        if var.get().startswith("*"):
                            var.set(real_pwd)
                            toggle_var.set("Hide")
                        else:
                            var.set("*" * len(real_pwd))
                            toggle_var.set("Show")
                    return toggle

                toggle_btn = tk.Button(row, textvariable=toggle_text,
                                       command=make_toggle(pwd_var, password, toggle_text),
                                       width=6)
                toggle_btn.pack(side="left", padx=5)

                copy_btn = tk.Button(row, text="Copy", command=lambda pwd=password: self.copy_to_clipboard(pwd), width=6)
                copy_btn.pack(side="left", padx=5)

                def edit_entry(index=idx):
                    self.open_edit_window(index)

                edit_btn = tk.Button(row, text="Edit", command=edit_entry, width=6)
                edit_btn.pack(side="left", padx=5)

                def delete_entry(index=idx):
                    if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this entry?"):
                        self.entries.pop(index)
                        self.refresh_table()

                delete_btn = tk.Button(row, text="Delete", command=delete_entry, width=6)
                delete_btn.pack(side="left", padx=5)

    def open_edit_window(self, index):
        entry = self.entries[index]
        service, username, password = entry.split(" | ")

        top = tk.Toplevel(self.root)
        top.title("Edit Password Entry")
        top.geometry("350x270")

        tk.Label(top, text="Service:").pack(pady=5)
        service_entry = tk.Entry(top, width=30)
        service_entry.insert(0, service)
        service_entry.pack()

        tk.Label(top, text="Username:").pack(pady=5)
        user_entry = tk.Entry(top, width=30)
        user_entry.insert(0, username)
        user_entry.pack()

        tk.Label(top, text="Password:").pack(pady=5)
        pwd_entry = tk.Entry(top, width=30)
        pwd_entry.insert(0, password)
        pwd_entry.pack()

        def generate_and_fill():
            pwd_entry.delete(0, tk.END)
            pwd_entry.insert(0, generate_password(16))

        tk.Button(top, text="Generate Password", command=generate_and_fill).pack(pady=5)

        def save_changes():
            new_service = service_entry.get()
            new_user = user_entry.get()
            new_pwd = pwd_entry.get()
            if new_service and new_user and new_pwd:
                self.entries[index] = f"{new_service} | {new_user} | {new_pwd}"
                self.refresh_table()
                top.destroy()
            else:
                messagebox.showwarning("Missing Info", "Please fill in all fields.")

        tk.Button(top, text="Save", command=save_changes).pack(pady=10)

    def add_entry(self):
        top = tk.Toplevel(self.root)
        top.title("Add Password Entry")
        top.geometry("350x250")

        tk.Label(top, text="Service:").pack(pady=5)
        service_entry = tk.Entry(top, width=30)
        service_entry.pack()

        tk.Label(top, text="Username:").pack(pady=5)
        user_entry = tk.Entry(top, width=30)
        user_entry.pack()

        tk.Label(top, text="Password:").pack(pady=5)
        pwd_entry = tk.Entry(top, width=30)
        pwd_entry.pack()

        def generate_and_fill():
            pwd_entry.delete(0, tk.END)
            pwd_entry.insert(0, generate_password(16))

        tk.Button(top, text="Generate Password", command=generate_and_fill).pack(pady=5)

        def save_entry():
            service = service_entry.get()
            username = user_entry.get()
            password = pwd_entry.get()
            if service and username and password:
                entry = f"{service} | {username} | {password}"
                self.entries.append(entry)
                self.refresh_table()
                top.destroy()
            else:
                messagebox.showwarning("Missing Info", "Please fill in all fields.")

        tk.Button(top, text="Add", command=save_entry).pack(pady=10)

    def save_entries(self):
        data = "\n".join(self.entries)
        save_vault(data, self.key)
        messagebox.showinfo("Saved", "Vault saved successfully!")

    def refresh_table(self):
        self.load_entries_to_table()

    def copy_to_clipboard(self, text):
        pyperclip.copy(text)
        messagebox.showinfo("Copied", "Password copied to clipboard. It will be cleared in 15 seconds.")

        def clear_clipboard():
            time.sleep(15)
            pyperclip.copy("")
        threading.Thread(target=clear_clipboard, daemon=True).start()


def prompt_master_password(prompt_text="Enter Master Password"):
    def submit():
        password = entry.get()
        if not password:
            messagebox.showwarning("Warning", "Password cannot be empty")
        else:
            result.append(password)
            top.destroy()

    result = []
    top = tk.Toplevel()
    top.title(prompt_text)
    width, height = 320, 140
    screen_width = top.winfo_screenwidth()
    screen_height = top.winfo_screenheight()
    x = (screen_width // 2) - (width // 2)
    y = (screen_height // 2) - (height // 2)
    top.geometry(f"{width}x{height}+{x}+{y}")
    top.resizable(False, False)
    top.grab_set()

    tk.Label(top, text=prompt_text, font=("Segoe UI", 11)).pack(pady=(15, 5))
    entry = tk.Entry(top, width=30, show="*")
    entry.pack(pady=5)
    entry.focus()

    tk.Button(top, text="OK", command=submit).pack(pady=(5, 10))
    top.wait_window()

    return result[0] if result else None

if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()  # Hide main window during prompt

    if is_first_run():
        pw1 = prompt_master_password("Create a master password:")
        pw2 = prompt_master_password("Confirm password:")
        if not pw1 or not pw2 or pw1 != pw2:
            messagebox.showerror("Error", "Passwords don't match or were empty.")
            exit()
        save_master_password(pw1)
        master_password = pw1
    else:
        master_password = prompt_master_password("Enter master password")
        if not master_password or not verify_master_password(master_password):
            messagebox.showerror("Error", "Incorrect master password.")
            exit()

    root.deiconify()  # Show main window after password is verified
    app = PasswordManagerApp(root, master_password)
    root.mainloop()
