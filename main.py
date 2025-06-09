import os
import csv
import random
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
from tkinterdnd2 import TkinterDnD, DND_FILES
import requests
from dotenv import load_dotenv
import datetime
from PIL import Image, ImageTk

load_dotenv()


class SubscriptionApp(TkinterDnD.Tk):
    def __init__(self):
        super().__init__()
        self.title("FinHarbor Manager")
        self.geometry("900x700")
        self.configure_dark_theme()
        self.setup_icon()

        self.admin_token = os.getenv('access_token')
        self.url = os.getenv('url')
        self.current_file = None
        self.log_file = "AppLogs.txt"
        self.setup_ui()
        self.clear_log_file()

    def configure_dark_theme(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')

        bg_color = "#2d2d2d"
        fg_color = "#ffffff"
        entry_bg = "#3d3d3d"
        button_bg = "#4d4d4d"
        highlight_color = "#3a7ebf"

        self.configure(bg=bg_color)
        self.style.configure('.', background=bg_color, foreground=fg_color)
        self.style.configure('TLabel', background=bg_color, foreground=fg_color)
        self.style.configure('TFrame', background=bg_color)
        self.style.configure('TButton', background=button_bg, foreground=fg_color)
        self.style.configure('TEntry', fieldbackground=entry_bg, foreground=fg_color)
        self.style.configure('TLabelFrame', background=bg_color, foreground=fg_color)
        self.style.map('TButton', background=[('active', highlight_color)])

    def setup_icon(self):
        try:
            img = Image.open("icon.png") if os.path.exists("icon.png") else None
            if img:
                img = img.resize((32, 32), Image.Resampling.LANCZOS)
                self.iconphoto(False, ImageTk.PhotoImage(img))
        except:
            pass

    def clear_log_file(self):
        with open(self.log_file, 'w') as f:
            f.write(f"FinHarbor Manager Log - {datetime.datetime.now()}\n\n")

    def setup_ui(self):
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        token_frame = ttk.LabelFrame(main_frame, text="Admin Settings", padding=10)
        token_frame.pack(fill=tk.X, pady=5)

        ttk.Label(token_frame, text="Admin Token:").grid(row=0, column=0, padx=5, pady=5)
        self.token_entry = ttk.Entry(token_frame, width=50)
        self.token_entry.insert(0, self.admin_token or "")
        self.token_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(token_frame, text="API URL:").grid(row=1, column=0, padx=5, pady=5)
        self.url_entry = ttk.Entry(token_frame, width=50)
        self.url_entry.insert(0, self.url or "")
        self.url_entry.grid(row=1, column=1, padx=5, pady=5)

        drop_frame = ttk.LabelFrame(main_frame, text="Drag & Drop CSV File", padding=10)
        drop_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.drop_label = ttk.Label(drop_frame, text="Drag and drop user_info.csv file here or click Browse",
                                    font=('Helvetica', 12), relief=tk.SUNKEN, padding=20)
        self.drop_label.pack(fill=tk.BOTH, expand=True)

        browse_button = ttk.Button(drop_frame, text="Browse", command=self.browse_file)
        browse_button.pack(pady=5)

        log_frame = ttk.LabelFrame(main_frame, text="Log Output", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, wrap=tk.WORD, bg="#3d3d3d", fg="#ffffff")
        self.log_text.pack(fill=tk.BOTH, expand=True)

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=5)

        ttk.Button(button_frame, text="Process File", command=self.process_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear Log", command=self.clear_log).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Info", command=self.show_info).pack(side=tk.RIGHT, padx=5)

        self.drop_label.drop_target_register(DND_FILES)
        self.drop_label.dnd_bind('<<Drop>>', self.on_drop)

    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if file_path:
            self.current_file = file_path
            self.drop_label.config(text=f"Selected file: {file_path}")
            self.log_message(f"File loaded: {file_path}")

    def on_drop(self, event):
        files = self.tk.splitlist(event.data)
        if files:
            file_path = files[0]
            if file_path.endswith('.csv'):
                self.current_file = file_path
                self.drop_label.config(text=f"Selected file: {file_path}")
                self.log_message(f"File loaded: {file_path}")
            else:
                messagebox.showerror("Error", "Please select a CSV file")

    def process_file(self):
        if not self.current_file:
            messagebox.showerror("Error", "No CSV file selected")
            return

        self.admin_token = self.token_entry.get()
        self.url = self.url_entry.get()

        if not self.admin_token or not self.url:
            messagebox.showerror("Error", "Please enter Admin Token and API URL")
            return

        try:
            with open(self.current_file, 'r') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    user_id = row['user_id']
                    user_token = row['access_token']
                    self.process_user(user_id, user_token)

        except Exception as e:
            self.log_message(f"Error processing file: {str(e)}")

    def process_user(self, user_id, user_token):
        self.log_message(f"\nProcessing user {user_id}")

        sub_info = self.get_user_subscriptions(user_token)
        if sub_info:
            status = sub_info['status']
            sub_id = sub_info['id']
            self.log_message(f"User already has {status} subscription (ID: {sub_id})")
            return False

        account_id = self.create_account(user_id, user_token)
        if not account_id:
            return False

        if not self.give_money(account_id):
            return False

        if not self.grant_sub(user_token, user_id):
            return False

        if not self.create_invoice_payment(user_token, account_id):
            return False

        return True

    def get_user_subscriptions(self, token):
        headers = self.get_auth_headers(token)
        try:
            response = requests.get(f"{self.url}/reg/subscription", headers=headers)
            if response.status_code == 200:
                data = response.json()
                if data and isinstance(data, list):
                    for sub in data:
                        if sub.get('status') in ['INIT', 'ACTIVE']:
                            return {
                                'id': sub.get('id'),
                                'status': sub.get('status'),
                                'name': sub.get('subscriptionDetails', {}).get('name')
                            }
        except Exception as e:
            self.log_message(f"Error checking subscriptions: {str(e)}")
        return None

    def create_account(self, user_id, token):
        headers = self.get_auth_headers(token)
        try:
            response = requests.post(
                f"{self.url}/wallet/account?accountType=CHECKING",
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            account_data = response.json()
            account_id = account_data.get('account')
            self.log_message(f"Account created. ID: {account_id}")
            return account_id
        except Exception as e:
            self.log_message(f"Account creation failed - {str(e)}")
            return None

    def give_money(self, to_account, amount="20", currency="USDT"):
        headers = self.get_auth_headers(self.admin_token)
        payload = {
            "fromAccount": "mm",
            "toAccount": to_account,
            "currency": currency,
            "amount": amount,
            "type": "ORIGINAL"
        }
        try:
            response = requests.post(
                f"{self.url}/wallet/admin/operations/transfer?dryRun=false&conversion=false&anyCurrency=true",
                headers=headers,
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            self.log_message(f"Added {amount} {currency} to account {to_account}")
            return True
        except Exception as e:
            self.log_message(f"Failed to add balance - {str(e)}")
            return False

    def grant_sub(self, token, user_id):
        headers = self.get_auth_headers(token)
        subscriptions = self.get_available_subscriptions(token)

        if not subscriptions:
            self.log_message("No available subscriptions found")
            return False

        try:
            sub_key, sub_value = random.choice(list(subscriptions.items()))

            payload = {
                "anyCurrency": True,
                "autoPayment": True,
                "subscriptionDetailsId": sub_value
            }

            response = requests.post(
                f"{self.url}/reg/subscription",
                headers=headers,
                json=payload,
                timeout=10
            )

            if response.status_code in (200, 201, 202):
                self.log_message(f"Assigned subscription: {sub_key} (ID: {sub_value})")
                return True
            else:
                self.log_message(f"Failed to assign subscription: {response.status_code} {response.text}")
                return False

        except Exception as e:
            self.log_message(f"Error granting subscription: {str(e)}")
            return False

    def create_invoice_payment(self, token, account_id):
        invoice_id = self.get_user_subs(token)
        if not invoice_id:
            self.log_message("No invoice ID found")
            return False

        invoice_payment_id = self.get_invoice_by_id(token, invoice_id)
        if not invoice_payment_id:
            self.log_message("No invoice payment ID found")
            return False

        headers = self.get_auth_headers(token)
        payload = {
            "invoiceId": invoice_payment_id,
            "type": "ORIGINAL",
            "externalPayment": {}
        }

        try:
            response = requests.post(
                f"{self.url}/acquiring/admin/invoice/pay",
                headers=headers,
                json=payload,
                timeout=10
            )

            if response.status_code in (200, 201, 202):
                self.log_message("Invoice payment successful")
                return True
            else:
                self.log_message(f"Payment failed: {response.status_code} {response.text}")
                return False

        except Exception as e:
            self.log_message(f"Error processing payment: {str(e)}")
            return False

    def get_auth_headers(self, token):
        return {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }

    def get_available_subscriptions(self, token):
        headers = self.get_auth_headers(token)
        try:
            response = requests.get(
                f"{self.url}/reg/subscription/details/available",
                headers=headers
            )
            if response.status_code == 200:
                subscriptions_data = response.json()
                return {sub['name']: sub['id'] for sub in subscriptions_data}
        except Exception as e:
            self.log_message(f"Error getting subscriptions: {str(e)}")
        return None

    def get_user_subs(self, token):
        headers = self.get_auth_headers(token)
        try:
            response = requests.get(f"{self.url}/reg/subscription", headers=headers)
            if response.status_code == 200:
                data = response.json()
                if data and isinstance(data, list) and data[0].get('invoice'):
                    return data[0]['invoice']['id']
        except Exception as e:
            self.log_message(f"Error getting subscriptions: {str(e)}")
        return None

    def get_invoice_by_id(self, token, invoice_id):
        headers = self.get_auth_headers(token)
        try:
            response = requests.get(f"{self.url}/acquiring/invoice/{invoice_id}", headers=headers)
            if response.status_code == 200:
                invoice_data = response.json()
                latest_invoice = None
                for invoice in invoice_data.get("linkedInvoices", []):
                    if invoice.get("status") == "INIT":
                        if latest_invoice is None or invoice["lastModifiedDate"] > latest_invoice["lastModifiedDate"]:
                            latest_invoice = invoice
                return latest_invoice["id"] if latest_invoice else None
        except Exception as e:
            self.log_message(f"Error getting invoice: {str(e)}")
        return None

    def log_message(self, message):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_msg = f"[{timestamp}] {message}"
        self.log_text.insert(tk.END, log_msg + "\n")
        self.log_text.see(tk.END)
        self.update_idletasks()

        with open(self.log_file, 'a') as f:
            f.write(log_msg + "\n")

    def clear_log(self):
        self.log_text.delete(1.0, tk.END)

    def show_info(self):
        info_text = """This tool helps manage user subscriptions:

1. Drag & drop a CSV file with user info (user_id, access_token)
2. For each user:
   - Checks for existing subscriptions
   - Creates an account if needed
   - Adds test funds (20 USDT)
   - Assigns a random subscription
   - Processes the payment

Admin Token is used to add funds and pay invoice for subscription to user accounts."""
        messagebox.showinfo("Information", info_text)


if __name__ == "__main__":
    app = SubscriptionApp()
    app.mainloop()