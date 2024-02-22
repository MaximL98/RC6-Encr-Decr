import tkinter as tk
import time


# Create username array
import threading

def print_without_freezing():
    thread = threading.Thread(target=send_info)
    thread.start()

def encrypt_passcode(passcode):
    pass


usernameArray = ["user1", "user2", "user3"]

def check_username():
    username = username_entry.get()
    if username not in usernameArray:
        bank_text.insert(tk.END, "Username not found\n", "error")
    else:
        bank_text.insert(tk.END, f"Username: {username}\n")

    # Configure text widget tags
    bank_text.tag_configure("error", foreground="red")

def send_info():
    username = username_entry.get()
    passcode = passcode_entry.get()
    card_number = card_number_entry.get()
    date = date_entry.get()

    def insert_text(text):
        bank_text.insert(tk.END, text)
        bank_text.see(tk.END)

    insert_text(f"Received payment request from {username}...\n")
    root.after(1000, lambda: insert_text(f"Passcode: {passcode}\n"))
    root.after(3000, lambda: insert_text(f"Hashed card number: {card_number}\n"))
    root.after(5000, lambda: insert_text("Encrypting data."))
    root.after(5330, lambda: insert_text("."))
    root.after(5660, lambda: insert_text("."))
    root.after(6000, lambda: insert_text("."))
    root.after(6330, lambda: insert_text("."))
    root.after(6660, lambda: insert_text("."))
    root.after(7000, lambda: insert_text("."))
    root.after(7330, lambda: insert_text("."))
    root.after(7660, lambda: insert_text(".\n"))
    

    root.after(8000, lambda: insert_text(f"Passcode after encryption: {encrypt_passcode(passcode)}\n"))
    root.after(8000, lambda: insert_text(f"Card number after encryption: {encrypt_passcode(passcode)}\n"))
    root.after(8000, lambda: insert_text("------------------------\n"))


root = tk.Tk()
root.title("Bank App")
root.geometry("1000x800")
root.configure(bg="black")

# Create input frame
input_frame = tk.Frame(root, bg="black")
input_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

# Create input boxes
username_label = tk.Label(input_frame, text="Username:", fg="white", bg="black")
username_label.pack()
username_entry = tk.Entry(input_frame)
username_entry.pack()

passcode_label = tk.Label(input_frame, text="Passcode:", fg="white", bg="black")
passcode_label.pack()
passcode_entry = tk.Entry(input_frame, show="*")
passcode_entry.pack()

card_number_label = tk.Label(input_frame, text="Card Number:", fg="white", bg="black")
card_number_label.pack()
card_number_entry = tk.Entry(input_frame)
card_number_entry.pack()

date_label = tk.Label(input_frame, text="Date:", fg="white", bg="black")
date_label.pack()
date_entry = tk.Entry(input_frame)
date_entry.pack()

cvc_label = tk.Label(input_frame, text="CVC:", fg="white", bg="black")
cvc_label.pack()
cvc_entry = tk.Entry(input_frame)
cvc_entry.pack()

# Create button
send_button = tk.Button(input_frame, text="Send", command=print_without_freezing)
send_button.pack()

# Create info frame
info_frame = tk.Frame(root, bg="black")
info_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

# Create bank box
bank_text = tk.Text(info_frame, bg="black", fg="white")
bank_text.pack()

# Create behind the scenes frame
behind_scenes_frame = tk.Frame(root, bg="black")
behind_scenes_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
behind_scenes_frame_label = tk.Label(behind_scenes_frame, text="Behind the scenes", fg="white", bg="black")

root.mainloop()
