import tkinter as tk
import tkinter.messagebox as messagebox
from tkinter import filedialog
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def generate_key():
    key_length = key_length_var.get()  # Get the selected key length from the variable
    key = RSA.generate(key_length)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    folder_path = filedialog.askdirectory()
    if folder_path:
        private_key_path = folder_path + "/private_key.pem"
        public_key_path = folder_path + "/public_key.pem"
        with open(private_key_path, "wb") as private_file:
            private_file.write(private_key)
        with open(public_key_path, "wb") as public_file:
            public_file.write(public_key)
        messagebox.showinfo(
            "RSA Key Generation",
            f"RSA密钥已生成！\n已保存至：\n{private_key_path}\n公钥已保存至：\n{public_key_path}",
        )


def encrypt_message():
    try:
        file_path = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
        if not file_path:
            return
        with open(file_path, "rb") as file:
            public_key = RSA.import_key(file.read())
        message = entry.get("1.0", tk.END).strip()
        cipher = PKCS1_OAEP.new(public_key)
        encrypted_message = cipher.encrypt(message.encode())
        entry.delete("1.0", tk.END)  # Clear the text box
        entry.insert(tk.END, encrypted_message.hex())  # Insert the encrypted message into the text box
        messagebox.showinfo("RSA Encryption", "加密成功！")
    except FileNotFoundError:
        messagebox.showerror("错误", "公钥文件不存在！请先生成RSA密钥。")


def decrypt_message():
    try:
        file_path = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
        if not file_path:
            return
        with open(file_path, "rb") as file:
            private_key = RSA.import_key(file.read())
        encrypted_message = entry.get("1.0", tk.END).strip()
        cipher = PKCS1_OAEP.new(private_key)
        decrypted_message = cipher.decrypt(bytes.fromhex(encrypted_message)).decode()
        entry.delete("1.0", tk.END)  # Clear the text box
        entry.insert(tk.END, decrypted_message)  # Insert the decrypted message into the text box
        messagebox.showinfo("RSA Decryption", "解密成功！")
    except FileNotFoundError:
        messagebox.showerror("错误", "私钥文件不存在！请先生成RSA密钥。")
    except ValueError:
        messagebox.showerror("错误", "无效的密文！")


def copy_text():
    window.clipboard_clear()  # Clear the clipboard
    window.clipboard_append(entry.get("1.0", tk.END).strip())  # Copy the content of the text box to the clipboard


window = tk.Tk()
window.title("RSA加解密/签名软件")

label = tk.Label(window, text="请输入要加密/解密的消息：")
label.pack()

entry = tk.Text(window, height=30, width=60)
entry.pack()

# Create a variable to store the selected key length
key_length_var = tk.IntVar()
key_length_var.set(2048)  # Set a default key length

key_length_label = tk.Label(window, text="选择密钥长度：")
key_length_label.pack()

# Create a dropdown menu for key length selection
key_length_menu = tk.OptionMenu(window, key_length_var, 1024, 2048, 4096)  # 选择密钥长度
key_length_menu.pack()

copy_button = tk.Button(window, text="复制文本框内容", command=copy_text)
copy_button.pack(side=tk.LEFT, padx=10, pady=10)

generate_button = tk.Button(window, text="生成RSA密钥对", command=generate_key)
generate_button.pack(side=tk.LEFT, padx=10, pady=10)

encrypt_button = tk.Button(window, text="RSA加密", command=encrypt_message)
encrypt_button.pack(side=tk.LEFT, padx=70, pady=10)

decrypt_button = tk.Button(window, text="RSA解密", command=decrypt_message)
decrypt_button.pack(side=tk.LEFT, padx=10, pady=10)

# 设置窗口尺寸和位置
window.geometry("500x550")
window.update_idletasks()  # 更新窗口尺寸
window_width = window.winfo_width()
window_height = window.winfo_height()
screen_width = window.winfo_screenwidth()
screen_height = window.winfo_screenheight()
x = int((screen_width - window_width) / 2)
y = int((screen_height - window_height) / 2)
window.geometry(f"{window_width}x{window_height}+{x}+{y}")

window.mainloop()
