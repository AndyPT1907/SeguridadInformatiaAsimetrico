import tkinter as tk
from tkinter import messagebox
from Crypto.PublicKey import RSA 
from Crypto.Cipher import PKCS1_OAEP 
from Crypto.Hash import SHA256 

# Generar las claves (esto debería hacerse una sola vez en una situación real)
key = RSA.generate(2048)

private_key = key.export_key()
public_key = key.publickey().export_key()

# Función para cifrar el texto ingresado
def encrypt_message():
    message = text_entry.get("1.0", tk.END).strip().encode('utf-8')
    if not message:
        messagebox.showwarning("Advertencia", "Por favor, ingrese un texto.")
        return
    
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key, hashAlgo=SHA256)
    encrypted_message = cipher_rsa.encrypt(message)
    
    text_output.delete("1.0", tk.END)
    text_output.insert(tk.END, encrypted_message.hex())  # Mostrar en formato hexadecimal para legibilidad

# Función para descifrar el texto ingresado
def decrypt_message():
    encrypted_message = text_entry.get("1.0", tk.END).strip()
    if not encrypted_message:
        messagebox.showwarning("Advertencia", "Por favor, ingrese un texto cifrado.")
        return
    
    try:
        encrypted_message_bytes = bytes.fromhex(encrypted_message)
        private_key_obj = RSA.import_key(private_key)
        cipher_rsa = PKCS1_OAEP.new(private_key_obj, hashAlgo=SHA256)
        decrypted_message = cipher_rsa.decrypt(encrypted_message_bytes)
        
        text_output.delete("1.0", tk.END)
        text_output.insert(tk.END, decrypted_message.decode('utf-8'))
    except (ValueError, TypeError):
        messagebox.showerror("Error", "El texto no se puede descifrar. Asegúrese de haber ingresado un texto cifrado válido.")

# Crear la ventana de la interfaz gráfica
app = tk.Tk()
app.title("Cifrado Asimétrico con RSA")

# Etiqueta y cuadro de entrada para el texto original
label_input = tk.Label(app, text="Ingrese el texto:")
label_input.pack()

text_entry = tk.Text(app, height=5, width=50)
text_entry.pack()

# Botón para cifrar el texto
encrypt_button = tk.Button(app, text="Cifrar", command=encrypt_message)
encrypt_button.pack(pady=5)

# Botón para descifrar el texto
decrypt_button = tk.Button(app, text="Descifrar", command=decrypt_message)
decrypt_button.pack(pady=5)

# Etiqueta y cuadro de salida para mostrar el resultado cifrado/descifrado
label_output = tk.Label(app, text="Resultado:")
label_output.pack()

text_output = tk.Text(app, height=5, width=50)
text_output.pack()

# Iniciar la interfaz gráfica
app.mainloop()
