import tkinter as tk
from tkinter import filedialog

def insert_file_path(entry_file_path, upload_button, root):
    file_path = filedialog.askopenfilename()
    if file_path:
        entry_file_path.config(state="normal")
        entry_file_path.delete(0, tk.END)
        entry_file_path.insert(0, file_path)
        upload_button.destroy()  # Delete the existing button
        upload_button_new = tk.Button(root, text="scan", command=lambda: insert_file_path())
        upload_button_new.pack(pady=5)

def virus_scan(file_path):
    pass

def main():
    root = tk.Tk()
    root.title("Anti virus scanner")
    root.geometry("500x500")

    title_font = ("Helvetica", 24, "bold")

    # Create a Label widget with the big title text and the defined font
    title_label = tk.Label(root, text="Anti virus scanner", font=title_font)
    title_label.pack(pady=20)

    entry_file_path = tk.Entry(root, width=70, state="disabled")
    entry_file_path.pack(pady=10)

    upload_button = tk.Button(root, text="Browse", command=lambda: insert_file_path(entry_file_path, upload_button, root))
    upload_button.pack(pady=5)


    root.mainloop()

if __name__=="__main__":
    main()