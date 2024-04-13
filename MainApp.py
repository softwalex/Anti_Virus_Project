import tkinter as tk
from tkinter import filedialog
import AntiVirus
import os
import time

def insert_file_path():
    file_path = filedialog.askopenfilename()
    entry_file_path.config(state="normal")
    report_text.config(text="Press on the scan button")
    entry_file_path.delete(0, tk.END)
    entry_file_path.insert(0, file_path)
    upload_button.config(text="scan", command=lambda: virus_scan(file_path))

def open_scan_report(scan_report):
    with open('scan_report.txt', 'w') as f:
        f.write(str(scan_report))
    os.system("notepad.exe scan_report.txt")

def reset_app():
    root.destroy()
    main()

def virus_scan(file_path):
    print("In the virus_scan func...")
    report_text.config(text="scanning in process...")
    root.update()

    open_scan_report_button = tk.Button(root, text="open scan report", command=lambda: open_scan_report(scan_report))
    print("tk objects set...")
    post_scan_result = AntiVirus.post_file_scan(file_path)
    if post_scan_result['response_code']==1:
        scan_id = post_scan_result['scan_id']
        print("File was sent...")
        while True:
            print("In loop...")
            scan_status = AntiVirus.check_scan_status(scan_id)
            if scan_status == 'completed':
                print("finished...")
                global scan_report
                scan_report = AntiVirus.get_file_scan(scan_id)
                if(scan_report['positives']==0):
                    print("clean")
                    report_text.config(text="THE FILE IS CLEAN", foreground="green")
                    open_scan_report_button.pack()
                else:
                    print("virus dected")
                    report_text.config(text="VIRUS WAS DETECTED", foreground="red")
                    open_scan_report_button.pack()
                break
            elif scan_status == 'queued' or scan_status== 'in-progress':
                print("In queue...")
                time.sleep(30)
            else:
                report_text.config("scan eror...", foreground="red")
                print("Eror...")
                break
    else:
        report_text.config("scan eror...", foreground="red")


def main():
    global root
    root = tk.Tk()
    root.title("Anti virus scanner")
    root.geometry("500x500")

    title_font = ("Helvetica", 24, "bold")

    # Create a Label widget with the big title text and the defined font
    title_label = tk.Label(root, text="Anti virus scanner", font=title_font)
    title_label.pack(pady=20)

    global entry_file_path
    entry_file_path = tk.Entry(root, width=70, state="disabled")
    entry_file_path.pack(pady=10)

    global upload_button
    upload_button = tk.Button(root, text="Browse", command=lambda: insert_file_path())
    upload_button.pack(pady=5)

    reset_scan = tk.Button(root, text="reset", command=reset_app)
    reset_scan.pack()

    global report_text
    report_text = tk.Label(root, text="Input a file to scan")
    report_text.pack()


    root.mainloop()

if __name__=="__main__":
    main()