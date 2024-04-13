import tkinter as tk
from tkinter import filedialog
import AntiVirus
import os
import time

#summary
#GUI version for the anti virus scan project
#made by tkinter library
#all scan functions in the file: AntiVirus.py, with an option for a console version (main func)
#summary

#show the file path on the input field
def insert_file_path():
    #retrive file path
    file_path = filedialog.askopenfilename()
    #unlock input field
    entry_file_path.config(state="normal")
    #change instructions for the user
    report_text.config(text="Press on the scan button")
    #input file path
    entry_file_path.delete(0, tk.END)
    entry_file_path.insert(0, file_path)
    #change the upload button to a scan button
    upload_button.config(text="scan", command=lambda: virus_scan(file_path))

#open a scan report (JSON) in .txt file
def open_scan_report(scan_report):
    #copy the scan report to the txt file
    with open('scan_report.txt', 'w') as f:
        f.write(str(scan_report))
    #show file on screen
    os.system("notepad.exe scan_report.txt")

#reset app to scan another file
def reset_app():
    root.destroy()
    main()

#virus scan process function, input file path.
def virus_scan(file_path):
    print("In the virus_scan func...")
    #show text on screen for the user
    report_text.config(text="scanning in process...")
    root.update()

    #create button to open scan report at the end
    open_scan_report_button = tk.Button(root, text="open scan report", command=lambda: open_scan_report(scan_report))
    print("tk objects set...")
    #upload file to antivirustotal.com for scannig
    post_scan_result = AntiVirus.post_file_scan(file_path)
    #recive response code to check if the file was sent
    if post_scan_result['response_code']==1:
        #retrive scan_id from the post JSON file
        scan_id = post_scan_result['scan_id']
        print("File was sent...")
        #scan loop
        while True:
            print("In loop...")
            #check if scan is completed
            scan_status = AntiVirus.check_scan_status(scan_id)
            #if the scan is completed, show results.
            if scan_status == 'completed':
                print("finished...")
                #retrive the scan resulte as JSON file
                global scan_report
                scan_report = AntiVirus.get_file_scan(scan_id)
                #if the file is clean
                if(scan_report['positives']==0):
                    print("clean")
                    #show resulte on screen for the user
                    report_text.config(text="THE FILE IS CLEAN", foreground="green")
                    #active scan report button
                    open_scan_report_button.pack()
                #virus was detected
                else:
                    print("virus dected")
                    #show resulte on screen for the user
                    report_text.config(text="VIRUS WAS DETECTED", foreground="red")
                    #active scan report button
                    open_scan_report_button.pack()
                break
            #if the file is in queue for the scan
            elif scan_status == 'queued' or scan_status== 'in-progress':
                print("In queue...")
                #wait 30 seconds for another iteration
                time.sleep(30)
            #scanning eror
            else:
                report_text.config("scan eror...", foreground="red")
                print("Eror...")
                break
    #scannig eror
    else:
        report_text.config("scan eror...", foreground="red")


def main():
    #build the tkinter window
    global root
    root = tk.Tk()
    root.title("Anti virus scanner")
    root.geometry("500x500")

    title_font = ("Helvetica", 24, "bold")

    #app title
    title_label = tk.Label(root, text="Anti virus scanner", font=title_font)
    title_label.pack(pady=20)

    #file path field
    global entry_file_path
    entry_file_path = tk.Entry(root, width=70, state="disabled")
    entry_file_path.pack(pady=10)

    #upload file button
    global upload_button
    upload_button = tk.Button(root, text="Browse", command=lambda: insert_file_path())
    upload_button.pack(pady=5)

    #reset button
    reset_scan = tk.Button(root, text="reset", command=reset_app)
    reset_scan.pack()

    #text for instructions
    global report_text
    report_text = tk.Label(root, text="Input a file to scan")
    report_text.pack()

    #tk loop
    root.mainloop()

if __name__=="__main__":
    main()