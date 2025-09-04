import psutil
import platform
import os
import hashlib
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox
from plyer import notification

# ----------------- Config -----------------
SCAN_INTERVAL = 10
SUSPICION_THRESHOLD = 5
TEMP_DIRS = [
    os.environ.get("TEMP","/tmp"),
    os.environ.get("TMP","/tmp"),
    "/var/tmp",
    os.environ.get("APPDATA","")  # Windows
]
known_pids = set()
IS_WINDOWS = platform.system() == "Windows"

# ----------------- Utility Functions -----------------
def compute_sha256(file_path):
    if not os.path.isfile(file_path):
        return None
    h = hashlib.sha256()
    try:
        with open(file_path,"rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()
    except:
        return None

def is_suspicious_file_access(proc):
    score = 0
    try:
        for f in proc.open_files():
            path = f.path.lower()
            if any(td.lower() in path for td in TEMP_DIRS):
                score += 3
    except:
        pass
    return score

def is_high_resource_usage(proc):
    score = 0
    try:
        if proc.cpu_percent(interval=0.1) > 20:
            score += 2
        if proc.memory_percent() > 20:
            score += 2
    except:
        pass
    return score

def is_network_activity(proc):
    score = 0
    try:
        cons = proc.connections(kind='inet')
        if cons:
            score += 2
    except:
        pass
    return score

def is_keyboard_hook(proc):
    score = 0
    if IS_WINDOWS:
        try:
            if "python" in (proc.name() or "").lower():
                score += 5
        except:
            pass
    return score

def show_system_notification(title,message):
    notification.notify(
        title=title,
        message=message,
        app_name="Keylogger Detector",
        timeout=5
    )

# ----------------- Scan Processes -----------------
def scan_processes():
    results = []
    for proc in psutil.process_iter(['pid','name','exe']):
        try:
            pid = proc.info['pid']
            name = proc.info['name'] or ""
            exe = proc.info['exe'] or ""
            sha256 = compute_sha256(exe)
            score = 0
            score += is_suspicious_file_access(proc)
            score += is_high_resource_usage(proc)
            score += is_network_activity(proc)
            score += is_keyboard_hook(proc)
            status = "OK"
            if score >= SUSPICION_THRESHOLD:
                status = "Suspicious"
            results.append((pid,name,exe,score,sha256,status))
        except:
            continue
    return results

# ----------------- GUI App -----------------
class DetectorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Cross-Platform Keylogger Detector")
        self.root.geometry("1000x600")

        tk.Label(root, text="🛡️ Keylogger Detector", font=("Arial",18,"bold"), fg="blue").pack(pady=10)

        frame = tk.Frame(root)
        frame.pack(fill="both", expand=True, padx=10, pady=5)
        self.tree = ttk.Treeview(frame, columns=("PID","Name","Path","Score","SHA256","Status"), show="headings")
        for col in ("PID","Name","Path","Score","SHA256","Status"):
            self.tree.heading(col,text=col)
        self.tree.pack(side="left",fill="both",expand=True)
        scrollbar = tk.Scrollbar(frame,command=self.tree.yview)
        scrollbar.pack(side="right",fill="y")
        self.tree.config(yscrollcommand=scrollbar.set)

        btn_frame = tk.Frame(root)
        btn_frame.pack(fill="x", pady=5)
        tk.Button(btn_frame,text="Terminate Selected Process",command=self.kill_process,bg="red",fg="white").pack(side="left", padx=5)
        tk.Button(btn_frame,text="View Details",command=self.view_details,bg="blue",fg="white").pack(side="left", padx=5)

        self.status_label = tk.Label(root,text="Status: Scanning...", font=("Arial",12), fg="green")
        self.status_label.pack(pady=5)

        self.running = True
        threading.Thread(target=self.monitor_processes, daemon=True).start()

    # ----------------- Update Tree -----------------
    def update_tree(self):
        self.tree.delete(*self.tree.get_children())
        processes = scan_processes()
        for pid,name,exe,score,sha256,status in processes:
            self.tree.insert("",tk.END,values=(pid,name,exe,score,sha256,status))
            if "Suspicious" in status:
                self.tree.item(self.tree.get_children()[-1],tags=("suspicious",))
        self.tree.tag_configure("suspicious", foreground="red")
        return processes

    # ----------------- Kill Process -----------------
    def kill_process(self):
        sel = self.tree.focus()
        if not sel:
            messagebox.showinfo("Info","No process selected.")
            return
        pid = int(self.tree.item(sel)['values'][0])
        try:
            psutil.Process(pid).terminate()
            messagebox.showinfo("Success",f"Process {pid} terminated.")
            self.update_tree()
        except Exception as e:
            messagebox.showerror("Error",str(e))

    # ----------------- View Details -----------------
    def view_details(self):
        sel = self.tree.focus()
        if not sel:
            messagebox.showinfo("Info","No process selected.")
            return
        values = self.tree.item(sel)['values']
        msg = f"PID: {values[0]}\nName: {values[1]}\nPath: {values[2]}\nScore: {values[3]}\nSHA256: {values[4]}\nStatus: {values[5]}"
        messagebox.showinfo("Process Details", msg)

    # ----------------- Focus on Suspicious Process -----------------
    def focus_on_process(self, pid):
        for item in self.tree.get_children():
            if int(self.tree.item(item)['values'][0]) == pid:
                self.tree.see(item)
                self.tree.selection_set(item)
                self.tree.focus(item)
                break

    # ----------------- Monitor -----------------
    def monitor_processes(self):
        global known_pids
        while self.running:
            processes = self.update_tree()
            current_pids = {p[0] for p in processes}
            new_pids = current_pids - known_pids
            for pid in new_pids:
                entry = next((p for p in processes if p[0]==pid),None)
                if entry and entry[5]=="Suspicious":
                    msg = f"{entry[1]} (PID {entry[0]}) flagged. Score: {entry[3]}"
                    show_system_notification("⚠️ Suspicious Process Detected", msg)
                    print(f"[ALERT] {msg}")
                    # Focus GUI on the suspicious process
                    self.root.after(0, lambda p=pid: self.focus_on_process(p))
            known_pids = current_pids
            if any(p[5]=="Suspicious" for p in processes):
                self.status_label.config(text="⚠️ Suspicious activity detected!", fg="red")
            else:
                self.status_label.config(text="✅ System is safe", fg="green")
            time.sleep(SCAN_INTERVAL)

# ----------------- Run -----------------
if __name__=="__main__":
    root = tk.Tk()
    app = DetectorGUI(root)
    root.protocol("WM_DELETE_WINDOW", root.quit)
    root.mainloop()

