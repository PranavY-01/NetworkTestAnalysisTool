from scapy.all import sniff, IP, get_if_list     # for packet sniffing
from datetime import datetime       # for date and time parameters
import pandas as pd     # to store and process captured data
import seaborn as sns        # to assist matplotlib in visualization
import matplotlib.pyplot as plt     #to show statistical visualizaton patterns of the packets
import tkinter as tk         # for GUI interaction
from tkinter import filedialog, messagebox, ttk
import threading        #to prevent the tkinter from freezing during packet sniffing

captured_data = []      # global for captured data packets
selected_file_path = ""  # global for CSV file path

# Protocol numbers to name mapping
protocol_map = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    89: "OSPF",
}

def packet_callback(packet):
    if IP in packet:
        proto_num = packet.proto
        proto_name = protocol_map.get(proto_num, f"Unknown({proto_num})")
        captured_data.append({
            'Timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'Source IP': packet[IP].src,
            'Destination IP': packet[IP].dst,
            'Protocol': proto_name,
            'Packet Length': len(packet)
        })
        progress_var.set(f"Captured: {len(captured_data)} packets")
        progress_label.update_idletasks()


def safe_sniff(interface, packet_count):                # for safe sniffing and error handling
    global captured_data
    try:
        sniff(iface=interface, prn=packet_callback, count=packet_count, store=False)
        messagebox.showinfo("Success", f"Captured {packet_count} packets.")
        progress_var.set("Sniffing complete.")
    except PermissionError:
        messagebox.showerror("Permission Denied", "Run the program with administrator/root privileges.")
        progress_var.set("Permission error.")
    except OSError as e:
        messagebox.showerror("Interface Error", f"Network interface error: {e}")
        progress_var.set("Interface error.")
    except Exception as e:
        messagebox.showerror("Sniffing Error", f"Unexpected error:\n{str(e)}")
        progress_var.set("Error occurred.")

def validate_inputs():            # checking for input
    try:
        interface = interface_combo.get().strip()
        packet_count = int(packet_entry.get())
        if not interface:
            raise ValueError("No interface selected")
        return interface, packet_count
    except ValueError:
        messagebox.showerror("Input Error", "Please select a valid interface and enter packet count (integer).")
        return None, None
def threaded_sniff_safe():
    global captured_data
    captured_data = []  # reset previous data

    # Set initial message and progress
    progress_var.set("Starting sniffing...")

    interface, count = validate_inputs()
    if interface is not None and count is not None:
        # Threading the sniff function
        progress_var.set(f"Sniffing {count} packets on {interface}...")
        thread = threading.Thread(target=safe_sniff, args=(interface, count))
        thread.daemon = True  # Optional: allows program to exit even if thread is running
        thread.start()

def browse_file():
    global selected_file_path
    file_path = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV files", "*.csv")])
    if file_path:
        selected_file_path = file_path
        file_entry.config(state='normal')
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)
        file_entry.config(state='readonly')

def save_to_csv():
    if not captured_data:
        messagebox.showwarning("No Data", "No packet data available to save.")
        return
    if not selected_file_path:
        messagebox.showwarning("No File Selected", "Please select a file using 'Browse' before saving.")
        return
    try:
        df = pd.DataFrame(captured_data)
        df.to_csv(selected_file_path, index=False)
        messagebox.showinfo("Success", f"Data saved to: {selected_file_path}")
    except Exception as e:
        messagebox.showerror("File Error", f"Could not save file:\n{e}")

def visualize_data():                   # visualize the sesssion traffic in bar graph
    if not captured_data:
        messagebox.showwarning("No Data", "No packet data to visualize.")
        return
    try:
        df = pd.DataFrame(captured_data)
        plt.figure(figsize=(8, 5))
        sns.set(style="whitegrid")
        ax = sns.countplot(x='Protocol', data=df, palette='Blues_d')
        ax.set_title("Protocol Distribution")
        ax.set_xlabel("Protocol")
        ax.set_ylabel("Number of Packets")
        plt.tight_layout()
        plt.show()
    except Exception as e:
        messagebox.showerror("Visualization Error", f"Could not generate plot:\n{e}")

# Get available interfaces
interfaces = get_if_list()

# GUI setup
root = tk.Tk()
root.title("Network Traffic Analysis Tool")
root.geometry("500x450")

tk.Label(root, text="Select Network Interface:").pack(pady=5)
interface_combo = ttk.Combobox(root, values=interfaces, width=50)
if interfaces:
    interface_combo.current(0)
interface_combo.pack(pady=5)

tk.Label(root, text="Number of Packets to Capture:").pack(pady=5)
packet_entry = tk.Entry(root)
packet_entry.insert(0, "20")
packet_entry.pack(pady=5)

start_btn = tk.Button(root, text="Start Sniffing", command=threaded_sniff_safe)
start_btn.pack(pady=10)

# Progress label
progress_var = tk.StringVar()
progress_var.set("Status : Idle")
progress_label = tk.Label(root, textvariable=progress_var)
progress_label.pack(pady=5)

# File selection section
tk.Label(root, text="CSV File Path:").pack(pady=5)
file_frame = tk.Frame(root)
file_frame.pack(pady=5)

file_entry = tk.Entry(file_frame, width=40, state='readonly')
file_entry.pack(side=tk.LEFT, padx=5)

browse_btn = tk.Button(file_frame, text="Browse", command=browse_file)
browse_btn.pack(side=tk.LEFT)

save_btn = tk.Button(root, text="Save to CSV", command=save_to_csv)
save_btn.pack(pady=10)

viz_btn = tk.Button(root, text="Visualize Traffic", command=visualize_data)
viz_btn.pack(pady=10)

root.mainloop()



