import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
import threading
import queue
from datetime import datetime

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        self.root.geometry("900x600")
        self.root.minsize(800, 500)
        
        self.sniffing = False
        self.packet_queue = queue.Queue()
        self.filter = ""
        self.packet_count = 0
        self.max_packets = 1000
        self.packets = {}  # Dictionary to store packet objects
        
        self.create_widgets()
        self.setup_layout()
        
        self.process_thread = threading.Thread(target=self.process_packets, daemon=True)
        self.process_thread.start()
    
    def create_widgets(self):
        # Control Frame
        self.control_frame = ttk.LabelFrame(self.root, text="Controls", padding=10)
        
        self.start_button = ttk.Button(self.control_frame, text="Start Sniffing", command=self.start_sniffing)
        self.stop_button = ttk.Button(self.control_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.clear_button = ttk.Button(self.control_frame, text="Clear", command=self.clear_output)
        
        self.interface_label = ttk.Label(self.control_frame, text="Interface:")
        self.interface_combo = ttk.Combobox(self.control_frame, values=self.get_interfaces())
        if self.interface_combo['values']:
            self.interface_combo.current(0)
        
        self.filter_label = ttk.Label(self.control_frame, text="Filter:")
        self.filter_entry = ttk.Entry(self.control_frame)
        
        # Packet Display Frame
        self.display_frame = ttk.LabelFrame(self.root, text="Captured Packets", padding=10)
        
        self.tree = ttk.Treeview(self.display_frame, columns=("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"), show="headings")
        
        # Configure treeview columns
        for col in ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"):
            self.tree.heading(col, text=col, anchor=tk.W)
            self.tree.column(col, width=100, minwidth=50)
        
        # Add scrollbars
        self.tree_scroll_y = ttk.Scrollbar(self.display_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree_scroll_x = ttk.Scrollbar(self.display_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=self.tree_scroll_y.set, xscrollcommand=self.tree_scroll_x.set)
        
        # Packet Details Frame
        self.details_frame = ttk.LabelFrame(self.root, text="Packet Details", padding=10)
        self.details_text = scrolledtext.ScrolledText(self.details_frame, wrap=tk.WORD, width=80, height=10)
        
        # Bind treeview selection event
        self.tree.bind('<<TreeviewSelect>>', self.on_packet_select)
    
    def on_packet_select(self, event):
        """Handle packet selection event"""
        selected_item = self.tree.focus()
        if not selected_item:
            return
            
        item = self.tree.item(selected_item)
        packet_number = item['values'][0]
        
        if packet_number not in self.packets:
            return
            
        packet = self.packets[packet_number]
        self.show_packet_details(packet)

    def show_packet_details(self, packet):
        """Show detailed packet information"""
        self.details_text.delete(1.0, tk.END)
        
        # Show packet summary
        self.details_text.insert(tk.END, "=== Packet Summary ===\n")
        self.details_text.insert(tk.END, f"Time: {datetime.fromtimestamp(packet.time)}\n")
        
        if Ether in packet:
            self.details_text.insert(tk.END, f"Source MAC: {packet[Ether].src}\n")
            self.details_text.insert(tk.END, f"Dest MAC: {packet[Ether].dst}\n")
        
        if IP in packet:
            self.details_text.insert(tk.END, f"Source IP: {packet[IP].src}\n")
            self.details_text.insert(tk.END, f"Destination IP: {packet[IP].dst}\n")
            self.details_text.insert(tk.END, f"Protocol: {packet[IP].proto}\n")
            self.details_text.insert(tk.END, f"TTL: {packet[IP].ttl}\n")
            self.details_text.insert(tk.END, f"Length: {len(packet)} bytes\n")
        
        if TCP in packet:
            self.details_text.insert(tk.END, "\n=== TCP Details ===\n")
            self.details_text.insert(tk.END, f"Source Port: {packet[TCP].sport}\n")
            self.details_text.insert(tk.END, f"Dest Port: {packet[TCP].dport}\n")
            self.details_text.insert(tk.END, f"Flags: {packet[TCP].flags}\n")
            self.details_text.insert(tk.END, f"Seq: {packet[TCP].seq}\n")
            self.details_text.insert(tk.END, f"Ack: {packet[TCP].ack}\n")
            self.details_text.insert(tk.END, f"Window: {packet[TCP].window}\n")
            
            # Show payload if present
            if packet[TCP].payload:
                payload = bytes(packet[TCP].payload)
                try:
                    decoded_payload = payload.decode('utf-8', errors='replace')
                    self.details_text.insert(tk.END, "\n=== Payload (UTF-8) ===\n")
                    self.details_text.insert(tk.END, decoded_payload[:500])  # Limit to 500 chars
                    if len(decoded_payload) > 500:
                        self.details_text.insert(tk.END, "\n[...truncated...]")
                except:
                    self.details_text.insert(tk.END, "\n=== Raw Payload ===\n")
                    self.details_text.insert(tk.END, str(payload[:100]))  # Show first 100 bytes
        
        elif UDP in packet:
            self.details_text.insert(tk.END, "\n=== UDP Details ===\n")
            self.details_text.insert(tk.END, f"Source Port: {packet[UDP].sport}\n")
            self.details_text.insert(tk.END, f"Dest Port: {packet[UDP].dport}\n")
        
        # Show hex dump
        self.details_text.insert(tk.END, "\n\n=== Hex Dump ===\n")
        hexdump = self.format_hexdump(packet)
        self.details_text.insert(tk.END, hexdump)

    def format_hexdump(self, packet):
        """Format hex dump in a readable way"""
        hex_lines = []
        raw_bytes = raw(packet)
        for i in range(0, len(raw_bytes), 16):
            chunk = raw_bytes[i:i+16]
            hex_str = ' '.join(f'{b:02x}' for b in chunk)
            ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            hex_lines.append(f"{i:04x}  {hex_str.ljust(47)}  {ascii_str}")
        return '\n'.join(hex_lines)

    def get_interfaces(self):
        """Get available network interfaces"""
        try:
            # For newer versions of Scapy (2.4.0+)
            from scapy.interfaces import get_working_ifaces
            return [iface.name for iface in get_working_ifaces()]
        except ImportError:
            # Fallback for older versions
            from scapy.arch.common import get_if_list
            return get_if_list()

    def setup_layout(self):
        """Setup the GUI layout"""
        # Control Frame Layout
        self.control_frame.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        
        self.interface_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.interface_combo.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        self.filter_label.grid(row=0, column=2, padx=5, pady=5, sticky="e")
        self.filter_entry.grid(row=0, column=3, padx=5, pady=5, sticky="ew")
        
        self.start_button.grid(row=0, column=4, padx=5, pady=5)
        self.stop_button.grid(row=0, column=5, padx=5, pady=5)
        self.clear_button.grid(row=0, column=6, padx=5, pady=5)
        
        # Display Frame Layout
        self.display_frame.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
        self.tree.grid(row=0, column=0, sticky="nsew")
        self.tree_scroll_y.grid(row=0, column=1, sticky="ns")
        self.tree_scroll_x.grid(row=1, column=0, sticky="ew")
        
        # Details Frame Layout
        self.details_frame.grid(row=2, column=0, padx=5, pady=5, sticky="nsew")
        self.details_text.grid(row=0, column=0, sticky="nsew")
        
        # Configure grid weights
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)
        
        self.display_frame.grid_columnconfigure(0, weight=1)
        self.display_frame.grid_rowconfigure(0, weight=1)
        
        self.details_frame.grid_columnconfigure(0, weight=1)
        self.details_frame.grid_rowconfigure(0, weight=1)

    def start_sniffing(self):
        """Start packet capture"""
        if self.sniffing:
            return
            
        interface = self.interface_combo.get()
        if not interface:
            messagebox.showerror("Error", "Please select a network interface")
            return
            
        self.filter = self.filter_entry.get()
        
        self.sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # Clear previous packets if any
        self.clear_output()
        
        # Start sniffing in a separate thread
        sniff_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        sniff_thread.start()
    
    def stop_sniffing(self):
        """Stop packet capture"""
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
    
    def clear_output(self):
        """Clear captured packets"""
        self.tree.delete(*self.tree.get_children())
        self.details_text.delete(1.0, tk.END)
        self.packet_count = 0
        self.packets = {}
    
    def sniff_packets(self):
        """Sniff packets and add them to the queue"""
        try:
            sniff(iface=self.interface_combo.get(), 
                 filter=self.filter, 
                 prn=self.process_packet, 
                 stop_filter=lambda x: not self.sniffing)
        except Exception as e:
            self.packet_queue.put(("error", str(e)))
    
    def process_packet(self, packet):
        """Process each captured packet and add to queue"""
        if not self.sniffing:
            return False
            
        if self.packet_count >= self.max_packets:
            self.packet_queue.put(("error", "Maximum packet limit reached. Stopping capture."))
            self.stop_sniffing()
            return False
            
        self.packet_queue.put(("packet", packet))
        return True
    
    def process_packets(self):
        """Process packets from the queue and update GUI"""
        while True:
            try:
                item_type, data = self.packet_queue.get(timeout=0.1)
                
                if item_type == "packet":
                    self.packet_count += 1
                    self.add_packet_to_tree(data)
                elif item_type == "error":
                    self.root.after(0, self.show_error, data)
                    
            except queue.Empty:
                continue
    
    def add_packet_to_tree(self, packet):
        """Add packet information to the treeview"""
        packet_time = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        packet_number = self.packet_count
        
        # Get basic packet info
        src = "N/A"
        dst = "N/A"
        protocol = "N/A"
        length = len(packet)
        info = ""
        
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            protocol = packet[IP].proto
            
            if protocol == 6 and TCP in packet:  # TCP
                protocol = "TCP"
                info = f"{packet[TCP].sport} -> {packet[TCP].dport} [{packet[TCP].flags}]"
            elif protocol == 17 and UDP in packet:  # UDP
                protocol = "UDP"
                info = f"{packet[UDP].sport} -> {packet[UDP].dport}"
            elif protocol == 1:  # ICMP
                protocol = "ICMP"
                info = "ICMP"
            else:
                protocol = f"IP ({protocol})"
        
        # Add to treeview
        values = (packet_number, packet_time, src, dst, protocol, length, info)
        
        self.root.after(0, self._add_tree_item, values, packet)
    
    def _add_tree_item(self, values, packet):
        """Thread-safe method to add item to treeview"""
        item = self.tree.insert("", tk.END, values=values)
        self.tree.see(item)
        
        # Store the packet object in our dictionary
        self.packets[values[0]] = packet
    
    def show_error(self, message):
        """Show error message"""
        messagebox.showerror("Error", message)
        self.stop_sniffing()

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()