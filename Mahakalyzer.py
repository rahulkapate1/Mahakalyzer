import os
import hashlib
import pefile
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from fpdf import FPDF
from datetime import datetime
import re

# Predefined suspicious APIs list
SUSPICIOUS_APIS = ["LoadLibrary", "GetProcAddress", "VirtualAlloc", "WriteProcessMemory"]

def calculate_hash(file_path):
    """Calculate MD5, SHA1, and SHA256 hashes of a file."""
    hashes = {}
    hash_types = {'md5': hashlib.md5(), 'sha1': hashlib.sha1(), 'sha256': hashlib.sha256()}
    with open(file_path, 'rb') as f:
        data = f.read()
        for name, hash_obj in hash_types.items():
            hash_obj.update(data)
            hashes[name] = hash_obj.hexdigest()
    return hashes

def analyze_pe_headers(file_path):
    """Analyze PE (Portable Executable) headers to extract important metadata."""
    headers = {}
    try:
        pe = pefile.PE(file_path)
        headers = {
            "Entry Point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "Image Base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "Subsystem": pefile.SUBSYSTEM_TYPE[pe.OPTIONAL_HEADER.Subsystem],
            "Sections": [
                {
                    "Name": section.Name.decode().strip(),
                    "Virtual Address": hex(section.VirtualAddress),
                    "Size": section.SizeOfRawData,
                    "Permissions": f"R{'' if not section.Characteristics & 0x40000000 else 'W'}{'' if not section.Characteristics & 0x20000000 else 'E'}"
                } for section in pe.sections
            ],
            "Imports": {entry.dll.decode(): [imp.name.decode() for imp in entry.imports] for entry in pe.DIRECTORY_ENTRY_IMPORT},
            "Suspicious APIs": find_suspicious_apis(pe)
        }
    except Exception as e:
        headers = {"Error": str(e)}
    return headers

def find_suspicious_apis(pe):
    """Identify suspicious API calls in imports."""
    suspicious_apis = []
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name and any(api in imp.name.decode() for api in SUSPICIOUS_APIS):
                    suspicious_apis.append(f"{imp.name.decode()} from {entry.dll.decode()}")
    except Exception:
        pass
    return suspicious_apis

def extract_strings(file_path):
    """Extract printable ASCII and Unicode strings from the binary file."""
    with open(file_path, 'rb') as f:
        data = f.read()
    ascii_strings = re.findall(b"[ -~]{4,}", data)
    unicode_strings = re.findall(b"(?:[ -~]\x00){4,}", data)
    return [s.decode() for s in ascii_strings] + [s.decode("utf-16le") for s in unicode_strings]

def find_ip_urls(strings):
    """Identify any IP addresses or URLs in extracted strings."""
    ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", ' '.join(strings))
    urls = re.findall(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", ' '.join(strings))
    return {"IPs": ips, "URLs": urls}

def hex_dump(file_path, length=256):
    """Generate a hex dump of the file (first 256 bytes by default)."""
    with open(file_path, 'rb') as f:
        data = f.read(length)
    return " ".join(f"{b:02x}" for b in data)

def analyze_file(file_path):
    """Run a static analysis on the file."""
    file_info = {
        "File Name": os.path.basename(file_path),
        "File Size": os.path.getsize(file_path),
        "Last Modified": datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
    }

    # Calculate hashes
    file_info.update(calculate_hash(file_path))

    # Analyze PE headers
    file_info["PE Headers"] = analyze_pe_headers(file_path)

    # Hex dump
    file_info["Hex Dump"] = hex_dump(file_path)

    # Extract strings and check for IPs and URLs
    strings = extract_strings(file_path)
    file_info["Strings"] = strings[:20]  # First 20 strings for preview
    file_info["Network Indicators"] = find_ip_urls(strings)

    return file_info

def generate_pdf_report(file_info, file_path):
    """Generate and save report as a PDF file with enhanced styling."""
    report_name = os.path.splitext(file_path)[0] + "_analysis_report.pdf"
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    
    # Title and Developer Information
    pdf.set_font("Arial", style="B", size=16)
    pdf.cell(200, 10, txt="Advanced Malware Analysis Report", ln=True, align="C")
    
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Developer: Rahul Kapate", ln=True, align="C")
    pdf.cell(200, 10, txt="Email: rahulkapate0000@gmail.com", ln=True, align="C")
    
    pdf.cell(200, 10, txt="Website: rahulkapate.online", ln=True, align="C")
    
    pdf.ln(10)  # Add space before report content

    # Report Content Header
    pdf.set_font("Arial", style="B", size=14)
    pdf.cell(200, 10, txt="File Analysis Summary", ln=True)
    pdf.ln(5)  # Space between headers

    # File Information Details
    for key, value in file_info.items():
        pdf.set_font("Arial", style="B", size=12)
        pdf.cell(200, 10, txt=f"{key}:", ln=True)
        pdf.set_font("Arial", size=10)

        # Handle dictionaries and lists for clean presentation
        if isinstance(value, dict):
            for item, detail in value.items():
                pdf.cell(200, 10, txt=f"  {item}: {detail}", ln=True)
        elif isinstance(value, list):
            for item in value:
                pdf.cell(200, 10, txt=f"  {item}", ln=True)
        else:
            pdf.cell(200, 10, txt=f"{value}", ln=True)

        pdf.ln(5)  # Add space between sections

    # Save PDF file
    pdf.output(report_name)
    messagebox.showinfo("Report Saved", f"Report saved as: {report_name}")

def display_analysis(file_info):
    """Display analysis results on canvas."""
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, "Malware Analysis Report\n\n")
    
    for key, value in file_info.items():
        output_text.insert(tk.END, f"{key}:\n", "header")
        if isinstance(value, dict) or isinstance(value, list):
            for item in value:
                output_text.insert(tk.END, f"  {item}: {value[item]}\n" if isinstance(value, dict) else f"  {item}\n")
        else:
            output_text.insert(tk.END, f"{value}\n")
        output_text.insert(tk.END, "\n")

def select_file():
    """Open file dialog to select a file for analysis."""
    file_path = filedialog.askopenfilename(filetypes=[("Executable files", "*.exe"), ("All files", "*.*")])
    if file_path:
        file_info = analyze_file(file_path)
        display_analysis(file_info)
        report_button.config(command=lambda: generate_pdf_report(file_info, file_path), state=tk.NORMAL)

def show_intro():
    """Display introductory information about the tool."""
    intro_frame.pack_forget()  # Hide the introduction frame
    main_frame.pack(fill=tk.BOTH, expand=True)  # Show the main analysis interface

# GUI Setup
root = tk.Tk()
root.title("Advanced Malware Analysis Tool")
root.geometry("800x600")
root.configure(bg="#2E2E2E")

intro_frame = tk.Frame(root, bg="#2E2E2E")
intro_frame.pack(pady=20)

tk.Label(intro_frame, text="MAHAKALYZER", bg="#2E2E2E", fg="#FFFFFF", font=("Arial", 50)).pack(pady=60)
tk.Label(intro_frame, text="⁃Developer: Rahul Kapate", bg="#2E2E2E", fg="#FFFFFF", font=("Arial", 14)).pack(pady=5)
tk.Label(intro_frame, text="⁃Email: rahulkapate0000@gmail.com", bg="#2E2E2E", fg="#FFFFFF", font=("Arial", 14)).pack(pady=5)
#tk.Label(intro_frame, text="⁃Contact No: 7058871282", bg="#2E2E2E", fg="#FFFFFF", font=("Arial", 14)).pack(pady=5)
tk.Label(intro_frame, text="⁃Website: cybersecurityrahul.in", bg="#2E2E2E", fg="#FFFFFF", font=("Arial", 14)).pack(pady=5)
tk.Button(intro_frame, text="Proceed to Analysis", command=show_intro, bg="#4D4D4D", fg="#FFFFFF").pack(pady=10)

main_frame = tk.Frame(root, bg="#2E2E2E")
output_text = scrolledtext.ScrolledText(main_frame, width=100, height=30, font=("Courier", 10), bg="#3E3E3E", fg="#FFFFFF", insertbackground='white')
output_text.tag_configure("header", font=("Courier", 10, "bold"), foreground="#FFFFFF")
output_text.pack(pady=10)

file_button = tk.Button(main_frame, text="Select File for Analysis", command=select_file, width=30, font=("Arial", 12), bg="#4D4D4D", fg="#FFFFFF")
file_button.pack(pady=10)

report_button = tk.Button(main_frame, text="Export Report as PDF", command=lambda: None, width=30, font=("Arial", 12), state=tk.DISABLED, bg="#4D4D4D", fg="#FFFFFF")
report_button.pack(pady=10)

root.mainloop()
