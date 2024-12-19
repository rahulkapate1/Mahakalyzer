# Mahakalyzer

**Mahakalyzer** is an advanced malware analysis tool designed to provide deep insights into malicious software. It enables cybersecurity professionals to identify, analyze, and mitigate malware threats efficiently.

---

## Features

- **Static Analysis**: Extract metadata, detect packers, and analyze strings from executables.
- **Dynamic Analysis**: Monitor runtime behavior, including API calls, file operations, and network connections.
- **Sandbox Integration**: Execute malware samples in an isolated environment for behavior analysis.
- **Signature Detection**: Identify known malware using an extensive signature database.
- **User-Friendly Interface**: Simplified GUI and command-line interface for quick and effective usage.
- **Supported File Types**:
  - PE files (`.exe`, `.dll`)
  - Office documents (`.docx`, `.xlsx`, `.pptx`, `.doc`, `.xls`, `.ppt`)
  - PDF files (`.pdf`)
  - Scripts (`.js`, `.vbs`, `.ps1`)
  - Archives (`.zip`, `.rar`, `.7z`)
- **Report Generation**: Export analysis reports in PDF formats.

---

## Requirements

To use Mahakalyzer effectively, ensure the following requirements are met:

### System Requirements:
- **Operating System**: Windows 10/11, Linux (Ubuntu/Debian-based), or macOS.
- **Processor**: 64-bit, 2.5 GHz or higher.
- **RAM**: Minimum 4 GB (8 GB recommended).
- **Storage**: At least 500 MB of free space.

### Software Requirements:
- **Python**: Version 3.8 or above.
- **pip**: Python package manager.
- **Optional**: Virtualization software (e.g., VirtualBox) for dynamic analysis in a sandbox.

### Python Dependencies:
All necessary Python packages can be installed using the provided `requirements.txt` file.

```bash
pip install -r requirements.txt
```

---

## Installation

### Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/rahulkapate1/Mahakalyzer.git
   cd Mahakalyzer
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Launch the GUI:
   - For the GUI:
     ```bash
     python Mahakalyzer.py
     ```

---

## Usage

### Graphical User Interface (GUI):

1. Launch the GUI:
   ```bash
   python mahakalyzer_gui.py
   ```
2. Use the intuitive interface to upload files, select analysis types, and generate reports.

---

## Contributing

We welcome contributions from the community! To contribute:

1. Fork the repository.
2. Create a new branch for your feature/bug fix.
3. Commit your changes and push the branch.
4. Create a pull request.

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Contact

For any queries or suggestions:

- **Author**: Rahul Kapate  
- **Email**: [rahulkapate0000@gmail.com](mailto:rahulkapate0000@gmail.com)  
- **Website**: [cybersecurityrahul.in/](https://cybersecurityrahul.in)  
- **LinkedIn**: [linkedin.com/in/rahul-kapate](https://www.linkedin.com/in/rahul-kapate)

Feel free to reach out for feedback or collaboration opportunities!
