# 🕵️‍♂️ The Interrogator

A lightweight PowerShell script to quickly identify **Centrally Managed Computers User & Groups (CUGs)** within an Active Directory domain.

Designed to operate even from **non-domain-joined machines**, provided DNS resolution to the domain controllers is possible (e.g., over VPN or jumpbox). Ideal for auditors, security engineers, or object owners who need to enumerate AD groups from a lightly integrated or external environment.

---

## 📦 Features

- 🔍 Discover CUGs across multiple trusted domains
- 💻 Works without domain joined assets
- 🛠 Auto-detects and installs missing AD modules (with fallback support)
- 💾 **Save presets** for commonly inspected items—great for objects you own.
- 📁 Configuration persistence via JSON (e.g. last used domain, credentials (Except your password.... Obviously))
- 📡 DNS-based discovery of domain controllers
- ✅ Supports full prettified output
- 👤 Detects managers, secretaries, and group descriptions

---

## 🚀 Usage

### 🔧 Setup (first-time only)

1. Run `installer.ps1`  
   - This will configure your environment
   - Optionally installs the Active Directory module
   - Stores preferences in a local JSON file
<img width="1076" height="889" alt="image" src="https://github.com/user-attachments/assets/af2e5ad5-3a08-4d34-90e8-a4b69e00f9f8" />



### 🛠 Running the Script

```powershell
.\interrogator.ps1
```
#### Classy Screenshots
<img width="1092" height="658" alt="image" src="https://github.com/user-attachments/assets/d22ebfdd-0b0f-467e-afcf-0e4ab75fa7a0" />
<img width="1090" height="439" alt="image" src="https://github.com/user-attachments/assets/5d1df8be-ff50-4d42-b9e1-3c740b8e6746" />
<img width="757" height="368" alt="image" src="https://github.com/user-attachments/assets/c9dc5b55-aaf7-4489-ab7a-7f91d9db8c4b" />

#### User Checking
<img width="1132" height="395" alt="image" src="https://github.com/user-attachments/assets/75178706-429b-4ff0-b99f-e0d285372dd1" />

#### Asset Checking
<img width="609" height="449" alt="image" src="https://github.com/user-attachments/assets/524e6cf8-b8ea-4dad-8752-b8adeef6bd76" />

---

## 📌 TODO / Roadmap

- ✅ **Highlight Domain Admin accounts**  
  Clearly flag any accounts that are members of `Domain Admins`, `Enterprise Admins`, or other privileged groups. **<-- Currently In Testing**

- 🔓 **Detect weak permissions on users or groups**  
  Alert if `GenericAll`, `GenericWrite`, `WriteOwner`, `WriteDACL`, or similar ACEs are found in the user's ACL.

- 📎 **Group nesting and indirect membership**  
  Trace indirect group membership (e.g. via nested groups) to uncover hidden privilege paths.

- 🧠 **Security scoring**  
  Assign a basic risk score based on membership, permissions, exposure, and naming patterns (e.g. `svc_`, `admin_`, `helpdesk_`).

- 🔁 **Interactive "follow path" navigation**  
  Allow selecting a group member and pivoting directly into their object inspection.

- 📤 **Export results to CSV or JSON**  
  Output group/user details for integration into wider reporting or data pipelines.

- 🪄 **BloodHound-ready mode**  
  Export select objects (e.g., with privileges) in a format readable by BloodHound or compatible with `neo4j`.

---

