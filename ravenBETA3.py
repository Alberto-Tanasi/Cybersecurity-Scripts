import subprocess
import os
import sys
import time

# --- [ TERMINAL COLORS ] ---
G = '\033[92m'  # Green
W = '\033[97m'  # White
D = '\033[90m'  # Grey
R = '\033[91m'  # Red
Y = '\033[93m'  # Yellow
RESET = '\033[0m'

def banner():
    os.system('clear')
    print(f"""
    {W}  ___________________________________________________
     |                                                   |
     |   ____      _     __     __  _____   _   _        |
     |  |  _ \    / \    \ \   / / | ____| | \ | |       |
     |  | |_) |  / _ \    \ \ / /  |  _|   |  \| |       |
     |  |  _ <  / ___ \    \ V /   | |___  | |\  |       |
     |  |_| \_\/_/   \_\    \_/    |_____| |_| \_|       |
     |___________________________________________________|
    {D}
       [ Remote Access & Vulnerability Engine Network ]
    _______________________________________________________
    
                  {G}Developed by: Alberto{RESET}
    """)

# --- [ UTILS ] ---

def get_local_network():
    try:
        cmd = "ip route | grep default | awk '{print $3}' | cut -d. -f1-3"
        prefix = subprocess.check_output(cmd, shell=True).decode().strip()
        return f"{prefix}.0/24"
    except:
        return "192.168.1.0/24"

# --- [ WIRELESS MODULE ] ---

def get_interfaces():
    try:
        raw_data = subprocess.check_output(["iwconfig"], stderr=subprocess.STDOUT).decode()
        ifaces = [line.split()[0] for line in raw_data.split('\n') if "IEEE 802.11" in line or "Mode:Monitor" in line]
        return ifaces
    except:
        return []

def toggle_monitor_mode(interface, action="start"):
    print(f"\n{G}[*] Attempting to {action} monitor mode on {interface}...{RESET}")
    try:
        subprocess.run(["sudo", "airmon-ng", action, interface], check=True)
        time.sleep(2)
        print(f"{G}[+] Operation Successful.{RESET}")
    except Exception as e:
        print(f"{R}[!] Error: Operation failed. {e}{RESET}")
    input(f"\n{D}Press Enter to continue...{RESET}")

def wifi_menu():
    while True:
        banner()
        ifaces = get_interfaces()
        print(f"\n{W}--- Wireless Auditing ---{RESET}")
        if not ifaces:
            print(f"{R}[!] No wireless interfaces detected!{RESET}")
        else:
            for i, iface in enumerate(ifaces):
                print(f" [{G}{i}{RESET}] {iface}")

        print(f"\n [{G}1{RESET}] Enable Monitor Mode")
        print(f" [{G}2{RESET}] Disable Monitor Mode (Stop)")
        print(f" [{G}b{RESET}] Back to Main Menu")
        
        choice = input(f"\n{W}RAVEN-WiFi{RESET} > ")
        
        if choice in ['1', '2'] and ifaces:
            try:
                idx_input = input(f"{W}Select ID (or 'b' to cancel): {RESET}")
                if idx_input.lower() == 'b': continue
                
                idx = int(idx_input)
                if 0 <= idx < len(ifaces):
                    action = "start" if choice == '1' else "stop"
                    toggle_monitor_mode(ifaces[idx], action)
                else:
                    print(f"{R}[!] Error: ID {idx} is out of range.{RESET}")
                    time.sleep(1.5)
            except ValueError:
                print(f"{R}[!] Error: Please enter a valid number.{RESET}")
                time.sleep(1.5)
        elif choice.lower() == 'b':
            break

# --- [ RECON MODULE ] ---

def scan_and_report():
    target_range = get_local_network()
    banner()
    print(f"\n{G}[*] Discovering devices on {target_range}...{RESET}")
    print(f"{D}[*] Running Nmap ARP Discovery...{RESET}")
    
    cmd = f"sudo nmap -sn -PR {target_range} -oG scan_temp.txt"
    try:
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL)
        header = f"{'DEVICE/NAME':<22} | {'IP ADDRESS':<15} | {'MAC ADDRESS':<18}"
        border = "-" * len(header)
        report_data = [header, border]
        
        print(f"\n{W}{header}{RESET}")
        print(f"{D}{border}{RESET}")

        if os.path.exists("scan_temp.txt"):
            with open("scan_temp.txt", "r") as f:
                for line in f:
                    if "Host:" in line and "Status: Up" in line:
                        parts = line.split()
                        ip = parts[1]
                        name = parts[2].replace("(", "").replace(")", "") if "(" in parts[2] else "Unknown"
                        entry = f"{name[:22]:<22} | {ip:<15} | {'(Scan for MAC)':<18}"
                        print(f"{W}{entry}{RESET}")
                        report_data.append(entry)
            
            filename = f"RAVEN_Scan_{int(time.time())}.txt"
            with open(filename, "w") as f:
                f.write(f"RAVEN NETWORK REPORT\n{'='*20}\n" + "\n".join(report_data))
            print(f"\n{G}[+] Report saved: {filename}{RESET}")
            os.remove("scan_temp.txt")
        else:
            print(f"{R}[!] Scan failed to generate data.{RESET}")
    except Exception as e:
        print(f"{R}[!] An error occurred: {e}{RESET}")
    
    input(f"\n{D}Press Enter to return...{RESET}")

def run_manual_nmap():
    banner()
    print(f"\n{W}--- Manual Nmap Scan ---{RESET}")
    target = input(f"{Y}Enter Target IP/Domain (or 'b' to go back): {RESET}")
    
    if target.lower() == 'b':
        return

    print(f"\n{W}Select Scan Intensity:{RESET}")
    print(f" [{G}1{RESET}] Quick Scan")
    print(f" [{G}2{RESET}] Service Version Detection (-sV)")
    print(f" [{G}3{RESET}] Aggressive Stealth Scan (-A -T4)")
    print(f" [{G}b{RESET}] Cancel and Go Back")
    
    intensity = input(f"\n{W}RAVEN-Nmap{RESET} > ")
    if intensity.lower() == 'b': return

    flags = "-F"
    if intensity == '2': flags = "-sV"
    elif intensity == '3': flags = "-A -T4"
    elif intensity not in ['1', '2', '3']:
        print(f"{R}[!] Invalid selection, defaulting to Quick Scan.{RESET}")
        time.sleep(1)

    print(f"\n{G}[*] Launching Nmap...{RESET}\n")
    try:
        subprocess.run(f"sudo nmap {flags} {target}", shell=True)
    except KeyboardInterrupt:
        print(f"\n{R}[!] Scan stopped by user.{RESET}")
    input(f"\n{D}Press Enter to return...{RESET}")

def recon_menu():
    while True:
        banner()
        print(f"\n{W}--- Network Reconnaissance ---{RESET}")
        print(f" [{G}1{RESET}] Auto-Discover Network (Chart & File)")
        print(f" [{G}2{RESET}] Manual Target Scan (Nmap)")
        print(f" [{G}b{RESET}] Back")

        choice = input(f"\n{W}RAVEN-Recon{RESET} > ")
        if choice == '1': scan_and_report()
        elif choice == '2': run_manual_nmap()
        elif choice == 'b': break

# --- [ MAIN ENGINE ] ---

def main_menu():
    while True:
        banner()
        print(f" [{G}1{RESET}] Wireless Auditing        (WiFi/Deauth)")
        print(f" [{G}2{RESET}] Network Reconnaissance  (Nmap/Discovery)")
        print(f" [{G}3{RESET}] Payload Orchestration   (WIP)")
        print(f" [{G}0{RESET}] Exit System")
        
        choice = input(f"\n{W}RAVEN{RESET} > ")
        if choice == '1': wifi_menu()
        elif choice == '2': recon_menu()
        elif choice == '0':
            print(f"\n{G}[*] Mission Complete. Closing RAVEN.{RESET}")
            break
        else:
            print(f"{R}[!] '{choice}' is not a valid option.{RESET}")
            time.sleep(1)

if __name__ == "__main__":
    if os.getuid() != 0:
        print(f"\n{R}[!] Error: RAVEN requires root. Use 'sudo python3 raven.py'{RESET}")
        sys.exit()
    main_menu()
