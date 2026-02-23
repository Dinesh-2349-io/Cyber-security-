import psutil
import socket
import requests
import os
import time
import threading
from datetime import datetime
from colorama import Fore, init
init()

LOG_FILE = "security_log.txt"
SUSPICIOUS_IPS = []
PROCESS_LIMIT = 200
UNKNOWN_CONNECTION_LIMIT = 5
RISK_SCORE = 0

def log_event(event):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} : {event}\n")

def firewall_status():
    print(Fore.CYAN+"\nChecking Firewall Status...\n")
    try:
        if os.name == 'nt':
            os.system("netsh advfirewall show allprofiles")
        else:
            os.system("sudo ufw status")
        log_event("Firewall checked")
    except:
        print("Firewall check failed")

def get_hostname_ip():
    host = socket.gethostname()
    ip = socket.gethostbyname(host)
    print(f"Hostname: {host}")
    print(f"IP: {ip}")
    log_event(f"Hostname/IP checked {host}/{ip}")

def check_internet():
    try:
        requests.get("https://www.google.com",timeout=5)
        print(Fore.GREEN+"Internet Connected")
        log_event("Internet Connected")
    except:
        print(Fore.RED+"No Internet Connection")
        log_event("Internet Disconnected")

def running_processes():
    count=0
    print(Fore.YELLOW+"\nRunning Processes\n")
    for proc in psutil.process_iter(['pid','name']):
        print(proc.info)
        count+=1
    log_event(f"Process count: {count}")
    if count>PROCESS_LIMIT:
        risk_update(2)

def network_connections():
    unknown=0
    print(Fore.BLUE+"\nActive Connections\n")
    for conn in psutil.net_connections(kind='inet'):
        if conn.raddr:
            ip=conn.raddr.ip
            print(f"Connected to {ip}")
            log_event(f"Connection {ip}")
            if not ip.startswith("192.") and not ip.startswith("127."):
                unknown+=1
    if unknown>UNKNOWN_CONNECTION_LIMIT:
        print(Fore.RED+"Too many unknown IPs!")
        risk_update(3)

def port_scan():
    host='127.0.0.1'
    print(Fore.MAGENTA+"\nScanning Ports...\n")
    for port in range(1,1025):
        sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result=sock.connect_ex((host,port))
        if result==0:
            print(f"Port {port} OPEN")
            log_event(f"Port {port} open")
        sock.close()

def bandwidth_usage():
    net=psutil.net_io_counters()
    sent=net.bytes_sent/(1024*1024)
    recv=net.bytes_recv/(1024*1024)
    print(f"Sent: {sent:.2f} MB")
    print(f"Recv: {recv:.2f} MB")
    log_event("Bandwidth monitored")
    if sent>500 or recv>500:
        risk_update(2)

def url_scanner():
    url=input("Enter URL: ")
    words=["login","bank","secure","verify","update"]
    for w in words:
        if w in url:
            print(Fore.RED+"Phishing Suspicion!")
            log_event(f"Suspicious URL {url}")
            risk_update(3)
            return
    print(Fore.GREEN+"URL seems safe")
    log_event(f"URL safe {url}")

def suspicious_process():
    bad=["keylogger","trojan","hack","spy"]
    for proc in psutil.process_iter(['name']):
        name=proc.info['name']
        for b in bad:
            if b in name.lower():
                print(Fore.RED+f"Suspicious Process {name}")
                log_event(f"Bad process {name}")
                risk_update(4)

def risk_update(val):
    global RISK_SCORE
    RISK_SCORE+=val
    print(Fore.RED+f"Risk Score Increased: {RISK_SCORE}")
    log_event(f"Risk Score {RISK_SCORE}")

def weekly_risk_report():
    print("\nSecurity Risk Score:",RISK_SCORE)
    if RISK_SCORE<5:
        print("System Secure")
    elif RISK_SCORE<10:
        print("Moderate Risk")
    else:
        print("High Risk!")
    log_event("Risk evaluated")

def background_monitor():
    while True:
        network_connections()
        suspicious_process()
        time.sleep(60)

def start_background():
    t=threading.Thread(target=background_monitor)
    t.daemon=True
    t.start()

def menu():
    start_background()
    while True:
        print("""
====== CYBER SECURITY MONITOR ======
1.Firewall Status
2.Hostname/IP
3.Check Internet
4.Running Processes
5.Network Connections
6.Port Scan
7.Bandwidth Usage
8.URL Scan
9.Suspicious Process Check
10.Weekly Risk Report
11.Exit
===================================
""")
        ch=input("Choice: ")
        if ch=='1':firewall_status()
        elif ch=='2':get_hostname_ip()
        elif ch=='3':check_internet()
        elif ch=='4':running_processes()
        elif ch=='5':network_connections()
        elif ch=='6':port_scan()
        elif ch=='7':bandwidth_usage()
        elif ch=='8':url_scanner()
        elif ch=='9':suspicious_process()
        elif ch=='10':weekly_risk_report()
        elif ch=='11':break
        else:print("Invalid")

menu()
