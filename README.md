# AWS DNS Lab

A comprehensive AWS DNS laboratory setup that demonstrates:
1. Primary and secondary DNS servers with BIND
2. Zone transfer configuration between DNS servers
3. Firewall configuration with proper access controls
4. DNS monitoring service with email notifications
5. Email system for alert notifications (SMTP/IMAP/IMAPS)

## Overview

This lab creates a complete DNS infrastructure in AWS us-east-1 region:
- **Primary DNS Server** (10.0.1.0/24): BIND9 with authoritative zones
- **Secondary DNS Server** (10.0.2.0/24): BIND9 with zone transfers from primary
- **Monitoring Server** (10.0.1.0/24): Email alerts and DNS health monitoring

## Prerequisites

- Python 3.7+
- [AWS account](https://aws.amazon.com/) with appropriate permissions
- AWS credentials configured (via AWS CLI, environment variables, or IAM roles)

## Installation

1. Clone the lab:
   ```bash
   git clone https://github.com/B4SEE/SPS.git  
   cd SPS/
   ```

2. Install required Python modules:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure AWS credentials in lab.py:
   ```python
   # Update these values with your AWS credentials
   self.access_key = "YOUR_ACCESS_KEY"
   self.secret_key = "YOUR_SECRET_KEY"
   ```

## Quick Start

### 1. Configure the Lab
```bash
python lab.py --configure
```
This will:
- Create VPC with subnets for DNS servers
- Launch primary and secondary DNS instances
- Configure BIND9 with zone files
- Set up monitoring server with email alerts
- Configure security groups (firewalls)

### 2. Test the Configuration
```bash
python lab.py --test
```
This will:
- Automatically start instances if they're stopped
- Test DNS resolution on both servers
- Verify zone transfer functionality
- Test monitoring and email systems
- Generate comprehensive test report

### 3. Check Status
```bash
python lab.py --status
```
Shows current infrastructure status, IP addresses, and DNS testing commands.

## Advanced Usage

### Instance Management

**Start Stopped Instances:**
```bash
python lab.py --start
```

**Stop Running Instances:**
```bash
python lab.py --stop
```

> [!TIP]
> You can stop instances via AWS Management Console to save costs. The `--test` command will automatically start them when needed.

### Cleanup

**Clean Up All Resources:**
```bash
python lab.py --cleanup
```

**Force Cleanup (removes all DNS lab VPCs):**
```bash
python lab.py --force-cleanup
```

## DNS Configuration

The DNS servers are configured with the following zones and records:

### Forward Zone (sps)
- **www.zkouska.sps** → 192.168.100.100 (A record)
- **www.lab.sps** → 192.168.100.1 (A record)
- **mail.lab.sps** → www.lab.sps (CNAME record)
- **lab.sps** → 10 mail.lab.sps (MX record)

### Reverse Zone (192.168.100.0/24)
- **100.100.168.192.in-addr.arpa** → www.zkouska.sps (PTR record)
- **1.100.168.192.in-addr.arpa** → www.lab.sps (PTR record)

### Zone Transfer
- Primary DNS server provides zones to secondary via AXFR
- Secondary DNS automatically updates from primary

## Email System Configuration

The monitoring server includes an email system with:

- **SMTP Server:** Port 25 (Postfix)
- **IMAP Server:** Port 143 (Dovecot)
- **IMAPS Server:** Port 993 (Dovecot with SSL)
- **Username:** `admin@dnslab.local`
- **Password:** `DNSLab123!`
- **Domain:** `dnslab.local`

### Email Alert Messages
- **Primary only down:** "WARNING nefunguje primarni DNS server"
- **Secondary only down:** "WARNING nefunguje sekundarni DNS server"
- **Both servers down:** "CRITICAL nefunguje DNS sluzba"

## Lab Requirements Fulfillment

This lab meets all specified requirements:

### 1. ✅ Primary and Secondary DNS Servers
- BIND9 configured on both servers
- Primary serves authoritative zones
- Secondary receives zone transfers from primary
- Both servers resolve DNS queries

### 2. ✅ Zone Transfer Configuration
- Primary DNS configured to allow zone transfers
- Secondary DNS configured to request zone updates
- Automatic synchronization between servers
- AXFR (full zone transfer) functionality

### 3. ✅ Firewall Configuration
- Security groups configured as firewalls
- Primary DNS: Full access (SSH, DNS)
- Secondary DNS: SSH restricted to Primary DNS security group
- Monitoring server: SSH, SMTP, HTTP access
- DNS ports (53) properly opened

### 4. ✅ DNS Monitoring Service
- Automated monitoring script runs every 2 minutes
- Checks both primary and secondary DNS servers
- Monitors DNS service availability
- Generates appropriate alert levels

### 5. ✅ Email Notifications
- Postfix SMTP server for outgoing emails
- Dovecot for IMAP/IMAPS access
- Custom monitoring system sends email alerts
- Self-contained email infrastructure

## File Structure

- `lab.py` - Main script with all functionality
- `infrastructure.json` - Stores infrastructure state (auto-generated)
- `dns-lab-key.pem` - SSH key for instances (auto-generated)
- `README.md` - This file

## Manual Testing Commands

### DNS Resolution Tests
```bash
# Test primary DNS server
nslookup www.zkouska.sps <primary-dns-ip>
nslookup www.lab.sps <primary-dns-ip>

# Test secondary DNS server
nslookup www.zkouska.sps <secondary-dns-ip>
nslookup www.lab.sps <secondary-dns-ip>

# Test reverse DNS
nslookup 192.168.100.100 <primary-dns-ip>
```

### Zone Transfer Test
```bash
# Test zone transfer from secondary server
dig @<secondary-dns-ip> sps AXFR
```

### Server Access Commands
```bash
# SSH to servers
ssh -i dns-lab-key.pem ec2-user@<primary-dns-ip>
ssh -i dns-lab-key.pem ec2-user@<secondary-dns-ip>
ssh -i dns-lab-key.pem ec2-user@<monitoring-ip>
```

### Service Verification
```bash
# Check DNS service status
sudo systemctl status named

# Check DNS configuration
sudo named-checkconf

# View DNS logs
sudo tail -f /var/log/named.log

# Check listening ports
sudo netstat -tulpn | grep :53
```

## Cost Management

To minimize AWS costs:

1. **Stop instances when not in use:**
   ```bash
   python lab.py --stop
   ```

2. **Instances can be restarted anytime:**
   ```bash
   python lab.py --start
   ```

3. **Full cleanup when done:**
   ```bash
   python lab.py --cleanup
   ```

## Troubleshooting

### Common Issues

**SSH Key Permissions (Windows):**
```powershell
$acl = Get-Acl dns-lab-key.pem; $acl.SetAccessRuleProtection($true,$false); $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$env:USERNAME","FullControl","Allow"); $acl.SetAccessRule($accessRule); Set-Acl dns-lab-key.pem $acl
```

**DNS Services Not Working:**
- Check if instances are running: `python lab.py --status`
- SSH to DNS server and check logs: `sudo tail -f /var/log/named.log`
- Verify services: `sudo systemctl status named`
- Test configuration: `sudo named-checkconf`

**Zone Transfer Issues:**
- Check primary DNS allows transfers: `sudo tail -f /var/log/named.log`
- Verify secondary DNS configuration
- Check network connectivity between servers

### Debug Commands

Access DNS servers for troubleshooting:
```bash
# Primary DNS server
ssh -i dns-lab-key.pem ec2-user@<primary-dns-ip>
sudo tail -f /var/log/dns-setup.log
sudo systemctl status named
sudo named-checkconf
sudo dig @localhost sps SOA

# Secondary DNS server  
ssh -i dns-lab-key.pem ec2-user@<secondary-dns-ip>
sudo tail -f /var/log/dns-setup.log
sudo systemctl status named
sudo ls -la /var/named/slaves/

# Monitoring server
ssh -i dns-lab-key.pem ec2-user@<monitoring-ip>
sudo tail -f /var/log/monitoring-setup.log
sudo systemctl status postfix
sudo python3 /root/dns_monitor.py
```

---

> [!NOTE]  
> - This is a **laboratory environment**
> - It uses permissive security settings for testing
> - SSH keys and email passwords are hardcoded for demonstration
> - DNS zones use private IP ranges for testing
> - SSL certificates are self-signed

## AWS Permissions Required

The script requires these AWS permissions:
- EC2: Full access for VPC, instance management
- CloudWatch: Create and manage alarms
- SNS: Create and manage topics
- IAM: Basic permissions for service roles

Ensure your AWS credentials have appropriate permissions before running the lab. 