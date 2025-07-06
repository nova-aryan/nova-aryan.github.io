# Untitled

Of course! Here’s a breakdown of the Voleur box, written as if one hacker were explaining it to another.

---

Alright, let's walk through how this Voleur box was taken down. It was a pretty cool journey, starting with just a single set of credentials and peeling back the layers one by one.

### **Step 1: Casing the Joint (Reconnaissance)**

First things first, you gotta know what you're dealing with. We ran a quick but deep `nmap`​ scan to see what doors were open on the machine.

```bash
nmap -sCV -p- 10.10.11.76 ...
```

The results basically screamed "Domain Controller!" We saw all the usual suspects: DNS (port 53), Kerberos (port 88), SMB (port 445), and LDAP (port 389). This confirmed we were up against a full-blown Active Directory environment.

Two things stood out, though:

1. **Port 2222 was open with SSH.**  This is a bit unusual for a Windows DC and hinted that maybe Windows Subsystem for Linux (WSL) was set up. We filed that away for later.
2. **Port 5985 was open for WinRM.**  This is our go-to for getting a remote shell if we can get credentials.

### **Step 2: Finding the First Weak Link (Kerberoasting)**

Since we were in an "Assumed Breach" scenario, we started with a user's credentials (`ryan.naylor`​). The first thing to do in any AD environment is to map it out. We used `BloodHound`​ for this.

```bash
bloodhound-python -u ryan.naylor -p 'Hollow0ct31Nyt' ...
```

BloodHound drew us a beautiful map of the domain, and sure enough, it pointed out a classic weak spot: a "kerberoastable" user named `svc_ldap`​.

In simple terms, this means we could ask the domain for a special ticket for that service account. The ticket is encrypted with the account's own password hash. We can take that ticket offline and try to crack the password without ever alerting the system.

So, we did just that with `targetedKerberoast.py`​ and got the hash for another user, `svc_winrm`​.

### **Step 3: Cracking the Password and Getting In**

We took that hash, threw a big list of common passwords (`rockyou.txt`​) at it using `john`​, and... **bingo!**

We got the password for `svc_winrm`​: `AFireInsidedeOzarctica980219afi`​.

Now we had the keys to the kingdom... or at least, a room inside. We used `evil-winrm`​ with these new credentials to get our first interactive shell on the machine. We were in!

### **Step 4: The Ghost in the Machine (Pivoting)**

This next part was pretty slick. Inside the network, we found another set of credentials for `svc_ldap`​. Using that user's access, we started poking around and found a "ghost" in the system—a deleted user account named `todd.wolfe`​.

Why is that interesting? Because sometimes, when you restore a deleted user in Active Directory, it comes back with its old group memberships and, crucially, its old password hash still works!

So we resurrected the `todd.wolfe`​ account. We guessed his old password (a common one, `NightT1meP1dg3on14`​) and, what do you know, it worked! This gave us yet another user to play with.

### **Step 5: The Golden Ticket (Finding the SSH Key)**

Pivoting through these accounts, we eventually got access as `jeremy.combs`​ and started looking through the file shares. In the `IT`​ share, we hit a mini-jackpot:

- A file named `Note.txt.txt`​
- An SSH private key file named `id_rsa`​

The note from the 'Admin' basically said, "Hey, I'm setting up Linux for our backups." This was a massive clue. The SSH key almost certainly belonged to a backup service account. Putting two and two together, we guessed the username was `svc_backup`​.

### **Step 6: The Heist (Stealing the AD Database)**

Remember that weird SSH port (2222) from the beginning? This was where it came into play. We used the `id_rsa`​ key to log in as `svc_backup`​.

```bash
ssh svc_backup@voleur.htb -p 2222 -i id_rsa
```

This dropped us into a Linux shell running on the Windows machine (thanks, WSL!). And as a backup user, we had permission to read the backup folders.

From there, we grabbed the holy grail of any Active Directory pentest:

1. The entire user database (`ntds.dit`​)
2. The `SYSTEM`​ registry hive (which acts as the key to unlock the database)

We `scp`​'d both files right off the server and onto our own machine.

### **Step 7: Game Over - Becoming Domain Admin**

Once you have the `ntds.dit`​ and `SYSTEM`​ files offline, it's effectively game over.

We used `impacket-secretsdump.py`​ to crack open that database. It instantly dumped the password hashes for **every single user** in the domain, including the `Administrator`​.

```bash
secretsdump.py -system SYSTEM -ntds ntds.dit LOCAL
```

We didn't even need to crack the Administrator's hash. We just used the hash itself to authenticate in a "Pass-the-Hash" attack. We got an Administrator Kerberos ticket and then used `evil-winrm`​ one last time.

This time, we logged in as the `Administrator`​. We navigated to the desktop, read the `root.txt`​ file, and owned the entire domain.

And that's how it's done. A classic chain of misconfigurations and weak passwords leading from a low-level user all the way to complete domain compromise.
