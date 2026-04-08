import csv, random, os
random.seed(42)
os.makedirs("dataset", exist_ok=True)

# SENSITIVE: 60 unique texts covering ALL categories
SENSITIVE = [
    # Credential transmission (10)
    "Login credentials are provided below. Do not share with anyone outside the team.",
    "The database password has been reset. New credentials are enclosed in this message.",
    "Your account has been created. Username and password are attached to this email.",
    "API key and secret token are provided below. Rotate them after first use.",
    "Server access credentials are enclosed. Store them securely and do not share.",
    "Your access token is attached. Update your environment configuration file with the new value.",
    "Admin credentials for the backup server are listed below. Restrict access to team leads only.",
    "SSH private key is attached to this message. Do not share this file under any circumstances.",
    "New login details are provided in the attachment. Change the password upon first login.",
    "Service account credentials are enclosed. These provide full production database access.",
    # Financial disclosure (10)
    "The bank statement for the requested period is enclosed in this email. Handle with care.",
    "Credit card statement is attached. Please verify all transactions and report any discrepancies.",
    "Salary and compensation details for all staff are enclosed. For authorised HR use only.",
    "Annual CTC breakdown is attached. This is a private communication between HR and the employee.",
    "Bank account details for payroll processing are listed below. Verify before initiating transfer.",
    "Financial records for this quarter are enclosed. These are confidential and must not be forwarded.",
    "The invoice with complete payment and account details is attached for your reference.",
    "Employee payroll data for this month is attached. For authorised HR personnel only.",
    "Please find the salary slip attached. The figures enclosed are strictly confidential.",
    "Wire transfer instructions and account details are provided below. Treat as confidential.",
    # Identity documents (10)
    "Aadhaar and PAN details have been submitted as part of the KYC verification process.",
    "Identity proof has been attached to this email for verification purposes.",
    "Passport details are noted below for visa processing. Do not share publicly.",
    "Voter ID registration is complete. Your personal details have been submitted to the electoral office.",
    "Please find a copy of the Aadhaar card attached for address verification.",
    "Employee identity documents are enclosed and stored securely in the HR system.",
    "Driving licence and PAN card copies are attached as requested for the background check.",
    "GST registration number and business identity documents are enclosed for verification.",
    "The UPI ID and linked bank account details are provided below for payment processing.",
    "Insurance policy documents with personal details are enclosed. For the insured member only.",
    # Medical and personal (8)
    "Patient medical record is enclosed. Access is restricted to authorised clinical staff only.",
    "Personal emergency contact details are listed below. Keep this information strictly private.",
    "Health insurance details and policy number are attached for the employee records.",
    "Medical history and diagnosis report are enclosed for the treating physician only.",
    "Personal health data report is attached. This document must not be shared beyond the care team.",
    "The patient admission record with Aadhaar and insurance details is enclosed for billing.",
    "Employee health declaration form with personal details is attached to this message.",
    "Lab test results and doctor's notes are enclosed. For the patient and treating doctor only.",
    # Security codes and tokens (8)
    "A one-time password has been sent to your registered mobile number for account verification.",
    "Security code is provided below. It is valid for five minutes only. Do not share with anyone.",
    "Transaction OTP is attached in this message. Approve only if you initiated this request.",
    "Your two-factor authentication backup codes are listed below. Store them in a secure location.",
    "JWT authentication token is enclosed. Use it in the Authorization header for API requests.",
    "AWS access key and secret are provided below for the deployment pipeline configuration.",
    "SSH private key for production server access is attached. Authorised personnel only.",
    "The bearer token for the payment gateway integration is enclosed. Do not log or expose this.",
    # Organisational confidential (7)
    "Revised CTC details are provided below. Do not discuss this with other employees.",
    "The merger negotiation terms and financial projections are enclosed. Board access only.",
    "Client pricing and contract terms are attached. Strictly confidential. Do not forward.",
    "Internal audit findings are enclosed for the compliance team. Not for external distribution.",
    "Employee performance ratings and appraisal scores are enclosed. HR eyes only.",
    "The acquisition due diligence report is attached. Treat as commercially sensitive.",
    "Trade secret documentation is enclosed. Access restricted by NDA. Handle accordingly.",
    # Network and system credentials (7)
    "VPN credentials and server IP addresses are listed below for remote access setup.",
    "Database connection string with username and password is enclosed for the dev team.",
    "Internal server IP addresses and admin passwords are listed below. Do not share externally.",
    "The firewall configuration with internal network details is attached for the infrastructure team.",
    "Production environment variables including secret keys are enclosed for the deployment team.",
    "Root SSH credentials for the cloud server are provided below. Restrict to senior engineers.",
    "API gateway keys and endpoint URLs for the payment system are enclosed below.",
]

# SAFE: 62 unique texts — policy/advisory/educational/general
SAFE = [
    # IT/Security policy (10)
    "The password policy mandates a minimum of 12 characters including uppercase and special symbols.",
    "Employees must change their passwords every 90 days in accordance with the IT security policy.",
    "Two-factor authentication is now required for all staff accessing the internal portal.",
    "The IT policy prohibits writing down passwords or sharing them via email or messaging applications.",
    "Access to production systems requires approval from the department head and the security team.",
    "All sensitive files must be encrypted before being transmitted over any external network.",
    "The organisation enforces a clean desk policy. No credentials may be written on physical notes.",
    "Multi-factor authentication codes must never be shared with anyone, including IT support staff.",
    "The acceptable use policy prohibits storing company credentials in personal cloud accounts.",
    "Password managers are recommended for all employees to securely store their login credentials.",
    # Aadhaar/PAN/identity informational (10)
    "Aadhaar-based authentication has significantly reduced identity fraud across government services.",
    "PAN card is required for income tax filing and for all financial transactions above Rs.50000.",
    "The PAN card is a 10-character alphanumeric identifier issued by the Income Tax Department.",
    "Aadhaar enrollment is available at government service centres from Monday to Friday.",
    "PAN-Aadhaar linking is mandatory for all taxpayers before the deadline specified by the ministry.",
    "The UIDAI website provides official services for Aadhaar corrections and address updates.",
    "Driving licence is accepted as a valid address proof for bank account opening procedures.",
    "GST registration is mandatory for businesses with annual turnover exceeding Rs.20 lakh.",
    "Voter ID card serves as valid identity proof for government services and financial institutions.",
    "Insurance policy documents should be stored safely and reviewed annually for coverage adequacy.",
    # Banking and financial advisory (10)
    "The bank has upgraded its mobile application with improved security and transaction features.",
    "Net banking services require registration at the branch with a valid identity document.",
    "Customers are advised to use only the official bank website for all online transactions.",
    "The bank will never ask for your account number or OTP through email or phone calls.",
    "UPI transactions are protected by a PIN that should never be shared with anyone.",
    "Credit card statements should be reviewed monthly to identify any unauthorised transactions.",
    "The Reserve Bank of India advises customers to report suspicious transactions immediately.",
    "Salary accounts typically offer zero minimum balance requirements and additional banking benefits.",
    "IFSC codes are used to identify the specific bank branch for electronic fund transfers.",
    "Fixed deposits offer guaranteed returns and are insured up to Rs.5 lakh by DICGC.",
    # Data privacy and compliance (10)
    "The data privacy policy requires masking of Aadhaar and PAN in all non-production databases.",
    "Our system does not retain credit card numbers after transaction completion.",
    "Role-based access control ensures that salary and payroll records are visible only to HR staff.",
    "Data masking hides sensitive field values in development and testing environments.",
    "The compliance framework prohibits storing passwords in plain text on any company system.",
    "Regular penetration testing is conducted to identify vulnerabilities in cloud infrastructure.",
    "GDPR and PDPB compliance require explicit consent before collecting personal data from users.",
    "Data minimisation principles require collecting only the information necessary for the task.",
    "Access logs are maintained for all interactions with systems containing personal data.",
    "Personal data must be deleted within 30 days of a user submitting a deletion request.",
    # Security advisory and awareness (10)
    "Users should never share their OTP with anyone, including company support representatives.",
    "Do not click on links in emails claiming to require your bank account details or password.",
    "Phishing emails often impersonate banks and request account credentials from recipients.",
    "Your Aadhaar card is a government-issued identity document. Store the physical copy securely.",
    "PAN card details should not be posted on social media or shared in public forums.",
    "Be cautious of social engineering attacks that try to extract credentials over the phone.",
    "Always verify the sender before opening attachments that claim to contain financial documents.",
    "Public Wi-Fi networks should not be used for banking or accessing sensitive company systems.",
    "Ransomware attacks often begin with a phishing email containing a malicious attachment.",
    "Report suspicious login attempts or unauthorised access immediately to the security team.",
    # General cloud/software/project (12)
    "Cloud computing provides scalable on-demand access to computing resources over the internet.",
    "Machine learning requires quality labelled data and proper validation to generalise well.",
    "The new software build has been deployed to the staging environment for quality assurance.",
    "The sprint retrospective is scheduled for Friday afternoon. All team members should attend.",
    "Please submit the quarterly progress report to the project lead before end of day Thursday.",
    "The system uptime for this month is 99.6 percent. All services are running normally.",
    "Encryption and access control are fundamental components of a secure cloud architecture.",
    "The API documentation has been updated. Review version 2.1 before integrating the endpoints.",
    "Network segmentation limits the blast radius of a security incident within cloud infrastructure.",
    "Zero trust security models verify every access request regardless of network location.",
    "Container orchestration platforms like Kubernetes require careful RBAC configuration.",
    "DevSecOps integrates security practices into every stage of the software development lifecycle.",
]

print(f"Sensitive: {len(SENSITIVE)} unique texts")
print(f"Safe:      {len(SAFE)} unique texts")
print(f"Total:     {len(SENSITIVE)+len(SAFE)} unique texts")

# Expand to 1400 rows
rows = []
for _ in range(700): rows.append({"text": random.choice(SENSITIVE), "label":"sensitive"})
for _ in range(700): rows.append({"text": random.choice(SAFE),      "label":"safe"})
random.shuffle(rows)

with open("dataset/data.csv","w",newline="",encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["text","label"])
    w.writeheader(); w.writerows(rows)
print(f"Saved dataset/data.csv  ({len(rows)} rows)")