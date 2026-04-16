"""
PhishAegis — Synthetic Phishing Dataset Generator

Generates a labeled CSV dataset of phishing and legitimate email texts
for training the TF-IDF + Naive Bayes classifier.
"""

import csv
import random
import os

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "data", "phishing_dataset.csv")

PHISHING_TEMPLATES = [
    "URGENT: Your {account_type} account has been compromised. Click here to verify your identity: {url}",
    "Dear Customer, We detected unusual activity on your {account_type} account. Please confirm your credentials at {url} within 24 hours.",
    "Your {account_type} password expires today. Reset it immediately: {url}",
    "ACTION REQUIRED: Your {account_type} account will be suspended unless you verify your information at {url}",
    "Important Security Alert! Unauthorized login attempt detected on your {account_type}. Secure your account now: {url}",
    "Congratulations! You've been selected as our lucky winner! Claim your $1,000,000 prize at {url}",
    "Dear valued member, Your {account_type} account needs immediate verification. Failure to respond within 48 hours will result in permanent suspension. {url}",
    "FINAL WARNING: Your {account_type} will be terminated. Update your payment information: {url}",
    "Hi, I'm reaching out from {company} support. We need you to re-enter your login credentials here: {url}",
    "Your recent {account_type} transaction of ${amount} has been flagged. If unauthorized, click here: {url}",
    "We have detected suspicious activity on your account. Please verify your identity by clicking: {url}",
    "Your {account_type} subscription has expired. Renew now to avoid losing access: {url}",
    "ALERT: Someone tried to access your {account_type} from an unknown device. Verify now: {url}",
    "Dear Sir/Madam, We are from {company} Security Team. Your account requires immediate attention: {url}",
    "Your {account_type} refund of ${amount} is pending. Confirm your bank details at: {url}",
    "Invoice #{invoice_num} attached. Payment overdue. See attached invoice or pay at: {url}",
    "Your package delivery failed. Reschedule at: {url}. Track ID: {tracking_id}",
    "IRS Notice: Your tax return requires additional verification. Submit documents at: {url}",
    "IT Department: Your email storage is full. Click here to expand: {url}",
    "Helpdesk ticket #{invoice_num}: Your password must be changed. Reset here: {url}",
    "Dear {account_type} user, Your account login was blocked. Unblock now: {url}",
    "SECURITY NOTICE: We have temporarily limited your {account_type} account. Restore access: {url}",
    "Your {company} order #{invoice_num} has a problem. Verify shipping details: {url}",
    "Urgent wire transfer needed. Please process ${amount} to the account specified at: {url}",
    "Dear Customer, We noticed your {account_type} credit card was charged ${amount}. If not you, report at: {url}",
    "Apple ID Locked - Your Apple ID has been locked due to security concerns. Unlock: {url}",
    "Microsoft Account Alert: Unusual sign-in from Russia. Secure your account: {url}",
    "Netflix: Your payment was declined. Update billing info to continue streaming: {url}",
    "Amazon Security: Unauthorized purchase of ${amount} detected on your account. Cancel here: {url}",
    "Your cryptocurrency wallet has been accessed from a new location. Verify ownership: {url}",
    "Dear user, confirm your identity immediately or your {account_type} will be closed permanently. {url}",
    "ALERT! Your social security number may have been compromised. Check status: {url}",
    "Bank of America: Suspicious transfer of ${amount}. Authorize or cancel: {url}",
    "Google Security Alert: Someone has your password. Change it now: {url}",
    "Your Dropbox shared file has been flagged. Review at: {url}",
    "FedEx: Your shipment is on hold due to unpaid duties of ${amount}. Pay now: {url}",
    "LinkedIn: Someone viewed your profile from an unusual location. Verify: {url}",
    "Dear valued customer, act now to prevent account termination. Verify at: {url}. Don't delay!",
    "You have (1) unread secure message from {company}. Read it here: {url}",
    "Your email account will be deactivated in 24 hours. Confirm ownership: {url}",
]

LEGITIMATE_TEMPLATES = [
    "Hi team, Just a reminder that our weekly standup is tomorrow at {time}. See you there!",
    "Please find attached the Q{quarter} report for review. Let me know if you have any questions.",
    "Thanks for your order #{invoice_num}. Your items will be shipped within 2-3 business days.",
    "Hi {name}, I wanted to follow up on our conversation from last week about the project timeline.",
    "Meeting agenda for {day}: 1) Project updates 2) Budget review 3) Next steps",
    "Dear {name}, Thank you for applying. We'd like to schedule an interview at your convenience.",
    "Your monthly statement for {month} is now available in your account dashboard.",
    "Hi everyone, Please review the attached document and provide feedback by {day}.",
    "Reminder: Office will be closed on {day} for the holiday. Enjoy the long weekend!",
    "Hey {name}, Are you available for a quick call this afternoon to discuss the design specs?",
    "Your subscription renewal was successful. Next billing date: {day}.",
    "Team update: We've completed milestone 3 ahead of schedule. Great work everyone!",
    "Hi {name}, Here's the summary from today's client meeting. Action items are listed below.",
    "Please note the updated parking policy effective {day}. Details attached.",
    "Congratulations on your work anniversary! Thank you for {years} years of dedication.",
    "Hi {name}, Your PTO request for {day} has been approved by your manager.",
    "Quarterly newsletter: Company updates, new hires, and upcoming events inside.",
    "Invitation: Annual company picnic on {day} at Riverside Park. RSVP by {day}.",
    "Your flight confirmation for {day}: {company} Airlines, departing at {time}.",
    "Hi {name}, The conference room has been booked for your presentation on {day} at {time}.",
    "Expense report #{invoice_num} has been approved and will be reimbursed in your next paycheck.",
    "Dear {name}, Your application for the {company} internship has been received. We'll be in touch.",
    "Scheduled maintenance notice: Systems will be down from {time} to {time} on {day}.",
    "Hi {name}, Could you review the pull request I submitted for the authentication module?",
    "Monthly team lunch is on {day}. Reply with your restaurant preference!",
    "Your document '{name} - Project Proposal' has been shared with you on Google Drive.",
    "Reminder: Performance reviews are due by end of {month}. Please complete your self-assessment.",
    "Hi {name}, The new office supplies have arrived. Pick them up from the supply room.",
    "Weekly digest: 15 new commits, 3 issues resolved, 2 pending reviews.",
    "Dear {name}, Your dental appointment is confirmed for {day} at {time}.",
    "Project kickoff meeting scheduled for {day}. Stakeholders please confirm attendance.",
    "Hi team, Attached is the updated sprint backlog. Please prioritize accordingly.",
    "Your Amazon order of '{name}' has been delivered. Rate your experience.",
    "Dear {name}, We appreciate your feedback. Our team is working on the improvements you suggested.",
    "Reminder: Submit your timesheet by end of day {day}.",
    "Hi {name}, The code review for PR #247 looks good. Approved with minor comments.",
    "Your gym membership has been renewed. See you at the fitness center!",
    "Team building event next {day}: Escape room challenge. Sign up sheet attached.",
    "Hi {name}, Thanks for the great presentation today. Really insightful data.",
    "Your car service appointment is confirmed for {day} at {time} at {company} Auto.",
]

ACCOUNT_TYPES = ["PayPal", "banking", "email", "iCloud", "Microsoft", "Google", "Netflix", "Amazon"]
COMPANIES = ["Microsoft", "Apple", "Google", "Amazon", "PayPal", "Chase", "Wells Fargo", "Citibank"]
NAMES = ["John", "Sarah", "Michael", "Emma", "David", "Lisa", "James", "Maria", "Robert", "Jennifer"]
DAYS = ["Monday", "Tuesday", "Wednesday", "Friday", "January 15th", "March 3rd", "next Tuesday"]
MONTHS = ["January", "February", "March", "April", "May", "June", "October", "November", "December"]
TIMES = ["9:00 AM", "10:30 AM", "2:00 PM", "3:30 PM", "4:00 PM"]
PHISHING_URLS = [
    "http://192.168.1.1/verify",
    "http://secure-paypa1.com/login",
    "https://micros0ft-support.xyz/verify",
    "http://amaz0n.security-check.tk/confirm",
    "https://g00gle.account-verify.ml/auth",
    "http://update.your-bank.click/secure",
    "http://login.netlfix-billing.top/payment",
    "https://apple.id-verification.gq/unlock",
    "http://chase-secure.ga/verify-account",
    "http://10.0.0.1/phish/login.php",
    "https://bit.ly/3x4mpl3",
    "http://accounts-verify.com/login%20form",
]


def generate_phishing_email():
    template = random.choice(PHISHING_TEMPLATES)
    text = template.format(
        account_type=random.choice(ACCOUNT_TYPES),
        company=random.choice(COMPANIES),
        url=random.choice(PHISHING_URLS),
        amount=random.randint(50, 9999),
        invoice_num=random.randint(10000, 99999),
        tracking_id=f"TRK{random.randint(100000, 999999)}",
        name=random.choice(NAMES),
    )
    return text


def generate_legitimate_email():
    template = random.choice(LEGITIMATE_TEMPLATES)
    text = template.format(
        name=random.choice(NAMES),
        company=random.choice(COMPANIES),
        day=random.choice(DAYS),
        month=random.choice(MONTHS),
        time=random.choice(TIMES),
        quarter=random.randint(1, 4),
        invoice_num=random.randint(10000, 99999),
        years=random.randint(1, 20),
    )
    return text


def generate_dataset(num_samples: int = 1000):
    """Generate a balanced synthetic phishing dataset."""
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)

    samples = []
    half = num_samples // 2

    for _ in range(half):
        samples.append({"text": generate_phishing_email(), "label": "phishing"})

    for _ in range(half):
        samples.append({"text": generate_legitimate_email(), "label": "legitimate"})

    random.shuffle(samples)

    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["text", "label"])
        writer.writeheader()
        writer.writerows(samples)

    print(f"Generated {len(samples)} samples -> {OUTPUT_PATH}")
    print(f"  Phishing: {half}")
    print(f"  Legitimate: {half}")
    return OUTPUT_PATH


if __name__ == "__main__":
    generate_dataset(1200)
