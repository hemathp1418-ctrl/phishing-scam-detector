"""Generates a SYNTHETIC training set (data/messages.csv).

Messages are built from templates modelled on common Indian SMS/UPI scams and
genuine bank/delivery/personal messages. It is only a starter dataset so the
project runs out of the box. For a stronger model, add real labelled messages
(see README -> "Improve the model").

Run:  python data/generate_data.py
"""

import csv
import random
from pathlib import Path

random.seed(42)

BANKS = ["SBI", "HDFC Bank", "ICICI Bank", "Axis Bank", "PNB", "Kotak", "Canara Bank", "Bank of Baroda"]
WALLETS = ["Paytm", "PhonePe", "Google Pay", "BHIM", "Amazon Pay"]
NAMES = ["Rahul", "Priya", "Anita", "Kiran", "Suresh", "Meena", "Arjun", "Divya", "Ravi", "Sneha"]
MERCHANTS = ["Swiggy", "Zomato", "BigBasket", "Reliance Fresh", "Uber", "Ola", "Myntra", "Cafe Coffee Day"]
BAD_TLDS = ["xyz", "top", "click", "icu", "link", "vip", "cc"]
AMOUNTS = ["500", "850", "1,200", "2,499", "4,999", "9,800", "15,000", "25,000", "50,000", "1,00,000"]
SMALL = ["10", "25", "49", "99", "149", "199", "299"]
DATES = ["12-Oct", "15-Oct", "18-Oct", "21-Oct", "25-Oct", "02-Nov", "05-Nov", "10-Nov"]


def rid(n=6):
    return "".join(random.choice("abcdefghjkmnpqrstuvwxyz23456789") for _ in range(n))


def phone():
    return random.choice(["98", "97", "88", "70", "63"]) + "".join(random.choice("0123456789") for _ in range(8))


def bad_url(brand):
    b = brand.lower().replace(" ", "").replace("bank", "")
    kind = random.randint(0, 5)
    if kind == 0:
        return f"http://{b}-{random.choice(['kyc', 'update', 'verify', 'secure', 'login'])}.{random.choice(BAD_TLDS)}/{rid()}"
    if kind == 1:
        return f"https://bit.ly/{rid(7)}"
    if kind == 2:
        return f"http://{b}{random.randint(10, 999)}.{random.choice(BAD_TLDS)}"
    if kind == 3:
        return f"http://{b}-bank-online.{random.choice(BAD_TLDS)}/login"
    if kind == 4:
        return f"https://tinyurl.com/{rid(8)}"
    return f"http://{random.randint(11, 220)}.{random.randint(1, 250)}.{random.randint(1, 250)}.{random.randint(1, 250)}/{rid(4)}"


def fields():
    bank = random.choice(BANKS)
    wallet = random.choice(WALLETS)
    return dict(
        bank=bank, wallet=wallet, name=random.choice(NAMES), merchant=random.choice(MERCHANTS),
        amt=random.choice(AMOUNTS), amt2=random.choice(AMOUNTS), small=random.choice(SMALL),
        url=bad_url(random.choice([bank.split()[0], wallet.split()[0]])),
        ph=phone(), num4=str(random.randint(1000, 9999)), num2=str(random.randint(1, 72)),
        otp=str(random.randint(100000, 999999)), ref=rid(8).upper(), date=random.choice(DATES),
    )


SCAM = [
    "Dear {bank} customer, your KYC has expired. Your account will be blocked today. Update immediately: {url}",
    "URGENT: {bank} account suspended due to incomplete KYC. Click {url} to verify PAN now.",
    "Congratulations! You have won Rs {amt} in the {wallet} lucky draw. Claim your reward here {url}",
    "{wallet} cashback of Rs {amt} pending. Approve the collect request and enter your UPI PIN to receive money.",
    "Your {bank} credit card reward points worth Rs {amt} will expire today. Redeem now {url}",
    "Dear user, your electricity will be disconnected tonight at 9:30 PM as previous month bill is not updated. Call {ph} immediately.",
    "Your parcel is held at customs. Pay a small customs fee of Rs {small} to release it: {url}",
    "India Post: your package could not be delivered. Pay Rs {small} redelivery fee within 24 hours {url}",
    "Part-time job offer: earn Rs {amt} per day working from home. Just like and subscribe to videos. WhatsApp {ph}",
    "Your loan of Rs {amt} is pre-approved. No documents needed. Download the app and apply now {url}",
    "{bank}: Dear customer, share the OTP received on your phone to avoid account deactivation.",
    "This is {bank} support. Please install AnyDesk and share the code so we can fix your account issue.",
    "Mistake alert: Rs {amt} was sent to your {wallet} by error. Please return it by approving the request and entering your UPI PIN.",
    "Your Aadhaar is linked to illegal activity. CBI case registered. Call {ph} immediately to avoid arrest.",
    "Income tax refund of Rs {amt} approved. Submit your bank details at {url} within 2 hours to receive it.",
    "Your SIM will be blocked in 2 hours. Complete re-KYC now: {url}",
    "Dear {bank} user, suspicious login detected on your account. Verify your card number and CVV at {url} to secure it.",
    "You are selected for a work from home task job. Earn Rs {amt} daily. Pay registration fee Rs 500 to start. Contact {ph}",
    "FINAL NOTICE: Your {wallet} wallet KYC is pending. Account will be frozen. Update now {url}",
    "Hi, I am {name}. I sent you Rs {amt} by mistake, please send it back to my number, it is urgent",
    "Free recharge of Rs {amt} for all users! Click {url} to claim before it expires.",
    "Gas subsidy of Rs {amt} is pending. Verify your account here {url} or it will be cancelled.",
    "Your {bank} net banking will be deactivated today. Login and update PAN at {url}",
    "Narcotics bureau found drugs in a parcel under your name. Do not disconnect this call. Transfer Rs {amt} to the verification account to clear your name.",
    "You won a brand new iPhone! Pay Rs 999 delivery charges to get it: {url}",
    "{bank} alert: Rs {amt} debited from your account. If not you, click {url} to cancel the transaction and enter your debit card PIN.",
    "Dear customer your {wallet} account is limited. Send your OTP to our agent on {ph} to restore.",
    "Electricity department: your power will be cut at 10 PM tonight. Contact officer on {ph} immediately.",
]

LEGIT = [
    "Rs {amt} debited from A/c XX{num4} on {date} to {name} via UPI. Ref {ref}. If not you, call your bank helpline.",
    "Your OTP for {bank} login is {otp}. Do not share it with anyone. Valid for 10 minutes.",
    "Rs {amt} credited to your account XX{num4} on {date}. Avl bal Rs {amt2}.",
    "Your {wallet} payment of Rs {amt} to {merchant} was successful.",
    "Hi {name}, are we meeting for lunch at 1? Let me know.",
    "Your Amazon order #{ref} has been shipped and will arrive by {date}.",
    "Reminder: your appointment with Dr. {name} is on {date} at 11:00 AM.",
    "Your electricity bill of Rs {amt} is due on {date}. Pay on the official BESCOM app or website.",
    "Salary of Rs {amt} credited to A/c XX{num4}.",
    "Your recharge of Rs {small} is successful. Validity 28 days. Thank you.",
    "{bank} never asks for your PIN, OTP or CVV. Do not share these with anyone, including bank staff.",
    "Your OTP is {otp}. Use it to complete your {wallet} transaction. Never share your OTP.",
    "Hey {name}, class is rescheduled to 10 AM tomorrow. Please inform others.",
    "Your {merchant} order is on the way. Delivery partner {name} will reach in 10 minutes.",
    "Your train PNR {ref} is confirmed. Coach S4, seat {num2}. Happy journey.",
    "Dear customer, your credit card statement of Rs {amt} is generated. Pay by {date}. Visit https://www.hdfcbank.com for details.",
    "{name}: Don't forget to take the medicines after dinner.",
    "Your {bank} debit card ending {num4} was used for Rs {amt} at {merchant}.",
    "Your Flipkart package is out for delivery today. Track at https://www.flipkart.com/track",
    "Assignment submission deadline is extended to {date}. Check the portal for details.",
    "Your Jio number is recharged with Rs {small}. Data: 1.5GB/day.",
    "Hi {name}, can you share the notes from yesterday's lecture? Thanks!",
    "Rs {amt} will be auto-debited on {date} for your subscription. Manage it in your UPI app.",
    "Your LIC premium of Rs {amt} is due on {date}. Pay via the official LIC website.",
    "Urgent: please submit your project report before 5 PM today. - {name}",
    "Sorry, your {merchant} order is delayed. It will arrive within 15 minutes.",
    "Reminder: your {bank} credit card bill of Rs {amt} is due on {date}. Pay via the bank's official app.",
    "Happy birthday {name}! Wishing you a great year ahead. Party at 7?",
    "Your cylinder booking is confirmed. Delivery expected on {date}. Booking ID {ref}.",
]


def render(templates, label, per_template=12):
    rows, seen = [], set()
    for t in templates:
        for _ in range(per_template):
            msg = t.format(**fields())
            if msg not in seen:
                seen.add(msg)
                rows.append((msg, label))
    return rows


if __name__ == "__main__":
    rows = render(SCAM, 1) + render(LEGIT, 0)
    random.shuffle(rows)
    out = Path(__file__).parent / "messages.csv"
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["text", "label"])  # label: 1 = scam, 0 = legit
        w.writerows(rows)
    print(f"Wrote {len(rows)} messages to {out}  (scam={sum(l for _, l in rows)})")
