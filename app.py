"""Streamlit web app for the SMS / UPI scam & phishing detector.

Run:  streamlit run app.py
"""

import streamlit as st

from scamdetector.analyzer import analyze

st.set_page_config(page_title="Scam & Phishing Detector", page_icon="🛡️", layout="centered")

SAMPLES = {
    "Fake KYC": "Dear SBI user, your KYC has expired. Account will be blocked today. Update now: http://sbi-kyc-update.xyz/login",
    "UPI PIN trap": "PhonePe cashback of Rs 2,499 pending. Approve the collect request and enter your UPI PIN to receive money.",
    "Digital arrest": "Narcotics bureau found drugs in a parcel under your name. Do not disconnect this call. Transfer Rs 50,000 to the verification account to clear your name.",
    "Genuine bank alert": "Rs 450.00 debited from A/c XX1234 on 17-Oct to ZOMATO via UPI. Ref 629384756. If not you, call your bank helpline.",
}
COLORS = {"Scam": "🔴", "Suspicious": "🟠", "Looks safe": "🟢"}


def load_sample(text: str):
    st.session_state["message"] = text


st.title("🛡️ Scam & Phishing Detector")
st.caption("Paste an SMS, UPI request or WhatsApp message. We'll tell you if it looks like a scam, and why.")

tab_check, tab_learn = st.tabs(["Check a message", "Learn the tricks"])

with tab_check:
    st.write("Try an example:")
    cols = st.columns(len(SAMPLES))
    for col, (name, text) in zip(cols, SAMPLES.items()):
        col.button(name, on_click=load_sample, args=(text,), use_container_width=True)

    message = st.text_area("Message", key="message", height=140,
                           placeholder="Paste the suspicious message here...")

    if st.button("Analyze", type="primary"):
        try:
            result = analyze(message)
        except ValueError as err:
            st.warning(str(err))
        else:
            st.subheader(f"{COLORS[result.verdict]} {result.verdict}")
            st.progress(result.score, text=f"Risk score: {result.score * 100:.0f}%")

            if result.warns_about_otp and result.verdict == "Looks safe":
                st.success("This message warns you NOT to share your OTP. That's what genuine banks do.")

            if result.findings:
                st.markdown("**Why:**")
                for f in result.findings:
                    st.markdown(f"- {f.reason}")
            else:
                st.markdown("No known scam tricks found.")

            if result.urls:
                st.markdown("**Links found:** " + ", ".join(f"`{u}`" for u in result.urls))

            st.markdown("**What to do:**")
            for tip in result.advice:
                st.markdown(f"- {tip}")

            with st.expander("How was this score calculated?"):
                st.write(f"Text model probability: **{result.ml_probability:.2f}**")
                st.write(f"Rule-check score: **{result.rule_score:.2f}**")
                st.caption("Final risk = 55% text model + 45% rule checks. A single very strong red flag "
                           "(like asking for your PIN) always raises the verdict.")

    st.caption("This tool can make mistakes. When in doubt, contact your bank using the number on your card, "
               "and never share your OTP or PIN.")

with tab_learn:
    st.subheader("5 tricks scammers use")
    st.markdown("""
1. **Fake urgency:** "Your account will be blocked today!" They want you to panic.
2. **Asking for OTP / PIN:** Banks and UPI apps *never* ask for these. A UPI PIN is only for **sending** money, never for receiving.
3. **Look-alike links:** `sbi-kyc-update.xyz` is not SBI. Real sites end in the official domain (e.g. `sbi.co.in`).
4. **Too-good-to-be-true offers:** prizes, easy jobs, instant loans.
5. **Authority pressure:** "CBI / police / customs" threats. There is no such thing as a "digital arrest".
""")
    st.info("Lost money? Call **1930** or report at **cybercrime.gov.in** immediately. Speed matters.")
