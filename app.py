import os
from pathlib import Path
import streamlit as st
from shield import analyze, build_graph

st.set_page_config(page_title="Phish Shield", page_icon="🛡️", layout="wide")
st.title("🛡️ Phish Shield - LangGraph phishing investigator")
st.caption("Paste a suspicious email / SMS. A LangGraph agent extracts evidence, scores it, asks Gemini to judge, "
           "re-checks when unsure, and gives a protection plan.")

pw = os.environ.get("APP_PASSWORD")
if pw and st.text_input("Password", type="password") != pw:
    st.stop()

if not os.environ.get("GEMINI_API_KEY"):
    k = st.sidebar.text_input("Gemini API key (optional)", type="password")
    if k:
        os.environ["GEMINI_API_KEY"] = k
    st.sidebar.info("Without a key the agent runs in offline rule-engine mode.")

samples = {p.stem: p.read_text() for p in sorted(Path("sample_emails").glob("*.txt"))}
choice = st.selectbox("Load a sample", ["(none)"] + list(samples))
text = st.text_area("Message", samples.get(choice, ""), height=220)
sender = st.text_input("Sender address (optional)", "")

if st.button("Investigate", type="primary") and text.strip():
    with st.spinner("Agent is investigating..."):
        r = analyze(text[:5000], sender)
    color = {"PHISHING": "🔴", "SUSPICIOUS": "🟠", "SAFE": "🟢"}[r["verdict"]]
    c1, c2, c3 = st.columns(3)
    c1.metric("Verdict", f"{color} {r['verdict']}")
    c2.metric("Rule score", f"{r['rule_score']}/100")
    c3.metric("Confidence", r["confidence"])
    st.write(r["reasoning"])
    st.subheader("Evidence")
    for f in r["link_findings"]:
        if f["issues"]:
            st.error(f"{f['url']}  ->  " + "; ".join(i for i, _ in f["issues"]))
    for m in r["language_findings"]:
        st.warning(m)
    st.subheader("Action plan")
    st.write(r["action_plan"])
    with st.expander("Agent trace (LangGraph node by node)"):
        st.code("\n".join(r["trace"]))

with st.expander("Graph diagram (Mermaid)"):
    st.code(build_graph().get_graph().draw_mermaid())
