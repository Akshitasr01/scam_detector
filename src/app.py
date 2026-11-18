# src/app.py
from datetime import datetime
import re

import pandas as pd
import streamlit as st

from predict import predict

st.set_page_config(
    page_title="AI Scam Shield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

if "ui_mode" not in st.session_state:
    st.session_state.ui_mode = "light"
if "history" not in st.session_state:
    st.session_state.history = []
if "active_page" not in st.session_state:
    st.session_state.active_page = "Predict"
if "preset_message" not in st.session_state:
    st.session_state.preset_message = ""


def sanitize_input(text: str) -> str:
    cleaned = re.sub(r"[^\w\s.,!?@#:/\\'\"-]", " ", text, flags=re.UNICODE)
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip()


def render_css():
    dark = st.session_state.ui_mode == "dark"
    bg_gradient = (
        "radial-gradient(circle at 10% 20%, #141639 0%, #221c4a 35%, #0f0f2d 100%)"
        if dark
        else "linear-gradient(135deg, #f4f6ff, #eef2ff, #fef6ff)"
    )
    card_bg = "rgba(11, 14, 34, 0.92)" if dark else "rgba(255,255,255,0.95)"
    sidebar_bg = "rgba(11, 14, 34, 0.95)" if dark else "rgba(255,255,255,0.95)"
    text_color = "#f7f8ff" if dark else "#1b1f3b"
    border_color = "#5b8df5" if dark else "#a2b8ff"
    st.markdown(
        f"""
        <style>
            .stApp {{
                background: {bg_gradient};
                color: {text_color};
            }}
            [data-testid="stAppViewContainer"] {{
                background: transparent;
            }}
            [data-testid="stHeader"] {{
                background: transparent;
            }}
            section[data-testid="stSidebar"] {{
                background-color: {sidebar_bg};
            }}
            section[data-testid="stSidebar"] .stMarkdown,
            section[data-testid="stSidebar"] label {{
                color: {text_color};
            }}
            [data-testid="stMain"] {{
                color: {text_color};
            }}
            [data-testid="stMain"] h1,
            [data-testid="stMain"] h2,
            [data-testid="stMain"] h3,
            [data-testid="stMain"] p,
            [data-testid="stMain"] label,
            [data-testid="stMain"] .stMarkdown {{
                color: {text_color};
            }}
            .main-container {{
                padding: 2rem 2rem 4rem;
            }}
            .glass-card {{
                background: {card_bg};
                border-radius: 22px;
                padding: 1.6rem;
                border: 1px solid rgba(255, 255, 255, 0.08);
                box-shadow: 0 25px 45px rgba(15, 18, 46, 0.3);
                color: {text_color};
            }}
            .glass-card p,
            .glass-card h2,
            .glass-card h3,
            .glass-card li {{
                color: {text_color};
            }}
            .hero-title {{
                font-size: 3rem;
                font-weight: 700;
                background: linear-gradient(120deg, #7f5af0, #5dd8ff, #b5179e);
                -webkit-background-clip: text;
                color: transparent;
            }}
            .hero-subtitle {{
                font-size: 1.1rem;
                color: {text_color};
                opacity: 0.85;
                margin-bottom: 0.5rem;
                animation: fadeIn 1.2s ease forwards;
            }}
            .typing {{
                border-right: 2px solid {border_color};
                white-space: nowrap;
                overflow: hidden;
                animation: typing 3.5s steps(40, end), blink 0.75s step-end infinite;
                font-size: 1.1rem;
            }}
            @keyframes typing {{
                from {{ width: 0 }}
                to {{ width: 100% }}
            }}
            @keyframes blink {{
                from {{ border-color: {border_color}; }}
                to {{ border-color: transparent; }}
            }}
            @keyframes fadeIn {{
                from {{ opacity: 0; transform: translateY(8px); }}
                to {{ opacity: 1; transform: translateY(0); }}
            }}
            .status-card {{
                border-radius: 18px;
                padding: 1.2rem 1.6rem;
                color: #fff;
                font-weight: 600;
                margin-top: 1rem;
            }}
            .status-card.safe {{
                background: linear-gradient(135deg, #1abc9c, #16a085);
            }}
            .status-card.scam {{
                background: linear-gradient(135deg, #ff4b5c, #c9184a);
            }}
            .footer {{
                text-align: center;
                margin-top: 3rem;
                color: {text_color};
                opacity: 0.8;
            }}
            textarea {{
                border-radius: 16px !important;
                border: 1px solid {border_color} !important;
                padding: 1rem !important;
                font-size: 1rem !important;
                box-shadow: inset 0 0 0 1px rgba(91, 141, 245, 0.15);
            }}
        </style>
        """,
        unsafe_allow_html=True,
    )


sidebar = st.sidebar
sidebar.title("🛡️ Scam Shield")
sidebar.caption("DistilBERT-powered protection")

toggle_dark_mode = sidebar.toggle(
    "Dark / Light mode", value=st.session_state.ui_mode == "dark"
)
st.session_state.ui_mode = "dark" if toggle_dark_mode else "light"

render_css()

nav_choice = sidebar.radio(
    "Navigate", ["Home", "Predict", "About"], index=["Home", "Predict", "About"].index(st.session_state.active_page)
)
st.session_state.active_page = nav_choice

sidebar.markdown("### Quick Tips")
sidebar.markdown(
    "- Use short paragraphs\n"
    "- Try multilingual inputs 🌐\n"
    "- Upload `.txt` files"
)
sidebar.markdown("---")
sidebar.write("Need help? Ping Akshita 💬")

sample_messages = {
    "Test Example 1": "Congrats! Your bank account qualifies for a limited bonus. Click http://bit.ly/4bankbonus to claim.",
    "Test Example 2": "Hi team, attaching the meeting summary for tomorrow. Let me know if anything is missing.",
    "Test Example 3": "We detected an unusual login. Verify immediately at secure-paypal.com to avoid suspension.",
}


def render_hero():
    st.markdown(
        """
        <div class="glass-card">
            <p class="hero-subtitle typing">Real-time intelligence • AI Safety • Global Languages</p>
            <h1 class="hero-title">AI Scam Shield</h1>
            <p>Ultra-modern detection for scam, phishing, and spam content .</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_home():
    render_hero()
    st.markdown("### ✨ Why teams use Scam Shield")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown(
            """
            <div class="glass-card">
                <h3>⚡ Instant Verdicts</h3>
                <p>Lightning-fast classification with precision-optimized Transformers.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            """
            <div class="glass-card">
                <h3>🌍 Multilingual</h3>
                <p>Works with Hindi, Spanish, French, and more—no extra setup.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col3:
        st.markdown(
            """
            <div class="glass-card">
                <h3>📊 Insights</h3>
                <p>Session history, probability charts, and human-friendly explanations.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_prediction_page():
    render_hero()
    st.markdown("### 📝 Text Analyzer")
    lang_col, file_col = st.columns([2, 1])
    with lang_col:
        language = st.selectbox(
            "Language of your message",
            ["English", "Hindi", "Spanish", "French", "German", "Other"],
            help="We normalize Unicode text so you can paste multilingual content.",
        )
    with file_col:
        uploaded = st.file_uploader(
            "Upload text file",
            type=["txt"],
            help="Supports UTF-8 encoded text files up to 500KB.",
        )

    uploaded_text = ""
    if uploaded is not None:
        uploaded_text = uploaded.read().decode("utf-8", errors="ignore")
        st.info("📎 Text file uploaded. Click Analyze to run predictions.")

    placeholder = (
        "Paste or type your email, SMS, or WhatsApp message here...\n"
        "Example: \"Dear user, your account is on hold. Verify at ...\""
    )

    if st.session_state.preset_message:
        default_text = st.session_state.preset_message
    elif uploaded_text:
        default_text = uploaded_text
    else:
        default_text = ""

    user_text = st.text_area("Message", value=default_text, placeholder=placeholder, height=200, key="message_box")

    sample_cols = st.columns(len(sample_messages))
    for (label, text_sample), column in zip(sample_messages.items(), sample_cols):
        if column.button(label, key=f"sample_{label}"):
            st.session_state.preset_message = text_sample
            st.rerun()

    analyze = st.button("🔍 Analyze Text", width="stretch", type="primary")
    if analyze:
        cleaned_text = sanitize_input(user_text or uploaded_text)
        if not cleaned_text:
            st.warning("Please provide a message to analyze.")
            return
        with st.spinner("🤖 Running DistilBERT..."):
            result = predict(cleaned_text)
        confidence = float(result["confidence"])
        label = result["label"]
        color_class = "scam" if "Scam" in label else "safe"
        st.success("Analysis completed!")
        st.markdown(
            f"""
            <div class="status-card {color_class}">
                <div style="font-size:1.6rem;">{label}</div>
                <div style="opacity:0.9;">Detected with {confidence:.2f}% confidence</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown("**Confidence level**")
        st.progress(min(max(confidence / 100, 0.0), 1.0))

        with st.expander("🔎 Model explanation & probabilities", expanded=True):
            st.write("The model compares semantic patterns with known scam campaigns and legitimate messages.")
            st.write(f"- Probability of predicted class: **{confidence:.2f}%**")
            st.write(f"- Language provided: **{language}**")
            st.write("Tip: Use the history section to track trends over time.")

        st.session_state.history.append(
            {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "label": "Scam" if "Scam" in label else "Safe",
                "confidence": confidence,
            }
        )
        st.session_state.history = st.session_state.history[-12:]

    if st.session_state.history:
        st.markdown("### 📈 Session Insights")
        hist_df = pd.DataFrame(st.session_state.history)
        st.bar_chart(hist_df.set_index("timestamp")["confidence"])
        st.dataframe(hist_df, use_container_width=True, hide_index=True)


def render_about():
    st.markdown(
        """
        <div class="glass-card">
            <h2>About the project</h2>
            <p>This UI sits on top of Akshita's fine-tuned DistilBERT model designed to flag phishing, spam, and scam outreach across channels.</p>
            <ul>
                <li>✔ Transformer backbone with balanced dataset</li>
                <li>✔ Confidence-calibrated outputs</li>
                <li>✔ Friendly UX for analysts and CX teams</li>
            </ul>
            <p>Need enterprise deployment or API integration? Extend this Streamlit prototype or export the tokenizer/model weights.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


with st.container():
    if st.session_state.active_page == "Home":
        render_home()
    elif st.session_state.active_page == "Predict":
        render_prediction_page()
    else:
        render_about()

st.markdown(
    """
    <div class="footer">
        Made with 💙 by Akshita
    </div>
    """,
    unsafe_allow_html=True,
)
