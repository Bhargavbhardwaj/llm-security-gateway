import json
from pathlib import Path

import pandas as pd
import streamlit as st

from detectors.keyword_detector import KeywordDetector
from detectors.similarity_detector import SimilarityDetector

LOG_FILE = Path("logs/events.jsonl")
EVAL_FILE = Path("reports/eval_results.json")

st.set_page_config(page_title="LLM Security Gateway", layout="wide")
st.title("LLM Security Gateway Dashboard")


@st.cache_resource
def load_detectors():
    return KeywordDetector(), SimilarityDetector()


def load_events() -> pd.DataFrame:
    if not LOG_FILE.exists():
        return pd.DataFrame()
    lines = LOG_FILE.read_text(encoding="utf-8").splitlines()
    return pd.DataFrame([json.loads(l) for l in lines if l.strip()])


tab_events, tab_eval, tab_play = st.tabs(["Live events", "Evaluation", "Playground"])

# ---------- Tab 1: gateway events ----------
with tab_events:
    df = load_events()
    if df.empty:
        st.info("No events yet. Run `python main.py` and send a few prompts first.")
    else:
        blocked = df[df["blocked"]]
        c1, c2, c3 = st.columns(3)
        c1.metric("Total scans", len(df))
        c2.metric("Blocked", len(blocked))
        c3.metric("Block rate", f"{len(blocked) / len(df):.0%}")

        left, right = st.columns(2)
        with left:
            st.subheader("Blocked by severity")
            if len(blocked):
                st.bar_chart(blocked["severity"].value_counts())
            else:
                st.caption("Nothing blocked yet.")
        with right:
            st.subheader("Detections by category")
            cats = [d["category"] for ds in df["detections"] for d in ds]
            if cats:
                st.bar_chart(pd.Series(cats).value_counts())
            else:
                st.caption("No detections yet.")

        st.subheader("Event log")
        view = df.copy()
        view["rules"] = view["detections"].apply(
            lambda ds: ", ".join(d["rule_id"] for d in ds)
        )
        view = view[["timestamp", "direction", "blocked", "severity", "rules", "text"]]
        st.dataframe(view.iloc[::-1], use_container_width=True, hide_index=True)

        if st.button("Refresh"):
            st.rerun()

# ---------- Tab 2: evaluation results ----------
with tab_eval:
    if not EVAL_FILE.exists():
        st.info("Run `python evaluate.py` first to generate reports/eval_results.json.")
    else:
        data = json.loads(EVAL_FILE.read_text(encoding="utf-8"))
        st.caption(f"Similarity threshold used: {data['threshold']}")

        st.subheader("Detector comparison")
        res = pd.DataFrame(data["results"]).T[
            ["detection_rate", "fpr", "precision", "tp", "fn", "fp", "tn"]
        ]
        st.dataframe(res.style.format(
            {"detection_rate": "{:.0%}", "fpr": "{:.0%}", "precision": "{:.0%}"}
        ), use_container_width=True)

        st.subheader("Threshold sweep")
        sweep = pd.DataFrame(data["sweep"]).set_index("threshold")
        st.line_chart(sweep[["detection_rate", "fpr"]])
        st.caption("Lower thresholds catch more attacks but block more harmless prompts.")

# ---------- Tab 3: playground ----------
with tab_play:
    st.write("Scan a prompt with the detectors only (no LLM call).")
    text = st.text_area("Prompt to scan", height=120)
    if st.button("Scan") and text.strip():
        kw, sim = load_detectors()
        kw_hits = kw.scan(text)
        score, category, closest = sim.best_match(text)

        verdict_block = bool(kw_hits) or score >= sim.threshold
        if verdict_block:
            st.error("BLOCK")
        else:
            st.success("ALLOW")

        st.write(f"**Similarity score:** {score:.2f} (threshold {sim.threshold})")
        st.write(f"**Closest known attack:** [{category}] {closest}")
        if kw_hits:
            st.write("**Keyword rules matched:**")
            for d in kw_hits:
                st.write(f"- {d.rule_id} ({d.severity.name}): {d.description}, matched `{d.matched_text}`")
        else:
            st.write("**Keyword rules matched:** none")