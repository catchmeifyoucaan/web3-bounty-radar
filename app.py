from __future__ import annotations

import json
import os

import pandas as pd
import streamlit as st

from radar.db import RadarDB


st.set_page_config(page_title="Web3 Bounty Radar", layout="wide")
st.title("Web3 Bounty Radar")
st.caption("Public policy metadata only. A listing or security.txt contact is not authorization to test.")

db_path = st.sidebar.text_input("SQLite database", os.getenv("RADAR_DB", "data/radar.db"))
if not os.path.exists(db_path):
    st.warning("No database yet. Run `python crawler.py` first.")
    st.stop()

db = RadarDB(db_path)
programs = db.list_programs()
events = db.list_events(limit=5000)
if not programs:
    st.info("The database contains no programs.")
    st.stop()

rows = []
for p in programs:
    rows.append({
        "Project": p.project,
        "Category": p.category,
        "Chains": ", ".join(p.chain),
        "Platform": p.platform,
        "Reward USD": p.max_reward_usd,
        "Safe harbor": p.safe_harbor,
        "Status": p.status,
        "Smart contracts": len(p.smart_contract_scope),
        "Scope assets": len(p.scope),
        "Sources": ", ".join(p.sources),
        "Last seen": p.last_seen,
        "Program URL": p.program_url,
        "Confidence": p.web3_confidence,
        "_program": p,
    })
frame = pd.DataFrame(rows)

st.sidebar.header("Filters")
search = st.sidebar.text_input("Project, URL, chain, or policy text")
categories = st.sidebar.multiselect("Category", sorted(frame["Category"].unique()))
statuses = st.sidebar.multiselect("Status", sorted(frame["Status"].unique()))
safe = st.sidebar.multiselect("Safe harbor", sorted(frame["Safe harbor"].unique()))
sources = st.sidebar.multiselect("Source", sorted({s for p in programs for s in p.sources}))
min_reward = st.sidebar.number_input("Minimum USD reward", min_value=0.0, value=0.0, step=10000.0)
smart_only = st.sidebar.checkbox("Explicit smart-contract scope only")
exclude_review = st.sidebar.checkbox("Hide review candidates", value=True)

filtered = frame.copy()
if search:
    needle = search.lower()
    keep = []
    for row in rows:
        p = row["_program"]
        haystack = "\n".join([
            p.project, p.program_url, " ".join(p.chain), p.policy_text,
            "\n".join(p.scope), "\n".join(p.smart_contract_scope),
        ]).lower()
        keep.append(needle in haystack)
    filtered = filtered[keep]
if categories:
    filtered = filtered[filtered["Category"].isin(categories)]
if statuses:
    filtered = filtered[filtered["Status"].isin(statuses)]
if safe:
    filtered = filtered[filtered["Safe harbor"].isin(safe)]
if sources:
    filtered = filtered[filtered["Sources"].apply(lambda value: any(s in value.split(", ") for s in sources))]
if min_reward:
    filtered = filtered[filtered["Reward USD"] >= min_reward]
if smart_only:
    filtered = filtered[filtered["Smart contracts"] > 0]
if exclude_review:
    filtered = filtered[filtered["Confidence"] != "review"]

m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Programs", len(filtered))
m2.metric("Active", int((filtered["Status"] == "active").sum()))
m3.metric("Safe harbor stated", int((filtered["Safe harbor"] == "stated").sum()))
m4.metric("Smart-contract scope", int((filtered["Smart contracts"] > 0).sum()))
m5.metric("Events", len(events))

program_tab, event_tab, detail_tab = st.tabs(["Programs", "Change feed", "Policy inspector"])
with program_tab:
    display = filtered.drop(columns=["_program"]).sort_values(["Reward USD", "Project"], ascending=[False, True])
    st.dataframe(display, use_container_width=True, hide_index=True, column_config={
        "Program URL": st.column_config.LinkColumn("Program URL"),
        "Reward USD": st.column_config.NumberColumn("Reward USD", format="$%,.0f"),
    })
with event_tab:
    if events:
        event_types = st.multiselect("Event types", sorted({e["type"] for e in events}), key="event_types")
        shown = [e for e in events if not event_types or e["type"] in event_types]
        st.dataframe([{
            "Detected": e["detected_at"], "Type": e["type"], "Project": e["project"],
            "Old": e["old_value"], "New": e["new_value"], "Details": e["details"],
        } for e in shown], use_container_width=True, hide_index=True)
    else:
        st.info("No changes recorded yet.")
with detail_tab:
    options = {row["Project"]: row["_program"] for row in filtered.to_dict("records")}
    if not options:
        st.info("Adjust the filters to inspect a program.")
    else:
        name = st.selectbox("Program", sorted(options))
        program = options[name]
        st.write(f"**Current policy:** {program.program_url}")
        st.write(
            f"Status: **{program.status}** · Safe harbor: **{program.safe_harbor}** · "
            f"Extraction: **{program.extraction_method}**"
        )
        if program.status in {"policy_dead", "closed"} or program.policy_expires:
            st.warning("Treat missing, closed, or expired policies as no permission. Re-read the live policy before any research.")
        c1, c2 = st.columns(2)
        with c1:
            st.subheader("Scope")
            st.json(program.scope)
            st.subheader("Smart-contract scope")
            st.json(program.smart_contract_scope)
        with c2:
            st.subheader("Out of scope")
            st.json(program.out_of_scope)
            st.subheader("Contacts")
            st.json(program.contact)
        with st.expander("Normalized record"):
            st.json(program.export_dict())
        # Look up the stable internal ID without exposing it in the interface.
        pid = next((pid for pid, p in db.programs_with_ids() if p.project == name and p.program_url == program.program_url), None)
        snapshot = db.latest_snapshot(pid) if pid else None
        if snapshot:
            with st.expander("Latest normalized policy snapshot"):
                st.text(snapshot["normalized_text"])
        st.subheader("Program history")
        st.dataframe([e for e in events if e["project"] == name], use_container_width=True, hide_index=True)

db.close()
