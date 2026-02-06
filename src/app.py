import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import plotly.express as px
import streamlit as st

from src.analyzer import SystemLogAnalyzer, TrafficAnalyzer
from src.database import LogDatabase
from src.parser import AccessEntry, LogParser, SystemLogEntry

st.set_page_config(page_title="Log Analyzer", layout="wide")
st.title("Log Analyzer Dashboard")


@st.cache_resource
def get_db():
    return LogDatabase()


db = get_db()
analyzer = TrafficAnalyzer(db)
sys_analyzer = SystemLogAnalyzer(db)

with st.sidebar:
    st.header("Upload Log File")
    uploaded = st.file_uploader("Choose a log file", type=["log", "txt"])
    if uploaded:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as tmp:
            content = uploaded.read().decode("utf-8")
            tmp.write(content)
            tmp_path = tmp.name

        parser = LogParser()
        access_entries, system_entries = parser.parse_file_by_type(tmp_path)
        os.unlink(tmp_path)

        loaded = 0
        if access_entries:
            db.insert_entries(access_entries)
            loaded += len(access_entries)
        if system_entries:
            db.insert_system_entries(system_entries)
            loaded += len(system_entries)

        if loaded > 0:
            st.success(f"Loaded {loaded} entries")
            st.rerun()
        else:
            st.error("No valid entries found")

    st.divider()
    if st.button("Reset Database"):
        db.reset()
        st.success("Database cleared")
        st.rerun()

access_count = db.get_entry_count()
system_count = db.get_system_entry_count()

if access_count == 0 and system_count == 0:
    st.info("No data available. Upload a log file to get started.")
    st.stop()

tab1, tab2 = st.tabs(["Access Logs", "System Logs"])

with tab1:
    if access_count == 0:
        st.info("No access log data available.")
    else:
        info = db.get_summary()
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Requests", f"{info['total']:,}")
        col2.metric("Unique IPs", f"{info['unique_ips']:,}")
        col3.metric("Total Bandwidth", f"{info['total_bytes']:,} B")
        col4.metric("Time Range", f"{str(info['first_entry'])[:10]}")

        st.divider()

        left, right = st.columns(2)

        with left:
            st.subheader("Traffic Over Time")
            traffic_df = analyzer.traffic_over_time()
            if not traffic_df.empty:
                fig = px.line(traffic_df, x="timestamp", y="count")
                fig.update_layout(margin=dict(l=0, r=0, t=10, b=0), height=300)
                st.plotly_chart(fig, use_container_width=True)

        with right:
            st.subheader("Status Code Distribution")
            status_df = analyzer.status_distribution()
            if not status_df.empty:
                status_df["status"] = status_df["status"].astype(str)
                fig = px.pie(status_df, values="count", names="status")
                fig.update_layout(margin=dict(l=0, r=0, t=10, b=0), height=300)
                st.plotly_chart(fig, use_container_width=True)

        left2, right2 = st.columns(2)

        with left2:
            st.subheader("Top IPs")
            ip_df = analyzer.top_ips()
            if not ip_df.empty:
                fig = px.bar(ip_df, x="count", y="ip", orientation="h")
                fig.update_layout(
                    margin=dict(l=0, r=0, t=10, b=0),
                    height=300,
                    yaxis=dict(autorange="reversed"),
                )
                st.plotly_chart(fig, use_container_width=True)

        with right2:
            st.subheader("Hourly Traffic Pattern")
            hourly_df = analyzer.hourly_pattern()
            if not hourly_df.empty:
                fig = px.bar(hourly_df, x="hour", y="count")
                fig.update_layout(margin=dict(l=0, r=0, t=10, b=0), height=300)
                st.plotly_chart(fig, use_container_width=True)

        st.divider()

        st.subheader("Error Rate Over Time")
        error_df = analyzer.error_rate_over_time()
        if not error_df.empty:
            fig = px.area(error_df, x="timestamp", y="error_rate")
            fig.update_layout(margin=dict(l=0, r=0, t=10, b=0), height=250)
            st.plotly_chart(fig, use_container_width=True)

        st.subheader("Bandwidth Over Time")
        bw_df = analyzer.bandwidth_over_time()
        if not bw_df.empty:
            fig = px.area(bw_df, x="timestamp", y="bytes")
            fig.update_layout(margin=dict(l=0, r=0, t=10, b=0), height=250)
            st.plotly_chart(fig, use_container_width=True)

with tab2:
    if system_count == 0:
        st.info("No system log data available.")
    else:
        info = db.get_system_summary()
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Entries", f"{info['total']:,}")
        col2.metric("Unique Sources", f"{info['unique_sources']:,}")
        col3.metric("Unique Hosts", f"{info['unique_hosts']:,}")
        col4.metric("Time Range", f"{str(info['first_entry'])[:10]}")

        st.divider()

        left, right = st.columns(2)

        with left:
            st.subheader("Events Over Time")
            events_df = sys_analyzer.events_over_time()
            if not events_df.empty:
                fig = px.line(events_df, x="timestamp", y="count")
                fig.update_layout(margin=dict(l=0, r=0, t=10, b=0), height=300)
                st.plotly_chart(fig, use_container_width=True)

        with right:
            st.subheader("Log Level Distribution")
            level_df = sys_analyzer.level_distribution()
            if not level_df.empty:
                fig = px.pie(level_df, values="count", names="level")
                fig.update_layout(margin=dict(l=0, r=0, t=10, b=0), height=300)
                st.plotly_chart(fig, use_container_width=True)

        left2, right2 = st.columns(2)

        with left2:
            st.subheader("Top Sources")
            src_df = sys_analyzer.top_sources()
            if not src_df.empty:
                fig = px.bar(src_df, x="count", y="source", orientation="h")
                fig.update_layout(
                    margin=dict(l=0, r=0, t=10, b=0),
                    height=300,
                    yaxis=dict(autorange="reversed"),
                )
                st.plotly_chart(fig, use_container_width=True)

        with right2:
            st.subheader("Hourly Pattern")
            hourly_df = sys_analyzer.hourly_pattern()
            if not hourly_df.empty:
                fig = px.bar(hourly_df, x="hour", y="count")
                fig.update_layout(margin=dict(l=0, r=0, t=10, b=0), height=300)
                st.plotly_chart(fig, use_container_width=True)

        st.divider()

        st.subheader("Errors Over Time")
        err_df = sys_analyzer.errors_over_time()
        if not err_df.empty:
            fig = px.area(err_df, x="timestamp", y="count")
            fig.update_layout(margin=dict(l=0, r=0, t=10, b=0), height=250)
            st.plotly_chart(fig, use_container_width=True)
