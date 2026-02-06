import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import click

from src.analyzer import SystemLogAnalyzer, TrafficAnalyzer
from src.anomaly import AnomalyDetector
from src.database import LogDatabase
from src.parser import AccessEntry, LogParser, SystemLogEntry
from src.watcher import LogWatcher


@click.group()
def cli():
    pass


@cli.command()
@click.argument("filepath")
def parse(filepath):
    if not os.path.isfile(filepath):
        click.echo(f"File not found: {filepath}")
        return

    parser = LogParser()
    fmt = parser.detect_format(filepath)
    click.echo(f"Detected format: {fmt or 'unknown'}")

    access_entries, system_entries = parser.parse_file_by_type(filepath)

    if not access_entries and not system_entries:
        click.echo("No valid entries found.")
        return

    db = LogDatabase()

    if access_entries:
        db.insert_entries(access_entries)
        click.echo(f"Inserted {len(access_entries)} access log entries.")

    if system_entries:
        db.insert_system_entries(system_entries)
        click.echo(f"Inserted {len(system_entries)} system log entries.")


@cli.command()
def summary():
    db = LogDatabase()
    access_count = db.get_entry_count()
    system_count = db.get_system_entry_count()

    if access_count == 0 and system_count == 0:
        click.echo("No data. Parse a log file first.")
        return

    if access_count > 0:
        info = db.get_summary()
        click.echo(f"\n--- Access Logs ---")
        click.echo(f"Total requests : {info['total']}")
        click.echo(f"Unique IPs     : {info['unique_ips']}")
        click.echo(f"First entry    : {info['first_entry']}")
        click.echo(f"Last entry     : {info['last_entry']}")
        click.echo(f"Total bytes    : {info['total_bytes']:,}")

        click.echo("\nTop IPs:")
        for row in db.get_top_ips(5):
            click.echo(f"  {row['ip']:20s} {row['count']:>6d}")

        click.echo("\nTop Paths:")
        for row in db.get_top_paths(5):
            click.echo(f"  {row['path']:40s} {row['count']:>6d}")

        click.echo("\nStatus Codes:")
        for row in db.get_status_distribution():
            click.echo(f"  {row['status']}  {row['count']:>6d}")

        analyzer = TrafficAnalyzer(db)
        hourly = analyzer.hourly_pattern()
        if not hourly.empty:
            click.echo("\nHourly Pattern:")
            for _, row in hourly.iterrows():
                bar = "#" * (row["count"] // max(1, hourly["count"].max() // 30))
                click.echo(f"  {int(row['hour']):02d}:00  {bar} ({row['count']})")

    if system_count > 0:
        info = db.get_system_summary()
        click.echo(f"\n--- System Logs ---")
        click.echo(f"Total entries  : {info['total']}")
        click.echo(f"Unique sources : {info['unique_sources']}")
        click.echo(f"Unique hosts   : {info['unique_hosts']}")
        click.echo(f"First entry    : {info['first_entry']}")
        click.echo(f"Last entry     : {info['last_entry']}")

        click.echo("\nLog Levels:")
        for row in db.get_level_distribution():
            click.echo(f"  {row['level']:12s} {row['count']:>6d}")

        click.echo("\nTop Sources:")
        for row in db.get_top_sources(5):
            click.echo(f"  {row['source']:30s} {row['count']:>6d}")

        sys_analyzer = SystemLogAnalyzer(db)
        hourly = sys_analyzer.hourly_pattern()
        if not hourly.empty:
            click.echo("\nHourly Pattern:")
            for _, row in hourly.iterrows():
                bar = "#" * (row["count"] // max(1, hourly["count"].max() // 30))
                click.echo(f"  {int(row['hour']):02d}:00  {bar} ({row['count']})")


@cli.command()
def anomalies():
    db = LogDatabase()
    access_count = db.get_entry_count()
    system_count = db.get_system_entry_count()

    if access_count == 0 and system_count == 0:
        click.echo("No data. Parse a log file first.")
        return

    detector = AnomalyDetector(db)
    results = detector.detect_all()

    if not results:
        click.echo("No anomalies detected.")
        return

    click.echo(f"\nDetected {len(results)} anomalies:\n")
    for a in results:
        click.echo(f"  [{a['type']}] {a['description']}")


@cli.command()
@click.argument("filepath")
def watch(filepath):
    if not os.path.isfile(filepath):
        click.echo(f"File not found: {filepath}")
        return

    click.echo(f"Watching {filepath} for changes... (Ctrl+C to stop)")
    db = LogDatabase()
    watcher = LogWatcher(filepath, db)
    watcher.start()


@cli.command()
def resetdb():
    db = LogDatabase()
    db.reset()
    click.echo("Database reset successfully.")


if __name__ == "__main__":
    cli()
