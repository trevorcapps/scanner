"""Report generation service — extracted from vuln_scan.py and app.py."""

import os
import logging
from datetime import datetime

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from artemis.utils.validation import validate_ip, validate_hostname
from artemis.utils.dns import ScanError, resolve_target
from artemis.utils.network import sanitize_filename
from artemis.services.scan_service import get_latest_scan, get_previous_scan, compare_scans, store_scan
from artemis.services.vuln_service import get_unified_vulnerabilities
from artemis.scanners.nmap_scanner import scan as nmap_scan, parse_scan

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def generate_report_from_existing(ip):
    """Generate a report from existing scan data without performing a new scan."""
    if not validate_ip(ip) and not validate_hostname(ip):
        raise ScanError(f"Invalid target: {ip}")
    if not validate_ip(ip):
        ip = resolve_target(ip)

    import sqlite3
    conn = sqlite3.connect(os.path.join(BASE_DIR, 'vuln_scan.db'))
    cursor = conn.cursor()
    try:
        cursor.execute('''SELECT MAX(scan_date) FROM scans WHERE ip = ?''', (ip,))
        result = cursor.fetchone()
        latest_date = result[0] if result else None

        if not latest_date:
            raise ScanError(f"No scan data found for {ip}")

        cursor.execute('''SELECT protocol, port, state, service, product, version
                          FROM scans WHERE ip = ? AND scan_date = ?''', (ip, latest_date))
        latest_scan = cursor.fetchall()

        if not latest_scan:
            return [], {'added': [], 'removed': [], 'changed': [], 'latest_date': latest_date, 'previous_date': None}, []

        previous_scan, previous_date = get_previous_scan(ip, latest_date)
        vulnerabilities = get_unified_vulnerabilities(ip=ip)

        if not previous_scan:
            changes = {
                'added': latest_scan, 'removed': [], 'changed': [],
                'latest_date': latest_date, 'previous_date': None
            }
            return latest_scan, changes, vulnerabilities

        changes = compare_scans(previous_scan, latest_scan)
        changes['latest_date'] = latest_date
        changes['previous_date'] = previous_date

        return latest_scan, changes, vulnerabilities
    except Exception as e:
        raise ScanError(f"Database error: {e}")
    finally:
        conn.close()


def generate_report(ip):
    """Generate a vulnerability report by performing a new scan."""
    if not validate_ip(ip) and not validate_hostname(ip):
        raise ScanError(f"Invalid target: {ip}")
    if not validate_ip(ip):
        ip = resolve_target(ip)

    latest_scan = get_latest_scan(ip)

    current_scan_result = nmap_scan(ip)
    parsed_current_scan = parse_scan(current_scan_result)

    if not parsed_current_scan:
        return parsed_current_scan, {'added': [], 'removed': [], 'changed': []}

    store_scan(ip, parsed_current_scan)

    if not latest_scan:
        return parsed_current_scan, {'added': parsed_current_scan, 'removed': [], 'changed': []}

    changes = compare_scans(latest_scan, parsed_current_scan)
    return parsed_current_scan, changes


def generate_report_plot(ip):
    """Generate a matplotlib plot showing port scan trends over time."""
    import sqlite3
    db_path = os.path.join(BASE_DIR, 'vuln_scan.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        cursor.execute('''SELECT scan_date, COUNT(*)
                          FROM scans
                          WHERE ip = ?
                          GROUP BY scan_date
                          ORDER BY scan_date''', (ip,))
        data = cursor.fetchall()

        if not data:
            return

        dates = []
        counts = []
        for row in data:
            try:
                date_str = row[0]
                if '.' in date_str:
                    dates.append(datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S.%f'))
                else:
                    dates.append(datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S'))
                counts.append(row[1])
            except ValueError:
                continue

        if not dates:
            return

        plt.figure()
        plt.plot(dates, counts, marker='o')
        plt.title(f'Open Ports Over Time for {ip}')
        plt.xlabel('Date')
        plt.ylabel('Number of Open Ports')
        plt.grid(True)
        plt.xticks(rotation=45)
        plt.tight_layout()

        safe_filename = f'report_{sanitize_filename(ip)}.png'
        plt.savefig(os.path.join(BASE_DIR, 'static', safe_filename))
        logger.info(f"Generated report plot: {safe_filename}")
    except Exception as e:
        logger.error(f"Error generating plot for {ip}: {e}")
    finally:
        plt.close()
        conn.close()


def generate_report_view(ip):
    """Generate and render a report for an existing asset (Flask view helper)."""
    from flask import render_template

    try:
        try:
            from artemis.utils.dns import resolve_ip_param
            ip = resolve_ip_param(ip)
        except (ValueError, ScanError) as e:
            return render_template('report.html', ip=ip, error=str(e))

        scan_results, changes, vulnerabilities = generate_report_from_existing(ip)
        generate_report_plot(ip)
        return render_template('report.html', ip=ip, scan_results=scan_results,
                               changes=changes, vulnerabilities=vulnerabilities)
    except ScanError as e:
        return render_template('report.html', ip=ip, error=str(e))
    except Exception as e:
        logger.error(f"Unexpected error generating report for {ip}: {e}")
        return render_template('report.html', ip=ip, error="An unexpected error occurred.")


def handle_scan_post(request):
    """Handle POST /scan form submission (Flask view helper)."""
    from flask import render_template

    ip = request.form.get('ip', '').strip()
    if not ip:
        return render_template('report.html', ip=ip, error="IP address is required.")

    from artemis.utils.validation import validate_target
    if not validate_target(ip):
        return render_template('report.html', ip=ip, error="Invalid target.")

    try:
        scan_results, changes = generate_report(ip)
        generate_report_plot(ip)
        return render_template('report.html', ip=ip, scan_results=scan_results, changes=changes)
    except ScanError as e:
        return render_template('report.html', ip=ip, error=str(e))
    except Exception as e:
        logger.error(f"Unexpected error scanning {ip}: {e}")
        return render_template('report.html', ip=ip, error="An unexpected error occurred.")
