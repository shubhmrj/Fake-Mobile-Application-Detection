"""
Logging Capture Module for BankShield
Captures real-time androguard logs for streaming to frontend
"""

import logging
import re
from datetime import datetime
from threading import Lock

# ── Real-time Log Storage ────────────────────────
scan_logs = []  # Global list to store logs during scan
scan_logs_lock = Lock()
current_scan_id = None


class CaptureHandler(logging.Handler):
    """Custom handler to capture logs for streaming to frontend"""

    def __init__(self):
        super().__init__()
        self.setLevel(logging.DEBUG)

    def emit(self, record):
        global scan_logs
        # Parse log format to extract components
        msg = self.format(record)

        # Try to extract module, function, line from the message
        # Format: module.func:line - message
        match = re.match(r'(\S+?):(\S+?):(\d+)\s+-\s+(.+)', msg)
        if match:
            module, func, line, message = match.groups()
        else:
            # Fallback: use record's info
            module = record.name
            func = record.funcName
            line = str(record.lineno)
            message = record.getMessage()

        log_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            'level': record.levelname,
            'module': module,
            'function': func,
            'line': line,
            'message': message
        }

        with scan_logs_lock:
            scan_logs.append(log_entry)
            # Keep only last 500 logs to prevent memory bloat
            if len(scan_logs) > 500:
                scan_logs = scan_logs[-500:]


def setup_logging_capture():
    """Setup the logging capture handler and attach to relevant loggers"""

    # Setup capture handler
    capture_handler = CaptureHandler()
    capture_handler.setFormatter(
        logging.Formatter('%(name)s:%(funcName)s:%(lineno)s - %(message)s')
    )

    # Attach to androguard loggers
    androguard_loggers = [
        logging.getLogger('androguard'),
        logging.getLogger('androguard.core'),
        logging.getLogger('androguard.core.analysis'),
        logging.getLogger('androguard.core.analysis.analysis'),
        logging.getLogger('androguard.core.bytecodes'),
        logging.getLogger('androguard.core.bytecodes.apk'),
        logging.getLogger('androguard.core.bytecodes.dvm'),
        logging.getLogger('apk_extractor'),
    ]

    for logger in androguard_loggers:
        logger.addHandler(capture_handler)
        logger.setLevel(logging.DEBUG)

    # Also capture root logger
    logging.getLogger().addHandler(capture_handler)

    return capture_handler


def clear_logs():
    """Clear logs at start of new scan"""
    global scan_logs, current_scan_id
    with scan_logs_lock:
        scan_logs = []
    current_scan_id = datetime.now().strftime('%Y%m%d%H%M%S')


def get_logs(since=0):
    """Get logs after the given index"""
    with scan_logs_lock:
        if since < len(scan_logs):
            return {
                'logs': scan_logs[since:],
                'total': len(scan_logs),
                'scan_id': current_scan_id
            }
        return {'logs': [], 'total': len(scan_logs), 'scan_id': current_scan_id}
