"""
Flask Web Application with SocketIO for real-time updates
"""
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import logging
import os
from config import Config
from core import oui_db

logger = logging.getLogger(__name__)

oui_db.load()


def _build_stats():
    data = sniffer.get_stats()
    data['oui_db'] = {
        'loaded':      oui_db.is_loaded(),
        'entry_count': oui_db.entry_count(),
        'source':      oui_db.source_path(),
    }
    return data

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or os.urandom(24)

_ALLOWED_ORIGINS = os.environ.get('CORS_ORIGINS', '').split() or [
    f'http://localhost:{Config.PORT}',
    f'http://127.0.0.1:{Config.PORT}',
]
CORS(app, origins=_ALLOWED_ORIGINS)

socketio = SocketIO(app, cors_allowed_origins=_ALLOWED_ORIGINS)

sniffer = None


def set_sniffer(sniffer_instance):
    global sniffer
    sniffer = sniffer_instance
    sniffer.register_alert_callback(emit_alert_to_clients)


def emit_alert_to_clients(alert):
    socketio.emit('alert', alert, namespace='/')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/stats')
def get_stats():
    if sniffer:
        data = sniffer.get_stats()
        data['oui_db'] = {
            'loaded':      oui_db.is_loaded(),
            'entry_count': oui_db.entry_count(),
            'source':      oui_db.source_path(),
        }
        return jsonify(data)
    return jsonify({'error': 'Sniffer not initialized'}), 503


@app.route('/api/alerts')
def get_alerts():
    if sniffer:
        _SYSTEM_TYPES = {
            'BASELINE_COMPLETE', 'SCAN_STARTED', 'SCAN_STOPPED',
            'MONITOR_MODE_FALLBACK', 'OUI_DB_LOADED', 'OUI_DB_MISSING',
        }
        alerts = [
            a for a in sniffer.alert_manager.get_recent_alerts(limit=200)
            if a.get('type') not in _SYSTEM_TYPES
        ]
        return jsonify(alerts)
    return jsonify({'error': 'Sniffer not initialized'}), 503


@app.route('/api/packets')
def get_packets():
    if sniffer:
        packets = list(sniffer.recent_packets)[-50:]  # Last 50 packets
        return jsonify(packets)
    return jsonify({'error': 'Sniffer not initialized'}), 503


@app.route('/api/devices')
def get_devices():
    if sniffer:
        devices_info = sniffer.device_fingerprinter.get_stats()
        return jsonify(devices_info.get('discovered_devices', []))
    return jsonify({'error': 'Sniffer not initialized'}), 503


@app.route('/api/start', methods=['POST'])
def start_sniffer():
    if sniffer:
        data = request.get_json(silent=True) or {}
        baseline_enabled = data.get('baseline', False)

        sniffer.start()

        if baseline_enabled:
            try:
                duration = int(data.get('baseline_duration', Config.BASELINE_DURATION))
            except (TypeError, ValueError):
                duration = Config.BASELINE_DURATION
            duration = max(30, min(duration, 3600))
            sniffer.mitm_detector.start_baseline(duration)
            socketio.emit('baseline_status', sniffer.mitm_detector.get_baseline_status())

        return jsonify({'status': 'started', 'baseline': baseline_enabled})
    return jsonify({'error': 'Sniffer not initialized'}), 503


@app.route('/api/stop', methods=['POST'])
def stop_sniffer():
    if sniffer:
        sniffer.stop()
        return jsonify({'status': 'stopped'})
    return jsonify({'error': 'Sniffer not initialized'}), 503


@app.route('/api/alerts/clear', methods=['POST'])
def clear_alerts_route():
    if not sniffer:
        return jsonify({'error': 'Sniffer not initialized'}), 503
    data = request.get_json(silent=True) or {}
    types_to_clear = data.get('types')
    if types_to_clear and isinstance(types_to_clear, list):
        type_set = set(types_to_clear)
        keep = [a for a in sniffer.alert_manager.alerts if a['type'] not in type_set]
        sniffer.alert_manager.alerts.clear()
        sniffer.alert_manager.alerts.extend(keep)
    else:
        sniffer.alert_manager.clear_alerts()
    return jsonify({'status': 'cleared'})


@app.route('/api/baseline/start', methods=['POST'])
def start_baseline():
    if not sniffer:
        return jsonify({'error': 'Sniffer not initialized'}), 503
    data = request.get_json(silent=True) or {}
    try:
        duration = int(data.get('duration', Config.BASELINE_DURATION))
    except (TypeError, ValueError):
        return jsonify({'error': 'Invalid duration'}), 400
    duration = max(30, min(duration, 3600))  # clamp: 30 s – 60 min
    sniffer.mitm_detector.start_baseline(duration)
    socketio.emit('baseline_status', sniffer.mitm_detector.get_baseline_status())
    return jsonify({'status': 'started', 'duration': duration})


@app.route('/api/baseline/status', methods=['GET'])
def get_baseline_status():
    if not sniffer:
        return jsonify({'error': 'Sniffer not initialized'}), 503
    return jsonify(sniffer.mitm_detector.get_baseline_status())


@socketio.on('connect')
def handle_connect():
    logger.info('Client connected')
    emit('connected', {'status': 'connected'})

    if sniffer:
        emit('stats', _build_stats())


@socketio.on('disconnect')
def handle_disconnect():
    logger.info('Client disconnected')


@socketio.on('request_stats')
def handle_stats_request():
    if sniffer:
        emit('stats', _build_stats())
        emit('baseline_status', sniffer.mitm_detector.get_baseline_status())


@socketio.on('request_packets')
def handle_packets_request():
    if sniffer:
        packets = list(sniffer.recent_packets)[-50:]
        emit('packets', packets)


@socketio.on('request_devices')
def handle_devices_request():
    if sniffer:
        devices_info = sniffer.device_fingerprinter.get_stats()
        emit('devices', devices_info.get('discovered_devices', []))


def run_server(host=None, port=None, debug=None):
    host = host or Config.HOST
    port = port or Config.PORT
    debug = debug if debug is not None else Config.DEBUG
    
    logger.info(f"Starting web server on {host}:{port}")
    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)
