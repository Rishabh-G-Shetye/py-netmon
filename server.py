# server.py
from flask import Flask, request, render_template, jsonify
from flask_socketio import SocketIO, emit
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = 'change-this-to-something-secret'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

logging.basicConfig(level=logging.INFO)

# Keep a small in-memory recent list to show on initial client load
RECENT = []
MAX_RECENT = 200

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/report', methods=['POST'])
def report():
    """
    Receives JSON report from the sniffer.
    Expects JSON representation of the Pckt object
    (fields: ipsrc, ipdst, srcport, dstport, transport_layer,
    highest_layer, time_stamp).
    """
    try:
        data = request.get_json(force=True)
    except Exception as e:
        app.logger.exception("Bad JSON")
        return jsonify({"status": "bad-json", "error": str(e)}), 400

    # Basic validation
    if not data or ('ipsrc' not in data and 'ipdst' not in data):
        return jsonify({"status": "bad-request"}), 400

    # Add to recent list
    RECENT.append(data)
    if len(RECENT) > MAX_RECENT:
        RECENT.pop(0)

    # Emit to connected socket clients
    socketio.emit('new_packet', data)
    app.logger.info("Reported packet: %s", data)

    return jsonify({"status": "ok"}), 200


@socketio.on('connect')
def on_connect():
    app.logger.info("Client connected")
    # Send recent history to client on connect
    emit('recent_packets', RECENT)


if __name__ == '__main__':
    # Run Socket.IO server with Werkzeug for local testing
    socketio.run(app, host='127.0.0.1', port=5000, allow_unsafe_werkzeug=True)
