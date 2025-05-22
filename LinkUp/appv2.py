from flask import Flask, request, jsonify, render_template, redirect
import hashlib
import hmac
import time
import os
import json
from functools import wraps
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
import base64

app = Flask(__name__)

# File paths
device_file = "devices.json"
pending_file = "pending.json"


def load_json(path):
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}


def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


# ----------------------------------------------------------------verify_and_sign_v


def local_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.remote_addr != "127.0.0.1":
            return "Access denied", 403
        return f(*args, **kwargs)

    return decorated_function


def raw_signature_to_der(raw_sig):
    # raw_sig is 64 bytes (r(32) + s(32)) for P-256 curve
    r = int.from_bytes(raw_sig[: len(raw_sig) // 2], byteorder="big")
    s = int.from_bytes(raw_sig[len(raw_sig) // 2 :], byteorder="big")
    return encode_dss_signature(r, s)


def verify_signature(pubkey_b64, signature_b64, message):
    pubkey_der = base64.b64decode(pubkey_b64)
    raw_signature = base64.b64decode(signature_b64)
    public_key = serialization.load_der_public_key(pubkey_der)
    try:
        der_signature = raw_signature_to_der(raw_signature)
        public_key.verify(
            der_signature, message.encode("utf-8"), ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception as e:
        print("Signature verification failed:", e)
        return False


def is_device_verified(device_id, message, signature_b64):
    approved_data = load_json(device_file)
    device_entry = next(
        (d for d in approved_data.get("devices", []) if d["device"] == device_id), None
    )
    if not device_entry:
        return False
    pubkey_b64 = device_entry["publicKey"]
    return verify_signature(pubkey_b64, signature_b64, message)


# ------------------ Helper Functions ------------------ #
@app.route("/test")  # Main page---------------------------------------------------
def test():
    return render_template("base_template.html", page_title="test")


@app.route("/")  # index page---------------------------------------------------
def index():
    return render_template("index.html", page_title="/")


@app.route("/home")  # Main page---------------------------------------------------
def home():
    return render_template("home.html", page_title="home")


@app.route("/settings")  # Main page---------------------------------------------------
def settings():
    return render_template("settings.html", page_title="settings")


@app.route("/api/pending", methods=["GET"])
def get_pending_devices():
    pending = load_json(pending_file)
    return jsonify(pending)


@app.route("/api/devices", methods=["GET"])
def get_approved_devices():
    devices = load_json(device_file)
    return jsonify(devices)


@app.route("/enroll", methods=["GET"])
def enroll():
    if request.method == "POST":
        print("POST request received")
        device_name = request.form.get("device_name")
        print(f"Device name: {device_name}")

    # Get full server URL (e.g., http://192.168.1.42:5000)
    server_url = request.host_url.rstrip("/")
    return render_template("enroll.html", server_url=server_url, page_title="enroll")


@app.route("/api/enroll", methods=["POST"])
def api_enroll():
    print("API Enroll request received")
    data = request.get_json()

    if not data:
        return jsonify({"error": "No JSON data received"}), 400

    device_name = data.get("device")
    public_key = data.get("publicKey")

    if not device_name or not public_key:
        return jsonify({"error": "Missing device or publicKey"}), 400

    browser_info = request.headers.get("User-Agent", "Unknown")
    device_ip = request.remote_addr

    # Load current data
    pending_data = load_json(pending_file)

    # Make sure there's a 'requests' list to append to
    if "requests" not in pending_data:
        pending_data["requests"] = []

    # Add the new request
    pending_data["requests"].append(
        {
            "device": device_name,
            "publicKey": public_key,
            "browser": browser_info,
            "device_ip": device_ip,
        }
    )

    # Save back
    save_json(pending_file, pending_data)

    print(f"Stored pending request for device: {device_name}, device_ip: {device_ip}")
    return jsonify({"status": "enroll request received", "device": device_name}), 200


@app.route("/admin")  # Admin page---------------------------------------------
@local_only
def admin_panel():
    print("Admin panel accessed")
    pending = load_json(pending_file)
    devices = load_json(device_file)
    return render_template("admin.html", page_title="admin")


@app.route("/api/approve", methods=["POST"])
@local_only
def approve_device():
    data = request.get_json()
    device_id = data.get("device")

    if not device_id:
        return jsonify({"error": "Missing device name"}), 400

    pending_data = load_json(pending_file)
    approved_data = load_json(device_file)

    # Find device in pending list
    device_entry = next(
        (d for d in pending_data.get("requests", []) if d["device"] == device_id), None
    )

    if device_entry:
        # Add to approved list
        approved_data.setdefault("devices", []).append(device_entry)

        # Remove from pending list
        pending_data["requests"] = [
            d for d in pending_data["requests"] if d["device"] != device_id
        ]

        # Save both files
        save_json(pending_file, pending_data)
        save_json(device_file, approved_data)

        return jsonify({"status": "approved", "device": device_id})
    else:
        return jsonify({"error": "Device not found in pending"}), 404


@app.route("/api/deny", methods=["POST"])
@local_only
def deny_device():
    data = request.get_json()
    device_id = data.get("device")

    if not device_id:
        return jsonify({"error": "Missing device name"}), 400

    pending_data = load_json(pending_file)

    # Check if device exists
    device_entry = next(
        (d for d in pending_data.get("requests", []) if d["device"] == device_id), None
    )

    if device_entry:
        # Remove from pending list
        pending_data["requests"] = [
            d for d in pending_data["requests"] if d["device"] != device_id
        ]

        # Save updated pending list
        save_json(pending_file, pending_data)

        return jsonify({"status": "denied", "device": device_id})
    else:
        return jsonify({"error": "Device not found in pending"}), 404


@app.route("/api/control", methods=["POST"])
def control():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data received"}), 400

    device_id = data.get("device")
    command = data.get("command")
    signature_b64 = data.get("signature")

    print(signature_b64)
    print(device_id)
    print(command)

    if not all([device_id, command, signature_b64]):
        return jsonify({"error": "Missing device, command, or signature"}), 400

    if not is_device_verified(device_id, command, signature_b64):
        return jsonify({"error": "Invalid device or signature"}), 403

    if command == "verifyed_ya_connect":
        return_data = jsonify({"status": "OK_continue"}), 200
    else:
        return_data = (
            jsonify(
                {"status": "Command accepted", "device": device_id, "command": command}
            ),
            200,
        )
    return return_data


@app.route("/control_panel", methods=["GET", "POST"])  # Control page-----------------
def control_panel():
    if request.method == "POST":
        command = request.form.get("command")
        print(f"Command received: {command}")

        # Run your logic here (dummy example)
        result = f"Command '{command}' executed successfully."

        return jsonify({"status": "success", "message": result})
    else:
        return render_template("control.html", page_title="control panel")


print(app.url_map)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
