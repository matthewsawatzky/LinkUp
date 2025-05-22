async function sendCommand(deviceId, secretHex, command) {
  const secret = new TextEncoder().encode(secretHex);
  const timestamp = Math.floor(Date.now() / 1000).toString();

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(timestamp));
  const token = Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');

  await fetch("http://host.local:8080/send-command", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ device_id: deviceId, timestamp, token, command })
  }).then(r => r.json()).then(console.log);
}

const device_id = localStorage.getItem("device_id");
const secret = localStorage.getItem("secret");

if (!device_id || !secret) {
    alert("You need to enroll first.");
    window.location.href = "/enroll";
}