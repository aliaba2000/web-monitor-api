from flask import Flask, request, jsonify
import requests
import ssl
import socket
import datetime

app = Flask(__name__)

def get_ssl_info(hostname):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()
        expires_str = cert['notAfter']
        expires = datetime.datetime.strptime(expires_str, '%b %d %H:%M:%S %Y %Z')
        days_left = (expires - datetime.datetime.utcnow()).days
        return {
            "valid": True,
            "expires": expires.strftime('%Y-%m-%d'),
            "days_left": days_left,
            "subject": dict(x[0] for x in cert['subject']).get('commonName', ''),
            "issuer": dict(x[0] for x in cert['issuer']).get('organizationName', '')
        }
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "error": str(e)}
    except Exception as e:
        return {"valid": None, "error": str(e)}

@app.route('/')
def index():
    return jsonify({
        "service": "Web Monitor API",
        "usage": "/check?url=https://example.com",
        "params": {
            "url": "adres URL do sprawdzenia (wymagane)"
        }
    })

@app.route('/check')
def http_check():
    url = request.args.get('url')
    if not url:
        return jsonify({"error": "Parametr 'url' jest wymagany"}), 400
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    result = {
        "url": url,
        "checked_at": datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    }

    try:
        start = datetime.datetime.utcnow()
        resp = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 WebMonitor/1.0"}
        )
        elapsed_ms = int((datetime.datetime.utcnow() - start).total_seconds() * 1000)

        redirects = []
        for r in resp.history:
            redirects.append({
                "url": r.url,
                "status_code": r.status_code
            })

        result["status_code"] = resp.status_code
        result["response_time_ms"] = elapsed_ms
        result["final_url"] = resp.url
        result["redirects"] = redirects
        result["redirect_count"] = len(redirects)
        result["headers"] = {
            "server": resp.headers.get("Server", ""),
            "content_type": resp.headers.get("Content-Type", ""),
            "x_powered_by": resp.headers.get("X-Powered-By", ""),
            "strict_transport_security": resp.headers.get("Strict-Transport-Security", ""),
        }

    except requests.exceptions.Timeout:
        result["error"] = "Timeout po 10 sekundach"
        return jsonify(result), 504
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"Błąd połączenia: {str(e)}"
        return jsonify(result), 502
    except Exception as e:
        result["error"] = str(e)
        return jsonify(result), 500

    if url.startswith('https://'):
        hostname = url.split('/')[2].split(':')[0]
        result["ssl"] = get_ssl_info(hostname)

    return jsonify(result)

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
