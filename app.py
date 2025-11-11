# app.py
import os
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, send_from_directory
import sqlite3
from werkzeug.utils import secure_filename
from modules.utils import sha256_of_bytes, extract_printable_strings, entropy, suspicious_shell_text
import pathlib

# Config
BASE_DIR = pathlib.Path(__file__).parent.resolve()
DATA_DIR = BASE_DIR / 'data'
UPLOAD_DIR = DATA_DIR / 'uploads'
DB_PATH = DATA_DIR / 'db.sqlite3'
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = 'replace-this-secret'  # troque em deploy real!
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB uploads
ALLOWED_EXT = {'txt','bin','exe','elf','zip','pdf'}

def get_db():
    if not DB_PATH.exists():
        # create DB initial by running init_db
        import init_db
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Index
@app.route('/')
def index():
    return render_template('index.html')

# -----------------------
# XSS Playground
# -----------------------
@app.route('/xss', methods=['GET','POST'])
def xss():
    conn = get_db()
    c = conn.cursor()
    if request.method == 'POST':
        name = request.form.get('name','Anonymous')
        message = request.form.get('message','')
        # stored XSS: save text (inert) and display later
        c.execute('INSERT INTO xss_messages (name,message) VALUES (?,?)', (name, message))
        conn.commit()
        flash('Mensagem salva (stored). Vá para "Mostrar mensagens" para ver.')
        return redirect(url_for('xss'))
    # show messages
    c.execute('SELECT id,name,message FROM xss_messages ORDER BY id DESC LIMIT 20')
    msgs = c.fetchall()
    conn.close()
    return render_template('xss.html', messages=msgs)

@app.route('/xss/reflect')
def xss_reflect():
    q = request.args.get('q','')
    return render_template('xss.html', reflect=q, messages=[])

# -----------------------
# Headers / Cookies (Burp playground)
# -----------------------
@app.route('/headers', methods=['GET','POST'])
def headers():
    headers = dict(request.headers)
    cookies = request.cookies
    body = request.get_data(as_text=True)
    return render_template('headers.html', headers=headers, cookies=cookies, body=body)

# -----------------------
# SQLi lab
# -----------------------
@app.route('/sqli', methods=['GET','POST'])
def sqli():
    mode = request.args.get('mode','vulnerable')  # vulnerable or safe
    result = None
    query = ''
    if request.method == 'POST':
        username = request.form.get('username','')
        password = request.form.get('password','')
        conn = get_db()
        c = conn.cursor()
        if mode == 'vulnerable':
            # VULNERABLE: string concatenation (educational only)
            query = f"SELECT id,username,fullname FROM users WHERE username = '{username}' AND password = '{password}';"
            try:
                rows = c.execute(query).fetchall()
            except Exception as e:
                rows = []
            result = [dict(r) for r in rows]
        else:
            # SAFE: prepared statement
            query = "SELECT id,username,fullname FROM users WHERE username = ? AND password = ?;"
            rows = c.execute(query, (username, password)).fetchall()
            result = [dict(r) for r in rows]
        conn.close()
    return render_template('sqli.html', mode=mode, result=result, query=query)

# -----------------------
# Reverse shell detection (text)
# -----------------------
@app.route('/shell', methods=['GET','POST'])
def shell():
    analysis = None
    text = ''
    if request.method == 'POST':
        text = request.form.get('payload','')
        analysis = suspicious_shell_text(text)
    return render_template('shell.html', analysis=analysis, text=text)

# -----------------------
# Binary analyzer (upload - static analysis only)
# -----------------------
def allowed_filename(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXT

@app.route('/binary', methods=['GET','POST'])
def binary():
    report = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or f.filename == '':
            flash('Nenhum arquivo selecionado')
            return redirect(url_for('binary'))
        filename = secure_filename(f.filename)
        if not allowed_filename(filename):
            flash('Tipo de arquivo não permitido. Extensões permitidas: ' + ','.join(sorted(ALLOWED_EXT)))
            return redirect(url_for('binary'))
        saved_path = UPLOAD_DIR / filename
        b = f.read()
        # save safely
        with open(saved_path, 'wb') as out:
            out.write(b)
        # static analysis
        sha256 = sha256_of_bytes(b)
        strings = extract_printable_strings(b)
        ent = entropy(b)
        suspicious = [s for s in strings if any(x in s.lower() for x in ('cmd.exe','createprocess','socket','connect','exec','system','powershell','curl','wget'))]
        report = {
            'filename': filename,
            'size': len(b),
            'sha256': sha256,
            'entropy': ent,
            'suspicious_strings': suspicious[:40],
            'strings_sample': strings[:80]
        }
    return render_template('binary.html', report=report)

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(str(UPLOAD_DIR), filename, as_attachment=True)

# -----------------------
# Network malware detection (simple IOC matching)
# -----------------------
IOC_LIST = {
    'bad_ips': ['10.0.0.123','203.0.113.5','198.51.100.9'],
    'bad_domains': ['malicious.example','bad-actor.test']
}

@app.route('/network', methods=['GET','POST'])
def network():
    findings = None
    data = ''
    if request.method == 'POST':
        data = request.form.get('netlog','')
        found_ips = [ip for ip in IOC_LIST['bad_ips'] if ip in data]
        found_dom = [d for d in IOC_LIST['bad_domains'] if d in data]
        findings = {
            'found_ips': found_ips,
            'found_domains': found_dom,
            'raw': data[:10000]
        }
    return render_template('network.html', findings=findings, ioc=IOC_LIST)

if __name__ == '__main__':
    if not DB_PATH.exists():
        import subprocess, sys
        subprocess.run([sys.executable, 'init_db.py'])
    app.run(host='0.0.0.0', port=5000, debug=True)
