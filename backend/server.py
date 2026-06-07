#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
财务管理刷题 - 后端认证服务器（一码一用）
"""

import os
import re
import json
import hashlib
import secrets
import sqlite3
import datetime
from functools import wraps
from flask import Flask, request, jsonify, g
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

DATABASE = os.path.join(os.path.dirname(__file__), 'quiz_data.db')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123456')

# ==================== Database ====================

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DATABASE)
    db.execute('''
        CREATE TABLE IF NOT EXISTS activation_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'unused' CHECK(status IN ('unused','used','disabled')),
            device_id TEXT,
            used_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            batch_id TEXT DEFAULT 'default',
            note TEXT DEFAULT ''
        )
    ''')
    db.commit()

    # Pre-populate 200 activation codes if empty
    count = db.execute('SELECT COUNT(*) as cnt FROM activation_codes').fetchone()['cnt']
    if count == 0:
        codes = _generate_deterministic_codes(200)
        for c in codes:
            db.execute('INSERT INTO activation_codes (code, batch_id) VALUES (?, ?)',
                       (c, 'initial-200'))
        db.commit()
        print(f'[INIT] Pre-populated {len(codes)} activation codes')

    db.close()

def _generate_deterministic_codes(count):
    """Generate deterministic activation codes matching the embedded hashes"""
    chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    codes = []
    for i in range(count):
        seed = f'quiz_seed_{i:04d}'
        rng = hashlib.sha256(seed.encode()).digest()
        code = ''.join(chars[rng[j] % len(chars)] for j in range(12))
        codes.append(code[:4] + '-' + code[4:8] + '-' + code[8:12])
    return codes

# ==================== Activation API (no auth needed) ====================

@app.route('/api/activate', methods=['POST'])
def activate():
    """
    激活码验证（一码一用）
    POST { code: "XXXX-XXXX-XXXX", device: "device_fingerprint" }
    成功返回 { token, message }
    """
    data = request.get_json() or {}
    raw_code = data.get('code', '').strip().upper().replace('-', '').replace(' ', '')
    device_id = data.get('device', 'unknown')

    if len(raw_code) != 12:
        return jsonify({'error': '激活码格式不正确'}), 400

    formatted = raw_code[:4] + '-' + raw_code[4:8] + '-' + raw_code[8:12]
    db = get_db()

    ac = db.execute('SELECT * FROM activation_codes WHERE code = ?', (formatted,)).fetchone()

    if not ac:
        return jsonify({'error': '激活码无效'}), 400

    if ac['status'] == 'used':
        if ac['device_id'] == device_id:
            # Same device, allow re-use
            token = secrets.token_hex(32)
            return jsonify({'token': token, 'message': '激活成功（已绑定此设备）', 'code': formatted})
        return jsonify({'error': '该激活码已被使用'}), 400

    if ac['status'] == 'disabled':
        return jsonify({'error': '该激活码已被禁用'}), 400

    # Mark as used
    db.execute(
        'UPDATE activation_codes SET status = ?, device_id = ?, used_at = ? WHERE id = ?',
        ('used', device_id, datetime.datetime.now().isoformat(), ac['id'])
    )
    db.commit()

    token = secrets.token_hex(32)
    return jsonify({'token': token, 'message': '激活成功', 'code': formatted})

@app.route('/api/check-device', methods=['POST'])
def check_device():
    """检查设备是否已激活"""
    data = request.get_json() or {}
    device_id = data.get('device', 'unknown')
    db = get_db()
    used = db.execute(
        'SELECT code, used_at FROM activation_codes WHERE device_id = ? AND status = ?',
        (device_id, 'used')
    ).fetchone()
    if used:
        return jsonify({'activated': True, 'code': used['code'], 'used_at': used['used_at']})
    return jsonify({'activated': False})

# ==================== Admin APIs ====================

def admin_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if token != ADMIN_PASSWORD:
            return jsonify({'error': '管理员密码错误'}), 403
        return f(*args, **kwargs)
    return decorated

@app.route('/api/admin/generate-codes', methods=['POST'])
@admin_auth
def generate_codes():
    """批量追加激活码"""
    data = request.get_json() or {}
    count = int(data.get('count', 1))
    batch_id = data.get('batch_id', datetime.datetime.now().strftime('%Y%m%d'))
    note = data.get('note', '')

    if count < 1 or count > 1000:
        return jsonify({'error': '单次生成数量范围: 1-1000'}), 400

    db = get_db()
    codes = _generate_deterministic_codes(count)
    added = []
    for c in codes:
        existing = db.execute('SELECT id FROM activation_codes WHERE code = ?', (c,)).fetchone()
        if not existing:
            db.execute('INSERT INTO activation_codes (code, batch_id, note) VALUES (?, ?, ?)',
                       (c, batch_id, note))
            added.append(c)
    db.commit()

    return jsonify({'generated': len(added), 'batch_id': batch_id, 'codes': added})

@app.route('/api/admin/codes', methods=['GET'])
@admin_auth
def list_codes():
    """查看激活码列表"""
    db = get_db()
    batch = request.args.get('batch', '')
    status = request.args.get('status', '')
    limit = min(int(request.args.get('limit', 100)), 500)

    query = 'SELECT * FROM activation_codes WHERE 1=1'
    params = []
    if batch:
        query += ' AND batch_id = ?'
        params.append(batch)
    if status:
        query += ' AND status = ?'
        params.append(status)
    query += ' ORDER BY id ASC LIMIT ?'
    params.append(limit)

    rows = db.execute(query, params).fetchall()
    return jsonify([{
        'id': r['id'],
        'code': r['code'],
        'status': r['status'],
        'batch_id': r['batch_id'],
        'note': r['note'],
        'device_id': r['device_id'],
        'used_at': r['used_at'],
        'created_at': r['created_at']
    } for r in rows])

@app.route('/api/admin/stats', methods=['GET'])
@admin_auth
def admin_stats():
    """统计"""
    db = get_db()
    total = db.execute('SELECT COUNT(*) as cnt FROM activation_codes').fetchone()['cnt']
    used = db.execute("SELECT COUNT(*) as cnt FROM activation_codes WHERE status='used'").fetchone()['cnt']
    unused = db.execute("SELECT COUNT(*) as cnt FROM activation_codes WHERE status='unused'").fetchone()['cnt']
    return jsonify({
        'total_codes': total,
        'used_codes': used,
        'unused_codes': unused,
    })

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'time': datetime.datetime.now().isoformat()})

# ==================== Main ====================

if __name__ == '__main__':
    init_db()
    print(f'[ADMIN] Password: {ADMIN_PASSWORD}')
    print('[START] Server running on http://0.0.0.0:5000')
    app.run(host='0.0.0.0', port=5000, debug=False)
