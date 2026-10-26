# -*- coding: utf-8 -*-
"""
用户管理 CLI（v2 SQLite 版）：增删用户、改权限、改角色
用法：
  python manage_users.py list
  python manage_users.py add <username> <password> [--role viewer|editor|admin] [--boards id1,id2|*]
  python manage_users.py del <username>
  python manage_users.py boards <username> <id1,id2|*>
  python manage_users.py role <username> <viewer|editor|admin>
角色：viewer 只读 / editor 可编辑 / admin 全权限
--boards * 表示全部看板可见；默认=全部（*）
"""
import json, os, sys, sqlite3, hashlib, secrets

BASE = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE, 'app.db')

def get_conn():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    return conn

def ensure_table():
    conn = get_conn()
    conn.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'viewer',
        allowed_boards TEXT NOT NULL DEFAULT '*',
        created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
    )""")
    conn.commit()
    conn.close()

def hash_pw(pw):
    salt = secrets.token_hex(8)
    dk = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 100000)
    return f'pbkdf2${salt}${dk.hex()}'

def main():
    ensure_table()
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    cmd = args[0]
    conn = get_conn()

    if cmd == 'list':
        rows = conn.execute('SELECT username, role, allowed_boards FROM users ORDER BY id').fetchall()
        if not rows:
            print('(暂无用户)')
        for r in rows:
            scope = '全部看板' if r['allowed_boards'] == '*' else r['allowed_boards']
            print(f"  {r['username']:<20} 角色: {r['role']:<8} 可见看板: {scope}")
        conn.close()
        return

    if cmd == 'add' and len(args) >= 3:
        name, pw = args[1], args[2]
        exists = conn.execute('SELECT 1 FROM users WHERE username=?', (name,)).fetchone()
        if exists:
            print(f'用户 {name} 已存在'); conn.close(); return
        role = 'viewer'
        if '--role' in args:
            i = args.index('--role')
            role = args[i + 1] if i + 1 < len(args) else 'viewer'
            if role not in ('viewer', 'editor', 'admin'):
                print('角色必须是 viewer/editor/admin'); conn.close(); return
        boards = '*'
        if '--boards' in args:
            i = args.index('--boards')
            raw = args[i + 1] if i + 1 < len(args) else '*'
            boards = '*' if raw == '*' else ','.join(x for x in raw.split(',') if x)
        columns = '*'
        if '--columns' in args:
            i = args.index('--columns')
            columns = args[i + 1] if i + 1 < len(args) else '*'
            if columns != '*':
                json.loads(columns)  # 校验 JSON
        conn.execute('INSERT INTO users (username, password_hash, role, allowed_boards, allowed_columns) VALUES (?,?,?,?,?)',
                     (name, hash_pw(pw), role, boards, columns))
        conn.commit(); conn.close()
        scope = '全部看板' if boards == '*' else boards
        cscope = '全部板块' if columns == '*' else columns
        print(f'已添加用户 {name}，角色: {role}，可见看板: {scope}，板块: {cscope}')
        return

    if cmd == 'del' and len(args) >= 2:
        name = args[1]
        cur = conn.execute('DELETE FROM users WHERE username=?', (name,))
        conn.commit(); conn.close()
        print(f'已删除用户 {name}' if cur.rowcount else f'用户 {name} 不存在')
        return

    if cmd == 'boards' and len(args) >= 3:
        name, raw = args[1], args[2]
        cur = conn.execute('SELECT 1 FROM users WHERE username=?', (name,)).fetchone()
        if not cur:
            print(f'用户 {name} 不存在'); conn.close(); return
        boards = '*' if raw == '*' else ','.join(x for x in raw.split(',') if x)
        conn.execute('UPDATE users SET allowed_boards=? WHERE username=?', (boards, name))
        conn.commit(); conn.close()
        scope = '全部看板' if boards == '*' else boards
        print(f'已更新 {name} 可见看板: {scope}')
        return

    if cmd == 'role' and len(args) >= 3:
        name, role = args[1], args[2]
        if role not in ('viewer', 'editor', 'admin'):
            print('角色必须是 viewer/editor/admin'); conn.close(); return
        cur = conn.execute('SELECT 1 FROM users WHERE username=?', (name,)).fetchone()
        if not cur:
            print(f'用户 {name} 不存在'); conn.close(); return
        conn.execute('UPDATE users SET role=? WHERE username=?', (role, name))
        conn.commit(); conn.close()
        print(f'已更新 {name} 角色: {role}')
        return

    conn.close()
    print(__doc__)

if __name__ == '__main__':
    main()
