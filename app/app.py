# -*- coding: utf-8 -*-
"""
TAPD 看板 Web 应用 v2 - 多人协作编辑版
- SQLite 存储（cards/users/actions/comments）
- 三层权限：viewer 只读 / editor 可编辑 / admin 全权限
- 卡片级编辑锁：WebSocket 实时广播，5 分钟超时自动释放 + 心跳续期
- 乐观锁：version 字段防并发覆盖
- 操作日志 + 卡片评论
依赖：fastapi, uvicorn（JWT/密码哈希均用标准库）
"""
import json, os, time, hmac, hashlib, base64, secrets, sqlite3, threading, re
from collections import defaultdict
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Depends, Header, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, '..', 'app.db')
STATIC_DIR = os.path.join(BASE_DIR, '..', 'static')
SECRET = os.environ.get('APP_SECRET', 'tapd-webapp-dev-secret-change-me')
TOKEN_TTL = 7 * 24 * 3600
LOCK_TIMEOUT = 300
LOCK_HEARTBEAT = 60
SUPER_ADMIN = 'admin'   # 内置超级管理员（不可删/改密码/改角色/换绑）
CARD_FIELDS = ['card_id','board_id','board_name','column_id','column_name','workspace_id',
    'card_name','status','status_name','priority','creator','owner','cc','follower',
    'begin','due','completed','created','modified','description','attachment_count',
    'label','b_sort','entity_type','cover_setted','cover_info','is_filed','created_from',
    'date_status','due_time_ux','begin_date_status','begin_time_ux','comments',
    'column_sort','board_status','board_creator','parent_id']

app = FastAPI(title="TAPD 看板", docs_url=None, redoc_url=None)

# ---------------- 数据库 ----------------
def get_conn():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    return conn

def dbq(sql, params=()):
    conn = get_conn()
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()

def dbe(sql, params=()):
    conn = get_conn()
    try:
        cur = conn.execute(sql, params)
        conn.commit()
        return cur
    finally:
        conn.close()

# ---------------- 密码 / JWT（标准库） ----------------
def hash_pw(pw: str) -> str:
    salt = secrets.token_hex(8)
    dk = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 100000)
    return f'pbkdf2${salt}${dk.hex()}'

def verify_pw(pw: str, stored: str) -> bool:
    try:
        _, salt, hexd = stored.split('$')
        dk = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 100000)
        return hmac.compare_digest(dk.hex(), hexd)
    except Exception:
        return False

def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))

def make_token(username: str) -> str:
    payload = {'u': username, 'exp': int(time.time()) + TOKEN_TTL}
    body = b64e(json.dumps(payload).encode())
    sig = b64e(hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).digest())
    return body + '.' + sig

def verify_token(token: str) -> Optional[str]:
    try:
        body, sig = token.split('.')
        expect = b64e(hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expect):
            return None
        payload = json.loads(b64d(body))
        if payload.get('exp', 0) < time.time():
            return None
        return payload.get('u')
    except Exception:
        return None

# ---------------- 权限 ----------------
def get_user(username: str):
    rows = dbq('SELECT * FROM users WHERE username=?', (username,))
    return dict(rows[0]) if rows else None

def user_role(username: str) -> str:
    u = get_user(username)
    return u['role'] if u else ''

_LEADER_ALL = '__ALL_BOARDS__'   # 负责人范围含'*'（全量）的标记

def _leader_boards(username: str):
    """负责人（部门长/组长）负责范围绑定的板块并集。
    登录账号 → 关联的成员中文名也要匹配（workgroups.leader 存的是成员名）。
    返回 None=非负责人；_LEADER_ALL=负责人且范围含'*'（全量）；set=负责人受限板块（可为空）。"""
    candidates = [username]
    row = dbq('SELECT name FROM team_members WHERE account=?', (username,))
    if row and row[0]['name'] and row[0]['name'] != username:
        candidates.append(row[0]['name'])
    marks = ','.join('?' * len(candidates))
    rows = dbq(f'SELECT id, parent_id, boards FROM workgroups WHERE leader IN ({marks})', candidates)
    if not rows:
        return None
    all_rows = dbq('SELECT id, parent_id, boards FROM workgroups')
    children = defaultdict(list)
    for r in all_rows:
        children[r['parent_id']].append(r)
    merged = set()

    def collect(node):
        nonlocal merged
        b = (node['boards'] or '').strip()
        if b == '*':
            return True
        if b:
            merged |= set(x for x in b.split(',') if x)
        for c in children.get(node['id'], []):
            if collect(c):
                return True
        return False

    for r in rows:
        if collect(r):
            return _LEADER_ALL
    return merged

def _group_boards(username: str):
    """成员所属工作组的板块绑定并集（白名单），含祖先部门传导。
    返回 set(board_id) 表示受限板块；None 表示不限制（未绑定/绑定'*'/超管/负责人）。"""
    if username == SUPER_ADMIN:
        return None
    row = dbq('SELECT workgroups FROM team_members WHERE account=?', (username,))
    if not row or not row[0]['workgroups']:
        return None
    names = [g.strip() for g in row[0]['workgroups'].split(';') if g.strip()]
    if not names:
        return None
    all_rows = dbq('SELECT id, name, parent_id, boards FROM workgroups')
    by_id = {r['id']: r for r in all_rows}
    by_name = {r['name']: r for r in all_rows}
    merged = set()
    for nm in names:
        cur = by_name.get(nm)
        # 沿父链向上收集（含自身）：上级部门绑定自动传导到部门内成员；
        # 最顶层（财务中心）不参与成员白名单——其"全部看板"是中心管理范围，不代表成员可见范围
        while cur and cur['parent_id'] != 0:
            b = (cur['boards'] or '').strip()
            if b == '*':
                return None  # 任一节点绑定全部 → 该用户不限制
            if b:
                merged |= set(x for x in b.split(',') if x)
            cur = by_id.get(cur['parent_id']) if cur['parent_id'] else None
    return merged or None

def user_allowed(username: str):
    """返回 (boards, columns)：
    boards=None=全部看板，否则 set(board_id)
    columns=None=全部板块，否则 dict {board_id: set(column_id)}（缺省=该看板全部板块）
    超级管理员(admin)自动拥有全部板块；
    部门长/组长自动拥有其负责范围（节点+后代）绑定的全部板块，且不受工作组白名单限制；
    普通成员：可见 = 账号权限 ∩ 所属工作组绑定并集。"""
    u = get_user(username)
    if not u:
        return set(), {}
    if username == SUPER_ADMIN:
        return None, None
    raw_b = u['allowed_boards']
    boards = None if raw_b == '*' else set(x for x in raw_b.split(',') if x)
    # 负责人（部门长/组长）：账号权限 ∪ 负责范围绑定板块，不再受工作组白名单限制
    lb = _leader_boards(username)
    if lb is not None:
        if lb == _LEADER_ALL:
            boards = None
        elif boards is None:
            pass  # 账号权限已是全量
        else:
            boards = boards | lb
    else:
        # 普通成员：工作组板块绑定白名单（最终可见 = 账号权限 ∩ 工作组绑定并集）
        gb = _group_boards(username)
        if gb is not None:
            boards = gb if boards is None else boards & gb
    raw_c = u.get('allowed_columns') or '*'
    if raw_c == '*':
        return boards, None
    try:
        cols = {k: set(v) for k, v in json.loads(raw_c).items() if v}
        return boards, cols or None
    except Exception:
        return boards, None

def can_edit(username: str) -> bool:
    return user_role(username) in ('editor', 'admin')

def is_admin(username: str) -> bool:
    return user_role(username) == 'admin'

# 成本看板：仅管理员可编辑（含子事项、评论外的所有写操作）
COST_BOARD_IDS = {'1162069797001000241'}

def check_cost_permission(board_id, username):
    """成本卡：非管理员拒绝"""
    if board_id in COST_BOARD_IDS and not is_admin(username):
        raise HTTPException(403, '成本卡仅管理员可操作')

async def require_auth(authorization: str = Header(None)):
    if not authorization or not authorization.startswith('Bearer '):
        raise HTTPException(401, '未登录')
    username = verify_token(authorization[7:])
    if not username:
        raise HTTPException(401, '登录已过期，请重新登录')
    return username

def require_editor(username: str = Depends(require_auth)):
    if not can_edit(username):
        raise HTTPException(403, '无编辑权限，请联系管理员')
    return username

def require_admin(username: str = Depends(require_auth)):
    if not is_admin(username):
        raise HTTPException(403, '需要管理员权限')
    return username

# ---------------- 审计日志 ----------------
def client_ip(request: Request) -> str:
    fwd = request.headers.get('x-forwarded-for')
    if fwd:
        return fwd.split(',')[0].strip()
    return request.client.host if request.client else ''

def audit_log(username: str, ip: str, action: str, target: str = '', detail: str = '', result: str = 'success'):
    """写审计日志（不抛异常，避免影响主流程）"""
    try:
        dbe('INSERT INTO audit_logs (username, ip, action, target, detail, result) VALUES (?,?,?,?,?,?)',
            (username or '', ip or '', action, (target or '')[:200], (detail or '')[:1000], result))
    except Exception:
        pass

def perm_pass(row: dict, boards, columns) -> bool:
    """两级权限过滤：row 可见？boards=None 或 row.board_id 在其中；columns 再细分板块"""
    if boards is not None and row['board_id'] not in boards:
        return False
    if columns is not None:
        cols = columns.get(row['board_id'])
        if cols is not None and row['column_id'] not in cols:
            return False
    return True

def filter_rows(rows, boards, columns):
    return [dict(r) for r in rows if perm_pass(dict(r), boards, columns)]

# ---------------- 卡片查询 ----------------
def card_dict(r) -> dict:
    d = dict(r)
    return d

def subtask_stats(card_ids) -> dict:
    """批量统计卡片的子事项完成情况：{card_id: {'done': n, 'total': m}}"""
    if not card_ids:
        return {}
    marks = ','.join('?' * len(card_ids))
    rows = dbq(f'SELECT card_id, done, COUNT(*) n FROM card_subtasks '
               f'WHERE card_id IN ({marks}) GROUP BY card_id, done', list(card_ids))
    out = {}
    for r in rows:
        s = out.setdefault(r['card_id'], {'done': 0, 'total': 0})
        s['total'] += r['n']
        if r['done']:
            s['done'] += r['n']
    return out

# ---------------- 锁管理 ----------------
class LockManager:
    def __init__(self):
        self.locks = {}
        self.lock = threading.Lock()

    def acquire(self, card_id, username):
        with self.lock:
            cur = self.locks.get(card_id)
            now = time.time()
            if cur and cur['user'] != username and now - cur['ts'] < LOCK_TIMEOUT:
                return False, cur['user']
            self.locks[card_id] = {'user': username, 'ts': now}
            return True, username

    def release(self, card_id, username):
        with self.lock:
            cur = self.locks.get(card_id)
            if cur and cur['user'] == username:
                del self.locks[card_id]
                return True
            return False

    def heartbeat(self, card_id, username):
        with self.lock:
            cur = self.locks.get(card_id)
            if cur and cur['user'] == username:
                cur['ts'] = time.time()
                return True
            return False

    def who(self, card_id):
        cur = self.locks.get(card_id)
        if cur and time.time() - cur['ts'] < LOCK_TIMEOUT:
            return cur['user']
        return None

lock_mgr = LockManager()

# ---------------- WebSocket 广播 ----------------
class WSManager:
    def __init__(self):
        self.conns = {}    # username -> set[WebSocket]

    async def connect(self, ws: WebSocket, username: str):
        await ws.accept()
        self.conns.setdefault(username, set()).add(ws)

    def disconnect(self, ws: WebSocket, username: str):
        s = self.conns.get(username)
        if s:
            s.discard(ws)
            if not s:
                self.conns.pop(username, None)

    async def broadcast(self, msg: dict, exclude: str = None):
        """推送给所有在线连接（可选排除某用户）"""
        dead = []
        for username, sockets in list(self.conns.items()):
            if exclude and username == exclude:
                continue
            for ws in list(sockets):
                try:
                    await ws.send_text(json.dumps(msg, ensure_ascii=False))
                except Exception:
                    dead.append((username, ws))
        for username, ws in dead:
            self.disconnect(ws, username)

ws_mgr = WSManager()

@app.websocket('/ws')
async def ws_endpoint(ws: WebSocket, token: str = None):
    """WebSocket: ?token=xxx 连接后实时收广播"""
    if not token:
        await ws.close(code=4401)
        return
    username = verify_token(token)
    if not username:
        await ws.close(code=4401)
        return
    await ws_mgr.connect(ws, username)
    try:
        while True:
            data = await ws.receive_text()   # 客户端心跳/保持连接
            if data == 'ping':
                await ws.send_text('pong')
    except WebSocketDisconnect:
        ws_mgr.disconnect(ws, username)

# ---------------- API：登录 / 信息 ----------------
class LoginReq(BaseModel):
    username: str
    password: str

@app.post('/api/login')
def login(req: LoginReq, request: Request):
    ip = client_ip(request)
    u = get_user(req.username)
    if not u or not verify_pw(req.password, u['password_hash']):
        audit_log(req.username, ip, 'login', '账号登录', '登录失败：账号或密码错误', 'failed')
        raise HTTPException(401, '账号或密码错误')
    audit_log(req.username, ip, 'login', '账号登录', f'登录成功（角色：{u["role"]}）', 'success')
    return {'token': make_token(req.username), 'username': req.username,
            'role': u['role']}

@app.post('/api/logout')
def logout(username: str = Depends(require_auth), request: Request = None):
    audit_log(username, client_ip(request), 'logout', '账号登出', '登出系统', 'success')
    return {'ok': True}

@app.get('/api/me')
def me(username: str = Depends(require_auth)):
    boards, columns = user_allowed(username)
    allb = _all_boards()
    if boards is not None:
        allb = [b for b in allb if b['board_id'] in boards]
    # 归属部门（board_config）：目录树按部门分组折叠用。
    # 未在「看板管理」里配置归属的看板 dept=''，前端归入「未配置」节点，不会丢失。
    dept_map = {r['board_id']: r['dept'] for r in dbq('SELECT board_id, dept FROM board_config')}
    boards_out = []
    for b in allb:
        item = dict(b)
        item['dept'] = dept_map.get(b['board_id'], '')
        boards_out.append(item)
    # 板块级权限信息（供前端配置/展示）
    col_info = None
    if columns is not None:
        col_info = {bid: sorted(cols) for bid, cols in columns.items()}
    return {'username': username, 'boards': boards_out, 'role': user_role(username),
            'can_edit': can_edit(username), 'is_admin': is_admin(username),
            'allowed_columns': col_info,
            'depts': DEPT_ORDER}   # 有序部门清单：空部门同样占位，前端据此渲染树顶层节点

@app.get('/api/overview')
def overview(username: str = Depends(require_auth)):
    boards, columns = user_allowed(username)
    rows = filter_rows(dbq("SELECT board_id, board_name, status, owner, column_id FROM cards WHERE deleted=0 AND parent_id=''"), boards, columns)
    names = {}
    by_board = defaultdict(lambda: {'total': 0, 'done': 0, 'progressing': 0})
    owner_cnt, owner_done = defaultdict(int), defaultdict(int)
    for r in rows:
        names[r['board_id']] = r['board_name']
        by_board[r['board_id']]['total'] += 1
        if r['status'] == 'done':
            by_board[r['board_id']]['done'] += 1
        elif r['status'] == 'progressing':
            by_board[r['board_id']]['progressing'] += 1
        for name in (r['owner'] or '').split(';'):
            name = name.strip()
            if not name:
                continue
            owner_cnt[name] += 1
            if r['status'] == 'done':
                owner_done[name] += 1
    board_stats = []
    for bid in sorted(by_board):
        s = by_board[bid]
        board_stats.append({'board_id': bid, 'board_name': names.get(bid, bid),
            'total': s['total'], 'done': s['done'],
            'progressing': s['progressing'],
            'open': s['total'] - s['done'] - s['progressing'],
            'done_rate': round(s['done'] / s['total'] * 100, 1) if s['total'] else 0})
    owner_stats = [{'owner': o, 'total': owner_cnt[o], 'done': owner_done.get(o, 0)}
                   for o in owner_cnt]
    owner_stats.sort(key=lambda x: -x['total'])
    return {'total': sum(s['total'] for s in board_stats),
            'done': sum(s['done'] for s in board_stats),
            'progressing': sum(s['progressing'] for s in board_stats),
            'open': sum(s['open'] for s in board_stats),
            'boards': board_stats, 'owners': owner_stats[:20]}

@app.get('/api/cards')
def cards(board_id: Optional[str] = None, status: Optional[str] = None,
          owner: Optional[str] = None, column: Optional[str] = None,
          q: Optional[str] = None, page: int = 1, size: int = 50,
          parent_id: Optional[str] = None, card_id: Optional[str] = None,
          username: str = Depends(require_auth), request: Request = None):
    if card_id:
        audit_log(username, client_ip(request), 'view', f'卡片 {card_id}', '查看卡片详情', 'success')
    boards, columns = user_allowed(username)
    all_rows = [dict(r) for r in dbq('SELECT * FROM cards WHERE deleted=0')]
    mine = filter_rows(all_rows, boards, columns)
    # 子事项计数（全量统计 parent 指向）
    sub_count = defaultdict(int)
    for r in all_rows:
        if r.get('parent_id'):
            sub_count[r['parent_id']] += 1
    # 层级过滤：parent_id 指定 → 查子事项；否则默认只看顶层（card_id 精确查询不受层级限制）
    if card_id:
        mine = [r for r in mine if r['card_id'] == card_id]
    elif parent_id:
        mine = [r for r in mine if r.get('parent_id') == parent_id]
    else:
        mine = [r for r in mine if not r.get('parent_id')]
    if board_id:
        mine = [r for r in mine if r['board_id'] == board_id]
    if status == 'done':
        mine = [r for r in mine if r['status'] == 'done']
    elif status == 'progressing':
        mine = [r for r in mine if r['status'] == 'progressing']
    elif status == 'open':
        mine = [r for r in mine if r['status'] != 'done' and r['status'] != 'progressing']
    if owner:
        mine = [r for r in mine if owner in (r.get('owner') or '')]
    if column:
        mine = [r for r in mine if (r.get('column_name') or '') == column]
    if q:
        mine = [r for r in mine if q in (r.get('card_name') or '') or q in (r.get('description') or '')]
    total = len(mine)
    start = (page - 1) * size
    page_rows = mine[start:start + size]
    st = subtask_stats([r['card_id'] for r in page_rows])
    out = []
    for r in page_rows:
        d = card_dict(r)
        d['locked_by'] = lock_mgr.who(r['card_id'])
        d['subtask_done'] = st.get(r['card_id'], {}).get('done', 0)
        d['subtask_total'] = st.get(r['card_id'], {}).get('total', 0)
        d['sub_count'] = sub_count.get(r['card_id'], 0)
        out.append(d)
    return {'total': total, 'page': page, 'size': size, 'cards': out}

# ---------------- API：编辑（写操作） ----------------
class CardUpdate(BaseModel):
    fields: dict        # 可编辑字段名->新值（version 单独传）

class CardCreate(BaseModel):
    board_id: str
    column_id: str = ''
    card_name: str
    fields: dict = {}
    parent_id: str = ''
    board_name: str = ''      # 全新看板（尚无卡片）建首卡时由前端传入
    workspace_id: str = ''    # 同上，携带看板工作空间

class CommentReq(BaseModel):
    content: str

def log_action(card_id, username, action, detail=''):
    dbe('INSERT INTO actions (card_id, username, action, detail) VALUES (?,?,?,?)',
        (card_id, username, action, detail))

@app.put('/api/cards/{card_id}')
async def update_card(card_id: str, req: CardUpdate, username: str = Depends(require_editor), request: Request = None):
    # 锁检查
    holder = lock_mgr.who(card_id)
    if holder and holder != username:
        raise HTTPException(409, f'卡片已被 {holder} 编辑中，无法保存')
    fields = req.fields
    if 'card_id' in fields: fields.pop('card_id')
    if 'version' in fields: fields.pop('version')
    if not fields:
        raise HTTPException(400, '没有可更新的字段')
    # 乐观锁：先取当前 version + board_id（成本卡权限检查）
    cur = dbq('SELECT version, parent_id, begin, due, board_id FROM cards WHERE card_id=? AND deleted=0', (card_id,))
    if not cur:
        raise HTTPException(404, '卡片不存在或已删除')
    check_cost_permission(cur[0]['board_id'], username)
    cur_ver = cur[0]['version']
    # 子事项时间约束：起始 ≥ 父起始，截止 ≤ 父截止
    if cur[0]['parent_id']:
        p_row = dbq('SELECT begin, due FROM cards WHERE card_id=? AND deleted=0', (cur[0]['parent_id'],))
        if p_row:
            p_begin, p_due = (p_row[0]['begin'] or ''), (p_row[0]['due'] or '')
            s_begin = fields.get('begin', cur[0]['begin'] or '')
            s_due = fields.get('due', cur[0]['due'] or '')
            if s_begin and p_begin and s_begin < p_begin:
                raise HTTPException(400, f'子事项起始时间不能早于父事项（父起始 {p_begin}）')
            if s_due and p_due and s_due > p_due:
                raise HTTPException(400, f'子事项截止时间不能晚于父事项（父截止 {p_due}）')
            if s_begin and s_due and s_begin > s_due:
                raise HTTPException(400, '子事项起始时间不能晚于截止时间')
    # 构建 SET
    cols = [k for k in fields if k in CARD_FIELDS]
    if not cols:
        raise HTTPException(400, '字段名不合法')
    sets = ', '.join(f'{c}=?' for c in cols) + ', version=version+1, modified=?'
    vals = [str(fields[c]) for c in cols] + [time.strftime('%Y-%m-%d %H:%M:%S')]
    # 乐观锁 WHERE version=?
    res = dbe(f'UPDATE cards SET {sets} WHERE card_id=? AND deleted=0 AND version=?',
              vals + [card_id, cur_ver])
    if res.rowcount == 0:
        raise HTTPException(409, '数据已被他人修改，请刷新后重试')
    log_action(card_id, username, 'update', json.dumps(fields, ensure_ascii=False)[:500])
    audit_log(username, client_ip(request), 'update', f'卡片 {card_id}', '更新字段：' + '、'.join(fields.keys()), 'success')
    # 释放锁 + 广播
    lock_mgr.release(card_id, username)
    await ws_mgr.broadcast({'type': 'card_update', 'card_id': card_id,
        'by': username}, exclude=username)
    return {'ok': True}

@app.post('/api/cards')
async def create_card(req: CardCreate, username: str = Depends(require_editor), request: Request = None):
    import uuid
    new_id = 'NC' + str(int(time.time() * 1000))
    # 子事项：board 继承父卡片（防跨看板权限漏洞），并校验父存在且可见
    if req.parent_id:
        parent = dbq('SELECT * FROM cards WHERE card_id=? AND deleted=0', (req.parent_id,))
        if not parent:
            raise HTTPException(404, '父事项不存在或已删除')
        boards, columns = user_allowed(username)
        if not perm_pass(dict(parent[0]), boards, columns):
            raise HTTPException(403, '父事项不可见，无法创建子事项')
        req.board_id = parent[0]['board_id']
        req.column_id = ''
        # 时间约束：子事项起始 ≥ 父起始，截止 ≤ 父截止，且起始 ≤ 截止
        f = req.fields or {}
        p_begin, p_due = (parent[0]['begin'] or ''), (parent[0]['due'] or '')
        s_begin, s_due = (f.get('begin') or ''), (f.get('due') or '')
        if s_begin and p_begin and s_begin < p_begin:
            raise HTTPException(400, f'子事项起始时间不能早于父事项（父起始 {p_begin}）')
        if s_due and p_due and s_due > p_due:
            raise HTTPException(400, f'子事项截止时间不能晚于父事项（父截止 {p_due}）')
        if s_begin and s_due and s_begin > s_due:
            raise HTTPException(400, '子事项起始时间不能晚于截止时间')
    # 仅继承看板元数据（board_name/workspace_id），业务字段（含日期/状态/负责人等）不继承——
    # 否则新建的"无时间父卡"会悄悄带上同看板第一张卡的 begin/due，导致子事项时间校验误判
    base = dbq('SELECT * FROM cards WHERE board_id=? AND deleted=0 LIMIT 1', (req.board_id,))
    vals = {}
    if base:
        b = dict(base[0])
        for k in ('board_name', 'workspace_id'):
            vals[k] = b.get(k, '')
    else:
        # 全新看板（尚无任何卡片）：使用建卡请求传入的看板元数据，保证首卡正确带出 board_name/workspace_id
        vals['board_name'] = (req.board_name or req.board_id).strip()
        vals['workspace_id'] = (req.workspace_id or '').strip()
    # 成本卡权限检查（创建时基于最终 board_id）
    check_cost_permission(req.board_id, username)
    vals.update(req.fields)
    vals['card_id'] = new_id
    vals['board_id'] = req.board_id
    vals['column_id'] = req.column_id or vals.get('column_id', '')
    vals['card_name'] = req.card_name
    vals['creator'] = username
    vals['created'] = time.strftime('%Y-%m-%d %H:%M:%S')
    vals['parent_id'] = req.parent_id
    cols = [k for k in CARD_FIELDS if k in vals]
    dbe(f'INSERT INTO cards ({",".join(cols)}) VALUES ({",".join("?"*len(cols))})',
        [vals[k] for k in cols])
    log_action(new_id, username, 'create', f'{req.card_name} (parent={req.parent_id or "-"})')
    audit_log(username, client_ip(request), 'create', f'卡片 {new_id}', f'新建卡片：{req.card_name}' + (f'（父事项 {req.parent_id}）' if req.parent_id else ''), 'success')
    await ws_mgr.broadcast({'type': 'card_create', 'card_id': new_id,
        'board_id': req.board_id, 'by': username}, exclude=username)
    return {'ok': True, 'card_id': new_id}

# ---------------- API：看板管理（新建看板） ----------------
class BoardCreateReq(BaseModel):
    board_name: str
    workspace_id: str = ''
    owner: str = ''
    sort: int = 0

@app.post('/api/boards')
def create_board(req: BoardCreateReq, username: str = Depends(require_admin), request: Request = None):
    """新建看板（仅管理员）。写入 boards 表，立即可在标签页看到空看板。"""
    import time
    name = (req.board_name or '').strip()
    if not name:
        raise HTTPException(400, '看板名称不能为空')
    bid = 'B' + str(int(time.time() * 1000))
    dbe('INSERT OR REPLACE INTO boards (board_id, board_name, workspace_id, owner, sort, created_at) VALUES (?,?,?,?,?,?)',
        (bid, name, (req.workspace_id or '').strip(), (req.owner or username).strip(), req.sort, time.strftime('%Y-%m-%d %H:%M:%S')))
    audit_log(username, client_ip(request), 'board_create', f'看板 {bid}', f'新建看板：{name}', 'success')
    return {'ok': True, 'board_id': bid, 'board_name': name, 'workspace_id': (req.workspace_id or '').strip()}

@app.delete('/api/cards/{card_id}')
async def delete_card(card_id: str, username: str = Depends(require_editor), request: Request = None):
    holder = lock_mgr.who(card_id)
    if holder and holder != username:
        raise HTTPException(409, f'卡片已被 {holder} 编辑中，无法删除')
    # 成本卡权限检查
    cur_row = dbq('SELECT board_id FROM cards WHERE card_id=? AND deleted=0', (card_id,))
    if not cur_row:
        raise HTTPException(404, '卡片不存在或已删除')
    check_cost_permission(cur_row[0]['board_id'], username)
    res = dbe('UPDATE cards SET deleted=1 WHERE card_id=? AND deleted=0', (card_id,))
    if res.rowcount == 0:
        raise HTTPException(404, '卡片不存在或已删除')
    # 级联：删除子事项（含其代办任务）
    subs = [r['card_id'] for r in dbq('SELECT card_id FROM cards WHERE parent_id=? AND deleted=0', (card_id,))]
    for sid in subs:
        dbe('UPDATE cards SET deleted=1 WHERE card_id=?', (sid,))
        dbe('DELETE FROM card_subtasks WHERE card_id=?', (sid,))
    dbe('DELETE FROM card_subtasks WHERE card_id=?', (card_id,))
    log_action(card_id, username, 'delete', f'subitems={len(subs)}')
    audit_log(username, client_ip(request), 'delete', f'卡片 {card_id}', f'删除卡片（含 {len(subs)} 个子事项）', 'success')
    lock_mgr.release(card_id, username)
    await ws_mgr.broadcast({'type': 'card_delete', 'card_id': card_id,
        'by': username}, exclude=username)
    return {'ok': True}

# ---------------- API：锁 ----------------
@app.post('/api/cards/{card_id}/lock')
async def lock_card(card_id: str, username: str = Depends(require_editor), request: Request = None):
    ok, holder = lock_mgr.acquire(card_id, username)
    if not ok:
        raise HTTPException(409, f'卡片已被 {holder} 编辑中')
    audit_log(username, client_ip(request), 'lock', f'卡片 {card_id}', '锁定编辑', 'success')
    await ws_mgr.broadcast({'type': 'lock', 'card_id': card_id, 'by': username})
    return {'ok': True}

@app.post('/api/cards/{card_id}/unlock')
async def unlock_card(card_id: str, username: str = Depends(require_editor), request: Request = None):
    if lock_mgr.release(card_id, username):
        audit_log(username, client_ip(request), 'unlock', f'卡片 {card_id}', '解锁编辑', 'success')
        await ws_mgr.broadcast({'type': 'unlock', 'card_id': card_id, 'by': username})
    return {'ok': True}

@app.post('/api/cards/{card_id}/heartbeat')
def heartbeat(card_id: str, username: str = Depends(require_editor)):
    lock_mgr.heartbeat(card_id, username)
    return {'ok': True}

# ---------------- API：评论 / 日志 ----------------
@app.get('/api/cards/{card_id}/comments')
def get_comments(card_id: str, username: str = Depends(require_auth)):
    rows = dbq('SELECT id, card_id, username, content, created_at FROM comments WHERE card_id=? ORDER BY id', (card_id,))
    return {'comments': [dict(r) for r in rows]}

@app.post('/api/cards/{card_id}/comments')
async def add_comment(card_id: str, req: CommentReq, username: str = Depends(require_auth), request: Request = None):
    if not req.content or not req.content.strip():
        raise HTTPException(400, '评论不能为空')
    dbe('INSERT INTO comments (card_id, username, content) VALUES (?,?,?)',
        (card_id, username, req.content.strip()))
    log_action(card_id, username, 'comment', req.content.strip()[:200])
    audit_log(username, client_ip(request), 'comment', f'卡片 {card_id}', '发表评论', 'success')
    await ws_mgr.broadcast({'type': 'comment', 'card_id': card_id,
        'by': username}, exclude=username)
    return {'ok': True}

@app.get('/api/cards/{card_id}/actions')
def get_actions(card_id: str, username: str = Depends(require_auth)):
    rows = dbq('SELECT username, action, detail, created_at FROM actions WHERE card_id=? ORDER BY id DESC LIMIT 30',
               (card_id,))
    return {'actions': [dict(r) for r in rows]}

# ---------------- API：子事项 ----------------
class SubtaskReq(BaseModel):
    title: Optional[str] = None
    done: Optional[int] = None
    sort: Optional[int] = None

@app.get('/api/cards/{card_id}/subtasks')
def get_subtasks(card_id: str, username: str = Depends(require_auth)):
    rows = dbq('SELECT id, card_id, title, done, sort, done_by, done_at, created_by, created_at '
               'FROM card_subtasks WHERE card_id=? ORDER BY sort, id', (card_id,))
    return {'subtasks': [dict(r) for r in rows]}

@app.post('/api/cards/{card_id}/subtasks')
async def add_subtask(card_id: str, req: SubtaskReq, username: str = Depends(require_editor), request: Request = None):
    holder = lock_mgr.who(card_id)
    if holder and holder != username:
        raise HTTPException(409, f'卡片已被 {holder} 编辑中，无法修改子事项')
    title = (req.title or '').strip()
    if not title:
        raise HTTPException(400, '子事项标题不能为空')
    card_row = dbq('SELECT board_id FROM cards WHERE card_id=? AND deleted=0', (card_id,))
    if not card_row:
        raise HTTPException(404, '卡片不存在或已删除')
    check_cost_permission(card_row[0]['board_id'], username)
    if not dbq('SELECT 1 FROM cards WHERE card_id=? AND deleted=0', (card_id,)):
        raise HTTPException(404, '卡片不存在或已删除')
    mx = dbq('SELECT COALESCE(MAX(sort),0) m FROM card_subtasks WHERE card_id=?', (card_id,))[0]['m']
    dbe('INSERT INTO card_subtasks (card_id, title, done, sort, created_by) VALUES (?,?,?,?,?)',
        (card_id, title, 0, mx + 10, username))
    log_action(card_id, username, 'subtask_add', title)
    audit_log(username, client_ip(request), 'subtask_add', f'卡片 {card_id}', f'新增子事项：{title}', 'success')
    await ws_mgr.broadcast({'type': 'card_update', 'card_id': card_id,
        'by': username}, exclude=username)
    return {'ok': True}

@app.put('/api/cards/{card_id}/subtasks/{sid}')
async def update_subtask(card_id: str, sid: int, req: SubtaskReq,
                         username: str = Depends(require_editor), request: Request = None):
    holder = lock_mgr.who(card_id)
    if holder and holder != username:
        raise HTTPException(409, f'卡片已被 {holder} 编辑中，无法修改子事项')
    card_row = dbq('SELECT board_id FROM cards WHERE card_id=? AND deleted=0', (card_id,))
    if card_row:
        check_cost_permission(card_row[0]['board_id'], username)
    row = dbq('SELECT 1 FROM card_subtasks WHERE id=? AND card_id=?', (sid, card_id))
    if not row:
        raise HTTPException(404, '子事项不存在')
    sets, vals = [], []
    if req.title is not None:
        t = req.title.strip()
        if not t:
            raise HTTPException(400, '子事项标题不能为空')
        sets.append('title=?'); vals.append(t)
    if req.done is not None:
        sets.append('done=?'); vals.append(1 if req.done else 0)
        sets.append('done_by=?'); vals.append(username if req.done else '')
        sets.append('done_at=?'); vals.append(time.strftime('%Y-%m-%d %H:%M:%S') if req.done else '')
    if req.sort is not None:
        sets.append('sort=?'); vals.append(req.sort)
    if not sets:
        raise HTTPException(400, '没有可更新的字段')
    vals.append(sid)
    dbe(f'UPDATE card_subtasks SET {", ".join(sets)} WHERE id=?', vals)
    log_action(card_id, username, 'subtask_update', f'#{sid} done={req.done}')
    audit_log(username, client_ip(request), 'subtask_update', f'卡片 {card_id} 子事项#{sid}', '更新子事项（勾选/改名/排序）', 'success')
    await ws_mgr.broadcast({'type': 'card_update', 'card_id': card_id,
        'by': username}, exclude=username)
    return {'ok': True}

@app.delete('/api/cards/{card_id}/subtasks/{sid}')
async def delete_subtask(card_id: str, sid: int, username: str = Depends(require_editor), request: Request = None):
    holder = lock_mgr.who(card_id)
    if holder and holder != username:
        raise HTTPException(409, f'卡片已被 {holder} 编辑中，无法修改子事项')
    card_row = dbq('SELECT board_id FROM cards WHERE card_id=? AND deleted=0', (card_id,))
    if card_row:
        check_cost_permission(card_row[0]['board_id'], username)
    res = dbe('DELETE FROM card_subtasks WHERE id=? AND card_id=?', (sid, card_id))
    if res.rowcount == 0:
        raise HTTPException(404, '子事项不存在')
    log_action(card_id, username, 'subtask_del', f'#{sid}')
    audit_log(username, client_ip(request), 'subtask_delete', f'卡片 {card_id} 子事项#{sid}', '删除子事项', 'success')
    await ws_mgr.broadcast({'type': 'card_update', 'card_id': card_id,
        'by': username}, exclude=username)
    return {'ok': True}

# ---------------- API：团队管理 ----------------
@app.get('/api/team')
def get_team(username: str = Depends(require_auth)):
    rows = dbq('''SELECT m.id, m.name, m.workgroups, m.account,
                        u.role AS role, u.allowed_boards AS allowed_boards,
                        (u.password_hash IS NOT NULL AND u.password_hash != '') AS password_set
                 FROM team_members m
                 LEFT JOIN users u ON u.username = m.account
                 ORDER BY m.id''')
    out = [dict(r) for r in rows]
    if not is_admin(username):
        # 非管理员仅用于首页负责人下拉，不暴露账号/角色/密码状态
        for m in out:
            m['account'] = ''
            m['role'] = ''
            m['password_set'] = False
    return {'members': out}

class TeamReq(BaseModel):
    name: str
    workgroups: List[str] = []
    account: Optional[str] = None   # 配套登录账号（username），可空=不开通
    password: Optional[str] = None  # 开通账号时的密码
    role: str = 'editor'

class TeamUpdateReq(BaseModel):
    name: str
    workgroups: List[str] = []
    account: Optional[str] = None   # 变更账号关联：空串=关闭，非空前=开通/绑定
    password: Optional[str] = None
    role: Optional[str] = None

def _norm_workgroups(workgroups):
    if not workgroups: return ''
    seen=[]; seen_set=set()
    for g in workgroups:
        g=str(g).strip()
        if g and g not in seen_set:
            seen.append(g); seen_set.add(g)
    return ';'.join(seen)

def _open_account(mid: int, acc_name: str, pwd: Optional[str] = None, role: Optional[str] = None):
    """为成员 mid 开通/绑定登录账号。账号不存在则创建（需密码）；存在则按需更新 role/密码。
    仅存哈希（登录验证用），不存明文。"""
    acc_name = acc_name.strip()
    if not acc_name:
        return
    if role and role not in ('viewer', 'editor', 'admin'):
        role = None
    if not get_user(acc_name):
        if not pwd:
            raise HTTPException(400, '开通新账号需设置密码')
        r = role or 'editor'
        dbe('INSERT INTO users (username, password_hash, role, allowed_boards, allowed_columns) VALUES (?,?,?,?,?)',
            (acc_name, hash_pw(pwd), r, '*', '*'))
    else:
        sets, vals = [], []
        if role in ('viewer', 'editor', 'admin'):
            sets.append('role=?'); vals.append(role)
        if pwd:
            sets.append('password_hash=?'); vals.append(hash_pw(pwd))
        if sets:
            vals.append(acc_name)
            dbe(f'UPDATE users SET {", ".join(sets)} WHERE username=?', vals)
    dbe('UPDATE team_members SET account=? WHERE id=?', (acc_name, mid))

@app.post('/api/team')
def add_team(req: TeamReq, username: str = Depends(require_admin), request: Request = None):
    name = req.name.strip()
    if not name:
        raise HTTPException(400, '成员名不能为空')
    if req.account and req.account.strip() == SUPER_ADMIN:
        raise HTTPException(403, f'「{SUPER_ADMIN}」是内置超级管理员，不可被成员关联')
    try:
        dbe('INSERT INTO team_members (name, workgroups) VALUES (?,?)', (name, _norm_workgroups(req.workgroups)))
    except sqlite3.IntegrityError:
        raise HTTPException(409, '成员已存在')
    mid = dbq('SELECT id FROM team_members WHERE name=?', (name,))[0]['id']
    if req.account and req.account.strip():
        acc = req.account.strip()
        # 若 acc 已被其他成员绑定，自动解除原绑定（避免一号多人）
        other = dbq('SELECT id FROM team_members WHERE account=? AND id!=?', (acc, mid))
        if other:
            dbe('UPDATE team_members SET account="" WHERE id=?', (other[0]['id'],))
        _open_account(mid, acc, req.password, req.role)
    audit_log(username, client_ip(request), 'member_create', f'成员 {name}', f'新增成员（id={mid}' + (f'，开通账号 {req.account.strip()}' if req.account and req.account.strip() else '，未开通账号') + '）', 'success')
    return {'ok': True}

@app.put('/api/team/{mid}')
def update_team(mid: int, req: TeamUpdateReq, username: str = Depends(require_admin), request: Request = None):
    name = req.name.strip()
    if not name:
        raise HTTPException(400, '成员名不能为空')
    cur = dbq('SELECT 1 FROM team_members WHERE id=?', (mid,))
    if not cur:
        raise HTTPException(404, '成员不存在')
    old = dbq('SELECT account FROM team_members WHERE id=?', (mid,))
    old_acc = old[0]['account'] if old else ''
    # 密码重置仅超级管理员；管理员可开通/变更账号（首次开通允许设置密码）
    if username != SUPER_ADMIN and req.password:
        raise HTTPException(403, '仅超级管理员可重置密码')
    # 超级管理员关联的成员行：完全只读
    if old_acc == SUPER_ADMIN:
        raise HTTPException(403, f'「{SUPER_ADMIN}」是内置超级管理员，对应成员行不可修改')
    if req.account and req.account.strip() == SUPER_ADMIN:
        raise HTTPException(403, f'不可将成员账号绑定到内置超级管理员「{SUPER_ADMIN}」')
    dup = dbq('SELECT 1 FROM team_members WHERE name=? AND id!=?', (name, mid))
    if dup:
        raise HTTPException(409, f'成员「{name}」已存在')
    dbe('UPDATE team_members SET name=?, workgroups=? WHERE id=?', (name, _norm_workgroups(req.workgroups), mid))
    # 只改角色：成员已有账号且本次未变更账号关联
    if req.account is None and req.role and old_acc:
        if req.role not in ('viewer', 'editor', 'admin'):
            raise HTTPException(400, '角色必须是 viewer/editor/admin')
        if old_acc == SUPER_ADMIN:
            raise HTTPException(403, f'「{SUPER_ADMIN}」是内置超级管理员，角色不可修改')
        dbe('UPDATE users SET role=? WHERE username=?', (req.role, old_acc))
    # 账号关联变更
    if req.account is not None:
        acc = req.account.strip()
        if not acc:
            if old_acc:
                dbe('DELETE FROM users WHERE username=?', (old_acc,))
            dbe('UPDATE team_members SET account="" WHERE id=?', (mid,))
        else:
            # 换绑：若 acc 已被其他成员绑定，自动解除原绑定
            if acc != old_acc:
                other = dbq('SELECT id FROM team_members WHERE account=? AND id!=?', (acc, mid))
                if other:
                    dbe('UPDATE team_members SET account="" WHERE id=?', (other[0]['id'],))
            _open_account(mid, acc, req.password, req.role)
    changes = []
    if name != req.name.strip() or True:
        changes = ['姓名/工作组']
    if req.role and old_acc:
        changes.append(f'角色→{req.role}')
    if req.password:
        changes.append('重置密码')
    if req.account is not None and req.account != old_acc:
        changes.append('变更账号关联')
    audit_log(username, client_ip(request), 'member_update', f'成员 {name} (id={mid})', '，'.join(changes) or '资料更新', 'success')
    return {'ok': True}

@app.delete('/api/team/{mid}')
def del_team(mid: int, username: str = Depends(require_admin), request: Request = None):
    cur = dbq('SELECT account, name FROM team_members WHERE id=?', (mid,))
    if not cur:
        raise HTTPException(404, '成员不存在')
    acc, mname = cur[0]['account'], cur[0]['name']
    if acc == SUPER_ADMIN:
        raise HTTPException(403, f'「{SUPER_ADMIN}」是内置超级管理员，不可删除')
    if acc == username:
        raise HTTPException(400, '不能删除当前登录账号关联的成员')
    if acc:
        dbe('DELETE FROM users WHERE username=?', (acc,))
    dbe('DELETE FROM team_members WHERE id=?', (mid,))
    audit_log(username, client_ip(request), 'member_delete', f'成员 {mname} (id={mid})', f'删除成员' + (f'及关联账号 {acc}' if acc else ''), 'success')
    return {'ok': True}

# ---------------- API：工作组管理（工作组树形架构） ----------------
def _wg_rows():
    rows = [dict(r) for r in dbq('SELECT id, name, parent_id, leader, function, description, boards FROM workgroups ORDER BY id')]
    # 最顶层（财务中心）：板块强制锁定为全部看板
    for r in rows:
        if r['parent_id'] == 0:
            r['boards'] = '*'
    return rows

def _wg_tree(rows):
    """平铺 rows → 树（children 递归）"""
    by_parent = defaultdict(list)
    for r in rows:
        by_parent[r['parent_id']].append(r)
    def build(pid):
        nodes = []
        for r in by_parent.get(pid, []):
            node = dict(r)
            node['children'] = build(r['id'])
            nodes.append(node)
        return nodes
    return build(0)

def _all_boards():
    """看板来源 = boards 表 ∪ cards 派生的看板（兼容历史仅有卡片、未登记元数据的看板）"""
    pairs = {}
    for r in dbq('SELECT board_id, board_name, workspace_id FROM boards ORDER BY sort, board_id'):
        d = dict(r)
        pairs[d['board_id']] = {'board_id': d['board_id'], 'board_name': d['board_name'], 'workspace_id': d.get('workspace_id', '')}
    for r in dbq('SELECT DISTINCT board_id, board_name, workspace_id FROM cards WHERE deleted=0'):
        d = dict(r)
        if d['board_id'] not in pairs:
            pairs[d['board_id']] = {'board_id': d['board_id'], 'board_name': d['board_name'], 'workspace_id': d.get('workspace_id', '')}
    return sorted(pairs.values(), key=lambda x: (x['board_id'],))

@app.get('/api/workgroups')
def get_workgroups(username: str = Depends(require_auth)):
    """工作组管理：返回树形工作组架构 + 全部看板列表（供板块绑定配置）"""
    return {'groups': _wg_tree(_wg_rows()), 'all_boards': _all_boards()}

@app.get('/api/org')
def get_org_alias(username: str = Depends(require_auth)):
    """兼容别名：/api/org 重定向到 /api/workgroups"""
    return get_workgroups(username)

@app.get('/api/groups')
def get_groups_alias(username: str = Depends(require_auth)):
    """兼容别名：平铺工作组列表（成员管理的工作组选择用）"""
    return {'groups': _wg_rows()}

class WgNodeReq(BaseModel):
    name: str
    parent_id: int = 0
    leader: str = ''
    function: str = ''
    description: str = ''
    boards: str = ''

def _check_leader(leader):
    """组长必须在团队成员中存在，否则抛 400（数据库层双重校验）"""
    if leader and not dbq('SELECT 1 FROM team_members WHERE name=?', (leader,)):
        raise HTTPException(400, f'组长「{leader}」不在团队成员列表中')

def _norm_boards(raw: str) -> str:
    """规范化板块绑定：不允许'*'（全部看板仅限最顶层系统锁定）；逗号分隔去重"""
    raw = (raw or '').strip()
    if not raw:
        return ''
    if raw == '*':
        raise HTTPException(400, '不能选择「全部看板」，请明确勾选具体看板')
    seen = []
    for b in raw.split(','):
        b = b.strip()
        if b and b not in seen:
            seen.append(b)
    return ','.join(seen)

def _is_root_wg(gid: int) -> bool:
    """是否最顶层工作组（财务中心）"""
    return bool(dbq('SELECT 1 FROM workgroups WHERE id=? AND parent_id=0', (gid,)))

def _check_child_boards(parent_id: int, boards: str):
    """子工作组板块不得超出上级部门绑定范围（父未绑定/绑定'*' → 子自由）"""
    if not parent_id:
        return
    p = dbq('SELECT boards FROM workgroups WHERE id=?', (parent_id,))
    if not p:
        return
    pb = (p[0]['boards'] or '').strip()
    if not pb or pb == '*':
        return
    if boards == '*':
        raise HTTPException(400, '上级已绑定板块，子级不能设为「全部看板」，请选择上级范围内的板块')
    sub = set(x for x in boards.split(',') if x)
    pset = set(x for x in pb.split(',') if x)
    if not sub <= pset:
        raise HTTPException(400, '子级板块超出上级部门的绑定范围')

def _cascade_boards(gid: int, new_boards: str):
    """父工作组板块权限变更后的级联清理：后代中超出新父范围的看板同步移除。
    new_boards 为 '*' 或 ''（不限制）时后代保持不变；否则后代的 '*' 降级为新父范围、
    列表则裁剪为交集；清理后为空则置 ''（未绑定）。"""
    if not new_boards or new_boards == '*':
        return
    pset = set(x for x in new_boards.split(',') if x)
    rows = _wg_rows()
    children = defaultdict(list)
    for r in rows:
        children[r['parent_id']].append(r)
    changed = []

    def walk(pid):
        for c in children.get(pid, []):
            b = (c['boards'] or '').strip()
            if b:
                if b == '*':
                    nb = new_boards
                else:
                    nb = ','.join(sorted(set(x for x in b.split(',') if x) & pset))
                if nb != b:
                    dbe('UPDATE workgroups SET boards=? WHERE id=?', (nb, c['id']))
                    changed.append((c['name'], b, nb))
            walk(c['id'])
    walk(gid)
    return changed

@app.post('/api/workgroups')
def add_wg_node(req: WgNodeReq, username: str = Depends(require_admin), request: Request = None):
    name = req.name.strip()
    if not name:
        raise HTTPException(400, '工作组名称不能为空')
    if not req.parent_id:
        raise HTTPException(400, '顶层工作组由系统管理（财务中心），请在顶层下新增部门')
    if req.parent_id and not dbq('SELECT 1 FROM workgroups WHERE id=?', (req.parent_id,)):
        raise HTTPException(400, '上级工作组不存在')
    _check_leader(req.leader.strip())
    boards = _norm_boards(req.boards)
    _check_child_boards(req.parent_id, boards)
    try:
        dbe('INSERT INTO workgroups (name, parent_id, leader, function, description, boards) VALUES (?,?,?,?,?,?)',
            (name, req.parent_id, req.leader.strip(), req.function.strip(), req.description.strip(), boards))
    except sqlite3.IntegrityError:
        raise HTTPException(409, '同级下已存在同名工作组')
    audit_log(username, client_ip(request), 'group_create', f'工作组 {name}', f'新增工作组节点（上级 id={req.parent_id}，板块绑定：{boards or "未绑定"}）', 'success')
    return {'ok': True}

@app.post('/api/org')
def add_org_alias(req: WgNodeReq, username: str = Depends(require_admin), request: Request = None):
    """兼容别名：/api/org 映射到 /api/workgroups"""
    return add_wg_node(req, username, request)

@app.put('/api/workgroups/{gid}')
def update_wg_node(gid: int, req: WgNodeReq, username: str = Depends(require_admin), request: Request = None):
    name = req.name.strip()
    if not name:
        raise HTTPException(400, '工作组名称不能为空')
    if not dbq('SELECT 1 FROM workgroups WHERE id=?', (gid,)):
        raise HTTPException(404, '工作组不存在')
    if req.parent_id:
        if req.parent_id == gid:
            raise HTTPException(400, '上级工作组不能是自身')
        # 防环：新父不能是自身的后代
        rows = _wg_rows()
        def is_desc(pid, target):
            for r in rows:
                if r['parent_id'] == pid:
                    if r['id'] == target:
                        return True
                    if is_desc(r['id'], target):
                        return True
            return False
        if is_desc(gid, req.parent_id):
            raise HTTPException(400, '上级工作组不能是自己的下级')
    if dbq('SELECT 1 FROM workgroups WHERE parent_id=? AND name=? AND id!=?', (req.parent_id, name, gid)):
        raise HTTPException(409, f'同级下已存在同名工作组「{name}」')
    _check_leader(req.leader.strip())
    if _is_root_wg(gid):
        # 最顶层（财务中心）：板块锁定为全部看板，不可修改调整、不可变更上级
        if req.parent_id:
            raise HTTPException(403, '最顶层工作组不可变更上级')
        boards = '*'
        if req.boards and req.boards != '*':
            raise HTTPException(403, '最顶层工作组锁定全部看板，不可修改板块权限')
    else:
        boards = _norm_boards(req.boards)
    _check_child_boards(req.parent_id, boards)
    dbe('UPDATE workgroups SET name=?, parent_id=?, leader=?, function=?, description=?, boards=? WHERE id=?',
        (name, req.parent_id, req.leader.strip(), req.function.strip(), req.description.strip(), boards, gid))
    # 父级板块收缩 → 级联清理后代超范围看板
    cascade = _cascade_boards(gid, boards)
    audit_log(username, client_ip(request), 'group_update', f'工作组 {name} (id={gid})',
              '更新工作组信息/上级/板块绑定' + (f'；级联调整 {len(cascade)} 个子级板块' if cascade else ''), 'success')
    return {'ok': True}

@app.put('/api/org/{gid}')
def update_org_alias(gid: int, req: WgNodeReq, username: str = Depends(require_admin), request: Request = None):
    """兼容别名：/api/org 映射到 /api/workgroups"""
    return update_wg_node(gid, req, username, request)

@app.delete('/api/workgroups/{gid}')
def del_wg_node(gid: int, username: str = Depends(require_admin), request: Request = None):
    if _is_root_wg(gid):
        raise HTTPException(403, '最顶层工作组（财务中心）不可删除')
    if not dbq('SELECT 1 FROM workgroups WHERE id=?', (gid,)):
        raise HTTPException(404, '工作组不存在')
    if dbq('SELECT 1 FROM workgroups WHERE parent_id=?', (gid,)):
        raise HTTPException(409, '请先删除该工作组下的子工作组')
    g = dbq('SELECT name FROM workgroups WHERE id=?', (gid,))[0]['name']
    dbe('DELETE FROM workgroups WHERE id=?', (gid,))
    # 同步清理成员工作组引用：删除工作组后，所有成员 workgroups 字段中的该工作组名一并移除（防止残留）
    removed_cnt = 0
    for r in dbq('SELECT id, workgroups FROM team_members'):
        gs = [x.strip() for x in (r['workgroups'] or '').split(';') if x.strip()]
        if g in gs:
            nf = [x for x in gs if x != g]
            dbe('UPDATE team_members SET workgroups=? WHERE id=?', (';'.join(nf), r['id']))
            removed_cnt += 1
    audit_log(username, client_ip(request), 'group_delete', f'工作组 {g} (id={gid})',
              f'删除工作组节点；同步清理 {removed_cnt} 名成员的工作组引用', 'success')
    return {'ok': True}

@app.delete('/api/org/{gid}')
def del_org_alias(gid: int, username: str = Depends(require_admin), request: Request = None):
    """兼容别名：/api/org 映射到 /api/workgroups"""
    return del_wg_node(gid, username, request)

# ---------------- API：看板管理（配置板块：年份/归属部门/属性/状态） ----------------
# 枚举可选值（与 DB CHECK 约束保持一致，应用层二次校验，越界即 400）
ALLOWED_YEARS = {'2025', '2026', '2027', '2028', '2029', '2030'}
# 部门的**有序**列表：目录树按此顺序渲染顶层部门节点（空部门同样占位）。
# ALLOWED_DEPTS 仅为校验用的集合，顺序无意义，故另设此有序列表。
DEPT_ORDER = ['财务中心', '核算部', '总账部', '管理部', '资金部', '商务部']
ALLOWED_DEPTS = set(DEPT_ORDER)
ALLOWED_ATTRS = {'日常', '专项'}
ALLOWED_STATUSES = {'启用', '封存'}

class BoardConfigReq(BaseModel):
    board_id: str = ''      # 关联的真实看板 id（boards ∪ cards 派生的 board_id）
    year: str
    dept: str
    attr: str
    status: str = '启用'
    remark: str = ''

def _validate_board_config(year, dept, attr, status):
    if year not in ALLOWED_YEARS:
        raise HTTPException(400, '年份必须是 ' + '/'.join(sorted(ALLOWED_YEARS)) + ' 之一')
    if dept not in ALLOWED_DEPTS:
        raise HTTPException(400, '归属部门必须是 ' + '/'.join(sorted(ALLOWED_DEPTS)) + ' 之一')
    if attr not in ALLOWED_ATTRS:
        raise HTTPException(400, '属性必须是 ' + '/'.join(ALLOWED_ATTRS) + ' 之一')
    if status not in ALLOWED_STATUSES:
        raise HTTPException(400, '状态必须是 ' + '/'.join(ALLOWED_STATUSES) + ' 之一')

@app.get('/api/boards')
def list_boards(username: str = Depends(require_auth)):
    """看板管理列表：真实看板（boards ∪ cards 派生）+ 卡片数 + 关联配置。
    看板管理功能直接作用于当前在用的真实看板，通过 board_id 与 board_config 关联。"""
    boards = _all_boards()
    counts = {}
    for r in dbq('SELECT board_id, COUNT(*) AS cnt FROM cards WHERE deleted=0 GROUP BY board_id'):
        counts[r['board_id']] = r['cnt']
    cfgs = {}
    for r in dbq('SELECT id, board_id, year, dept, attr, status, remark, created_at FROM board_config'):
        cfgs[r['board_id']] = dict(r)
    out = []
    for b in boards:
        bid = b['board_id']
        c = cfgs.get(bid, {})
        out.append({
            'board_id': bid,
            'board_name': b['board_name'],
            'workspace_id': b.get('workspace_id', ''),
            'card_count': counts.get(bid, 0),
            'config_id': c.get('id'),
            'year': c.get('year', ''),
            'dept': c.get('dept', ''),
            'attr': c.get('attr', ''),
            'status': c.get('status', ''),
            'remark': c.get('remark', ''),
        })
    return {'boards': out}

@app.get('/api/board-config')
def list_board_config(username: str = Depends(require_auth)):
    """看板配置列表（含关联看板名称），按年份↓、部门、属性排序"""
    rows = dbq('''SELECT c.id, c.board_id, c.year, c.dept, c.attr, c.status, c.remark, c.created_at,
                        COALESCE(b.board_name, '') AS board_name
                 FROM board_config c
                 LEFT JOIN boards b ON b.board_id = c.board_id
                 ORDER BY c.year DESC, c.dept, c.attr''')
    return {'items': [dict(r) for r in rows]}

@app.post('/api/board-config')
def create_board_config(req: BoardConfigReq, username: str = Depends(require_admin), request: Request = None):
    """为真实看板登记配置（仅管理员）。每个看板仅一条配置。"""
    bid = (req.board_id or '').strip()
    if not bid:
        raise HTTPException(400, '必须选择关联看板')
    if not dbq('SELECT 1 FROM boards WHERE board_id=?', (bid,)) and \
       not dbq('SELECT 1 FROM cards WHERE board_id=? AND deleted=0', (bid,)):
        raise HTTPException(404, '关联看板不存在')
    year = req.year.strip(); dept = req.dept.strip(); attr = req.attr.strip()
    status = (req.status or '启用').strip(); remark = (req.remark or '').strip()
    if not (year and dept and attr):
        raise HTTPException(400, '年份 / 归属部门 / 属性 均必填')
    _validate_board_config(year, dept, attr, status)
    if dbq('SELECT 1 FROM board_config WHERE board_id=?', (bid,)):
        raise HTTPException(409, '该看板已存在配置，请勿重复添加')
    try:
        dbe('INSERT INTO board_config (board_id, year, dept, attr, status, remark) VALUES (?,?,?,?,?,?)',
            (bid, year, dept, attr, status, remark))
    except sqlite3.IntegrityError:
        raise HTTPException(409, '该看板已存在配置')
    audit_log(username, client_ip(request), 'board_config_create', f'{bid}/{year}/{dept}/{attr}',
              f'状态={status}', 'success')
    return {'ok': True}

@app.put('/api/board-config/{cid}')
def update_board_config(cid: int, req: BoardConfigReq, username: str = Depends(require_admin), request: Request = None):
    """更新看板配置（仅管理员）。board_id 创建后锁定，不可改挂其他看板。"""
    if not dbq('SELECT 1 FROM board_config WHERE id=?', (cid,)):
        raise HTTPException(404, '配置不存在')
    year = req.year.strip(); dept = req.dept.strip(); attr = req.attr.strip()
    status = (req.status or '启用').strip(); remark = (req.remark or '').strip()
    if not (year and dept and attr):
        raise HTTPException(400, '年份 / 归属部门 / 属性 均必填')
    _validate_board_config(year, dept, attr, status)
    dbe('UPDATE board_config SET year=?, dept=?, attr=?, status=?, remark=? WHERE id=?',
        (year, dept, attr, status, remark, cid))
    audit_log(username, client_ip(request), 'board_config_update', f'id={cid}',
              f'{year}/{dept}/{attr} 状态={status}', 'success')
    return {'ok': True}

@app.delete('/api/board-config/{cid}')
def delete_board_config(cid: int, username: str = Depends(require_admin), request: Request = None):
    """删除看板配置（仅管理员）"""
    r = dbq('SELECT year, dept, attr FROM board_config WHERE id=?', (cid,))
    if not r:
        raise HTTPException(404, '配置不存在')
    dbe('DELETE FROM board_config WHERE id=?', (cid,))
    row = r[0]
    audit_log(username, client_ip(request), 'board_config_delete',
              f'{row["year"]}/{row["dept"]}/{row["attr"]}', f'id={cid}', 'success')
    return {'ok': True}

# ---------------- API：管理员账号管理 ----------------
class UserCreate(BaseModel):
    username: str
    password: str
    role: str = 'viewer'
    boards: str = '*'
    columns: str = '*'    # '*' 或 JSON {board_id:[column_id,...]}

class UserUpdateReq(BaseModel):
    role: Optional[str] = None
    boards: Optional[str] = None
    columns: Optional[str] = None
    password: Optional[str] = None

def norm_columns(raw: str) -> str:
    """校验并规范化 allowed_columns：'*' 或 JSON"""
    if not raw or raw.strip() == '*':
        return '*'
    try:
        obj = json.loads(raw)
        if not isinstance(obj, dict):
            raise ValueError('columns 必须是 JSON 对象')
        clean = {str(k): [str(x) for x in v] for k, v in obj.items() if v}
        return json.dumps(clean, ensure_ascii=False)
    except Exception:
        raise HTTPException(400, 'columns 格式应为 * 或 {"看板ID":["板块ID",...]}')

@app.get('/api/admin/users')
def admin_list_users(username: str = Depends(require_admin)):
    rows = dbq('SELECT username, role, allowed_boards, allowed_columns, created_at FROM users ORDER BY id')
    return {'users': [dict(r) for r in rows]}

@app.get('/api/admin/board-columns')
def admin_board_columns(username: str = Depends(require_admin)):
    """全部看板及其板块清单（供账号权限配置界面用）"""
    rows = dbq('SELECT DISTINCT board_id, board_name, column_id, column_name FROM cards WHERE deleted=0')
    boards = {}
    for r in rows:
        b = boards.setdefault(r['board_id'], {'board_name': r['board_name'], 'columns': {}})
        if r['column_id']:
            b['columns'][r['column_id']] = r['column_name']
    return {'boards': boards}

@app.post('/api/admin/users')
def admin_create_user(req: UserCreate, username: str = Depends(require_admin), request: Request = None):
    name = req.username.strip()
    if not name or not req.password:
        raise HTTPException(400, '账号和密码不能为空')
    if get_user(name):
        raise HTTPException(409, '账号已存在')
    if req.role not in ('viewer', 'editor', 'admin'):
        raise HTTPException(400, '角色必须是 viewer/editor/admin')
    boards = '*' if req.boards == '*' else ','.join(x for x in req.boards.split(',') if x)
    columns = norm_columns(req.columns)
    dbe('INSERT INTO users (username, password_hash, role, allowed_boards, allowed_columns) VALUES (?,?,?,?,?)',
        (name, hash_pw(req.password), req.role, boards, columns))
    log_action('__user__', username, 'user_create', f'{name}({req.role})')
    audit_log(username, client_ip(request), 'user_create', f'账号 {name}', f'新建登录账号（角色：{req.role}）', 'success')
    return {'ok': True}

@app.put('/api/admin/users/{name}')
def admin_update_user(name: str, req: UserUpdateReq, username: str = Depends(require_admin), request: Request = None):
    u = get_user(name)
    if not u:
        raise HTTPException(404, '账号不存在')
    if req.role is not None and req.role not in ('viewer', 'editor', 'admin'):
        raise HTTPException(400, '角色必须是 viewer/editor/admin')
    sets, vals = [], []
    if req.role is not None:
        sets.append('role=?'); vals.append(req.role)
    if req.boards is not None:
        b = '*' if req.boards == '*' else ','.join(x for x in req.boards.split(',') if x)
        sets.append('allowed_boards=?'); vals.append(b)
    if req.columns is not None:
        sets.append('allowed_columns=?'); vals.append(norm_columns(req.columns))
    if req.password:
        sets.append('password_hash=?'); vals.append(hash_pw(req.password))
    if sets:
        vals.append(name)
        dbe(f'UPDATE users SET {", ".join(sets)} WHERE username=?', vals)
        log_action('__user__', username, 'user_update', name)
        audit_log(username, client_ip(request), 'user_update', f'账号 {name}', '更新账号（角色/权限' + ('/密码' if req.password else '') + '）', 'success')
    return {'ok': True}

@app.delete('/api/admin/users/{name}')
def admin_delete_user(name: str, username: str = Depends(require_admin), request: Request = None):
    if name == username:
        raise HTTPException(400, '不能删除当前登录的管理员账号')
    res = dbe('DELETE FROM users WHERE username=?', (name,))
    if res.rowcount == 0:
        raise HTTPException(404, '账号不存在')
    log_action('__user__', username, 'user_delete', name)
    audit_log(username, client_ip(request), 'user_delete', f'账号 {name}', '删除登录账号', 'success')
    return {'ok': True}

# ---------------- API：跨看板移动 ----------------
class MoveReq(BaseModel):
    board_id: str
    column_id: str = ''
    column_name: str = ''

@app.put('/api/cards/{card_id}/move')
async def move_card(card_id: str, req: MoveReq, username: str = Depends(require_editor), request: Request = None):
    holder = lock_mgr.who(card_id)
    if holder and holder != username:
        raise HTTPException(409, f'卡片已被 {holder} 编辑中，无法移动')
    # 成本卡权限：源是成本或目标是成本 → 需 admin
    src_row = dbq('SELECT board_id FROM cards WHERE card_id=? AND deleted=0', (card_id,))
    if not src_row:
        raise HTTPException(404, '卡片不存在或已删除')
    check_cost_permission(src_row[0]['board_id'], username)
    check_cost_permission(req.board_id, username)
    # 目标看板是否存在
    tgt = dbq('SELECT board_id, board_name FROM cards WHERE board_id=? AND deleted=0 LIMIT 1', (req.board_id,))
    if not tgt:
        raise HTTPException(400, '目标看板不存在或不可见')
    dbe('UPDATE cards SET board_id=?, board_name=?, column_id=?, column_name=? WHERE card_id=? AND deleted=0',
        (req.board_id, tgt[0]['board_name'], req.column_id, req.column_name, card_id))
    # 子事项跟随父卡移动（保持同看板）
    dbe('UPDATE cards SET board_id=?, board_name=? WHERE parent_id=? AND deleted=0',
        (req.board_id, tgt[0]['board_name'], card_id))
    log_action(card_id, username, 'move', f'→ {tgt[0]["board_name"]}')
    audit_log(username, client_ip(request), 'move', f'卡片 {card_id}', f'移动到看板「{tgt[0]["board_name"]}」', 'success')
    await ws_mgr.broadcast({'type': 'card_update', 'card_id': card_id, 'by': username}, exclude=username)
    return {'ok': True}

# ---------------- API：导出 / 导入 ----------------
# xlsx 导出的列定义（与 TAPD 平台导出格式对齐，全部平铺，无合并单元格）
XLSX_COLUMNS = [
    ('卡片名称',   'card_name',    50),
    ('详细描述',   'description',  50),
    ('板块标题',   'column_name',  15),
    ('状态',       'status_name',  15),
    ('开始时间',   'begin',        15),
    ('截止时间',   'due',          15),
]

@app.get('/api/export/xlsx')
def export_xlsx(board_id: str = '', username: str = Depends(require_auth), request: Request = None):
    """导出当前用户可见范围的卡片为 xlsx（.xlsx）

    - board_id 非空时只导出该看板（仍受用户看板/板块权限约束）
    - 严格遵循用户可见性（看板 + 板块双层过滤）
    - 全平铺结构，**不使用任何合并单元格**（merge_cells 一次都不调用）
    - 表头加粗居中、首行冻结、自动筛选
    """
    import io
    from openpyxl import Workbook
    from openpyxl.styles import Font, Alignment, PatternFill, Border, Side
    from openpyxl.utils import get_column_letter

    boards, columns = user_allowed(username)
    # 指定看板时做交集校验：不在可见范围内的看板按不可见处理
    target_boards = None
    if board_id:
        if boards is None:
            target_boards = {board_id}
        elif board_id in boards:
            target_boards = {board_id}
        else:
            target_boards = set()
    cards = [dict(r) for r in filter_rows(
        dbq('SELECT * FROM cards WHERE deleted=0'), target_boards, columns)]
    # 稳定排序：按开始时间、卡片名，保证多次导出一致
    cards.sort(key=lambda c: (str(c.get('begin') or ''), str(c.get('card_name') or '')))

    wb = Workbook()
    ws = wb.active
    ws.title = 'Board_list'

    header_font = Font(bold=True, size=11)
    header_align = Alignment(horizontal='center', vertical='center')
    header_fill = PatternFill('solid', fgColor='F2F2F2')
    thin = Side(style='thin', color='D0D0D0')
    cell_border = Border(left=thin, right=thin, top=thin, bottom=thin)
    body_align = Alignment(vertical='top', wrap_text=True)

    # 表头
    for idx, (title, _key, _w) in enumerate(XLSX_COLUMNS, start=1):
        c = ws.cell(row=1, column=idx, value=title)
        c.font = header_font
        c.alignment = header_align
        c.fill = header_fill
        c.border = cell_border

    # 数据行（逐格写入，不做任何单元格合并）
    for r, card in enumerate(cards, start=2):
        for idx, (_title, key, _w) in enumerate(XLSX_COLUMNS, start=1):
            val = card.get(key)
            if val is None:
                val = ''
            c = ws.cell(row=r, column=idx, value=val)
            c.alignment = body_align
            c.border = cell_border

    # 列宽
    for idx, (_title, _key, width) in enumerate(XLSX_COLUMNS, start=1):
        ws.column_dimensions[get_column_letter(idx)].width = width

    # 冻结首行 + 自动筛选（增强可读性，不涉及合并）
    ws.freeze_panes = 'A2'
    if cards:
        ws.auto_filter.ref = f'A1:{get_column_letter(len(XLSX_COLUMNS))}{len(cards) + 1}'

    # 落盘到内存
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)

    audit_log(username, client_ip(request), 'export', '数据导出',
              f'导出 xlsx：卡片 {len(cards)} 张', 'success')

    # 文件名沿用 TAPD 命名习惯：看板名_YYYYMMDDHHMMSS.xlsx
    ts = time.strftime('%Y%m%d%H%M%S')
    if target_boards is not None and len(target_boards) == 1:
        bid = list(target_boards)[0]
        row = dbq('SELECT board_name FROM boards WHERE board_id=? LIMIT 1', (bid,))
        board_label = (row[0]['board_name'] if row else '') or '看板'
    else:
        names = sorted({c.get('board_name') or '' for c in cards if c.get('board_name')})
        if len(names) == 1:
            board_label = names[0]
        elif names:
            board_label = f'{len(names)}个看板'
        else:
            board_label = '全部看板'
    safe = re.sub(r'[\\/:*?"<>|]', '_', board_label)
    filename = f'看板_{safe}_{ts}.xlsx'
    # RFC 5987 编码，兼容中文文件名
    from urllib.parse import quote
    disposition = f"attachment; filename*=UTF-8''{quote(filename)}"

    return Response(
        content=buf.getvalue(),
        media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        headers={'Content-Disposition': disposition},
    )


@app.get('/api/export')
def export_data(username: str = Depends(require_auth), request: Request = None):
    """导出当前用户可见范围全部数据为 JSON（含团队、评论、子事项）"""
    boards, columns = user_allowed(username)
    cards = [dict(r) for r in filter_rows(
        dbq('SELECT * FROM cards WHERE deleted=0'), boards, columns)]
    teams = [dict(r) for r in dbq('SELECT id, name FROM team_members ORDER BY id')]
    # 子事项：仅导出可见卡片的
    cids = [c['card_id'] for c in cards]
    subtasks = []
    if cids:
        marks = ','.join('?' * len(cids))
        subtasks = [dict(r) for r in dbq(
            f'SELECT id, card_id, title, done, sort, done_by, done_at, created_by, created_at '
            f'FROM card_subtasks WHERE card_id IN ({marks}) ORDER BY card_id, sort', cids)]
    audit_log(username, client_ip(request), 'export', '数据导出', f'导出备份：卡片 {len(cards)} 张、子事项 {len(subtasks)} 条', 'success')
    return {'exported_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'exported_by': username,
            'boards': list(set((c['board_id'], c['board_name']) for c in cards)),
            'cards': cards,
            'subtasks': subtasks,
            'team': teams}

class ImportReq(BaseModel):
    cards: List[dict] = []
    subtasks: List[dict] = []
    team: List[str] = []

@app.post('/api/import')
async def import_data(req: ImportReq, username: str = Depends(require_editor), request: Request = None):
    """导入 JSON 备份（覆盖式恢复卡片、团队、子事项）"""
    if not req.cards and not req.team and not req.subtasks:
        raise HTTPException(400, '导入内容为空')
    conn = get_conn()
    try:
        if req.cards:
            conn.execute('UPDATE cards SET deleted=1')
            for c in req.cards:
                if not c.get('card_id'):
                    continue
                cols = [k for k in CARD_FIELDS if k in c]
                if not cols:
                    continue
                conn.execute(f'INSERT OR REPLACE INTO cards ({",".join(cols)}) VALUES ({",".join("?"*len(cols))})',
                             [c[k] for k in cols])
            # 清掉旧子事项，恢复导入的子事项
            conn.execute('DELETE FROM card_subtasks')
            for s in req.subtasks:
                if not s.get('card_id'):
                    continue
                conn.execute(
                    'INSERT INTO card_subtasks (id, card_id, title, done, sort, done_by, done_at, created_by, created_at) '
                    'VALUES (?,?,?,?,?,?,?,?,?)',
                    (s.get('id', 0), s['card_id'], s.get('title', ''),
                     1 if s.get('done') else 0, s.get('sort', 0),
                     s.get('done_by', ''), s.get('done_at', ''),
                     s.get('created_by', ''), s.get('created_at', '') or time.strftime('%Y-%m-%d %H:%M:%S')))
        if req.team:
            conn.execute('DELETE FROM team_members')
            for n in req.team:
                name = n.get('name') if isinstance(n, dict) else n
                if name and str(name).strip():
                    conn.execute('INSERT INTO team_members (name) VALUES (?)', (str(name).strip(),))
        conn.commit()
    finally:
        conn.close()
    log_action('__import__', username, 'import', f'cards={len(req.cards)} team={len(req.team)}')
    audit_log(username, client_ip(request), 'import', '数据导入', f'导入备份：卡片 {len(req.cards)} 张、子事项 {len(req.subtasks)} 条、团队成员 {len(req.team)} 人', 'success')
    await ws_mgr.broadcast({'type': 'card_update', 'card_id': '*', 'by': username})
    return {'ok': True, 'cards': len(req.cards), 'team': len(req.team)}

# ---------------- API：审计日志查询（仅管理员） ----------------
@app.get('/api/audit-logs')
def get_audit_logs(start: Optional[str] = None, end: Optional[str] = None,
                   action: Optional[str] = None, username: Optional[str] = None,
                   ip: Optional[str] = None, result: Optional[str] = None,
                   page: int = 1, page_size: int = 30,
                   current_user: str = Depends(require_admin), request: Request = None):
    where, vals = [], []
    if start:
        where.append('ts >= ?'); vals.append(start if len(start) > 10 else start + ' 00:00:00')
    if end:
        where.append('ts <= ?'); vals.append(end if len(end) > 10 else end + ' 23:59:59')
    if action:
        where.append('action = ?'); vals.append(action)
    if username:
        where.append('username LIKE ?'); vals.append(f'%{username}%')
    if ip:
        where.append('ip LIKE ?'); vals.append(f'%{ip}%')
    if result:
        where.append('result = ?'); vals.append(result)
    cond = ('WHERE ' + ' AND '.join(where)) if where else ''
    total = dbq(f'SELECT COUNT(*) n FROM audit_logs {cond}', vals)[0]['n']
    page = max(1, page)
    page_size = max(1, min(page_size, 200))
    offset = (page - 1) * page_size
    rows = dbq(f'SELECT id, ts, username, ip, action, target, detail, result '
               f'FROM audit_logs {cond} ORDER BY id DESC LIMIT ? OFFSET ?',
               vals + [page_size, offset])
    return {'total': total, 'page': page, 'page_size': page_size,
            'items': [dict(r) for r in rows]}

# ---------------- 静态页面 ----------------
import time as _time
def _index_resp():
    p = os.path.join(STATIC_DIR, 'index.html')
    with open(p, 'r', encoding='utf-8') as f:
        html = f.read()
    # 注入构建戳，确保浏览器每次都重新加载（开发期破缓存）
    html = html.replace('</head>', f'<meta name="build" content="{int(_time.time())}">\n</head>', 1)
    return Response(
        content=html, media_type='text/html',
        headers={'Cache-Control': 'no-store, max-age=0', 'Pragma': 'no-cache', 'Expires': '0'}
    )

def _login_resp():
    return FileResponse(
        os.path.join(STATIC_DIR, 'login.html'),
        headers={'Cache-Control': 'no-cache, no-store, must-revalidate',
                 'Pragma': 'no-cache', 'Expires': '0'}
    )

@app.get('/')
def index():
    return _index_resp()

@app.get('/login')
def login_page():
    return _login_resp()

# ---------------- 启动初始化：确保数据表存在（含 workgroups 表） ----------------
try:
    from app.init_db import init_db
    init_db()
except Exception as e:
    print('WARN: init_db() 失败:', e)
