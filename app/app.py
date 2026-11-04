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
from datetime import datetime, date as _date
from typing import Optional, List, Union
from fastapi import FastAPI, HTTPException, Depends, Header, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import FileResponse, Response, JSONResponse
from pydantic import BaseModel

# 分级权限内核（2026-11-02）：架构 > 看板 > 板块 > 事项
# 角色继承：架构负责人 ⊃ 看板负责人 ⊃ 板块负责人 ⊃ 事项负责人 ⊃ 参与人
try:
    from .perm import (PermError, E_DENIED, E_CROSS_SCOPE, E_NOT_OWNER, E_NOT_MEMBER,
                       E_LEVEL, E_ADMIN_ONLY, E_SELF_LOCK,
                       LV_NONE, LV_PARTICIPANT, LV_CARD_OWNER, LV_COLUMN_OWNER,
                       LV_BOARD_OWNER, LV_ARCH_OWNER, LV_ADMIN, LV_SUPER,
                       ROLE_NAMES, LEVEL_KEY,
                       OP_VIEW, OP_CREATE, OP_UPDATE, OP_DELETE,
                       OP_ASSIGN_OWNER, OP_ASSIGN_PARTICIPANT, OP_EDIT_CONTENT,
                       ALL_OPS, OP_MIN_LEVEL, OP_TARGET_LEVEL,
                       resource_chain, effective_level, has_role, can_do, can_do_level,
                       require_perm,
                       require_perm_level, can_do_level,
                       assert_same_arch, identity_names, _split_list,
                       _arch_scope_nodes, _arch_leader_nodes)
    PERM_ENABLED = True
except ImportError:                      # pragma: no cover —— 直接以脚本方式运行时
    PERM_ENABLED = False
    print('[WARN] perm.py 未加载 —— 分级权限校验不可用')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, '..', 'app.db')
STATIC_DIR = os.path.join(BASE_DIR, '..', 'static')
SECRET = os.environ.get('APP_SECRET', 'tapd-webapp-dev-secret-change-me')
TOKEN_TTL = 7 * 24 * 3600
LOCK_TIMEOUT = 300
LOCK_HEARTBEAT = 60

# ---------------- 登录失败锁定策略 ----------------
# 连续失败 LOGIN_FAIL_THRESHOLD 次 → 冷却 LOGIN_COOLDOWN 秒内不允许再试
# 连续失败 LOGIN_LOCK_THRESHOLD 次 → 永久锁定，需管理员重置
LOGIN_FAIL_THRESHOLD = 5
LOGIN_COOLDOWN = 180          # 3 分钟
LOGIN_LOCK_THRESHOLD = 10
SUPER_ADMIN = 'admin'   # 内置超级管理员（不可删/改密码/改角色/换绑）
# 「无负责人」筛选的哨兵值：前端下拉用它表示「负责人为空」。
# 不能用空字符串（那是「全部负责人」），也不能与真实负责人重名（负责人是中文姓名）。
OWNER_NONE = '__no_owner__'


def _norm_date(s):
    """归一化日期筛选参数 → 'YYYY-MM-DD'；空值或非法格式返回 None（该条件不参与筛选）。

    接受 'YYYY-MM-DD' / 'YYYY-MM-DD HH:MM' / 'YYYY-MM-DD HH:MM:SS' / 'YYYY/MM/DD'。
    非法值一律忽略而不报错 —— 避免一个脏参数让整个列表接口 500。
    """
    if s is None:
        return None
    s = str(s).strip()
    if not s:
        return None
    for f in ('%Y-%m-%d', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y/%m/%d'):
        try:
            return datetime.strptime(s, f).strftime('%Y-%m-%d')
        except ValueError:
            pass
    return None
def week_label(s) -> str:
    """周数标签：按**自然周（周一 ~ 周日）**计算，格式「2026年第41周」。

    归属年采用 ISO-8601 规则 —— 该周**周四**所在的年份（与 Excel / ISO 周编号一致），
    所以跨年周的归属年可能与日历年不同（如 2027-01-01 属于 2026 年第 53 周）。
    空值 / 非法日期返回空串。
    """
    m = re.match(r'^(\d{4})-(\d{1,2})-(\d{1,2})', str(s or '').strip())
    if not m:
        return ''
    try:
        d = _date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return ''
    iso = d.isocalendar()
    return '%d年第%d周' % (iso[0], iso[1])


WEEK_RE = re.compile(r'^\d{4}年第(\d{1,2})周$')


def week_sort_key(v):
    """周数排序键：把「2026年第41周」折成 (2026, 41) 这样的组合整数。

    ⚠️ 不能直接按字符串排序 —— 字典序下「第3周」会排在「第31周」**后面**
    （比较到 '3' 与 '周' 时 '3' 更大），列表会变成
    「第31周、第33周、第3周、第44周、第4周」这种乱序。
    这里用 (年, 周号) 数值对排序 → 等价于 202601 ~ 202644 的整数序。
    非标准标签统一排到最后并保持彼此的原始次序（稳定排序）。
    """
    s = (v or '').strip()
    m = re.match(r'^(\d{4})年第(\d{1,2})周$', s)
    if m:
        return (int(m.group(1)), int(m.group(2)), 0, s)
    return (9999, 0, 1, s)


def _norm_week(v) -> str:
    """周数字段归一：接受「2026年第41周」或「2026-41」，返回标准标签；非法值报错。"""
    s = str(v or '').strip()
    if not s:
        return ''
    m = WEEK_RE.match(s)
    if m:
        wk = int(m.group(1))
        if 1 <= wk <= 53:
            return s
        raise HTTPException(400, '周数应在第 1 ~ 53 周之间')
    m = re.match(r'^(\d{4})-(\d{1,2})$', s)
    if m:
        wk = int(m.group(2))
        if 1 <= wk <= 53:
            return '%s年第%d周' % (m.group(1), wk)
    raise HTTPException(400, '周数格式应为「2026年第41周」')


CARD_FIELDS = ['card_id','board_id','board_name','column_id','column_name','workspace_id',
    'card_name','status','status_name','priority','creator','owner','cc','follower',
    'begin','due','completed','created','modified','description','attachment_count',
    'label','b_sort','entity_type','cover_setted','cover_info','is_filed','created_from',
    'date_status','due_time_ux','begin_date_status','begin_time_ux','comments',
    'column_sort','board_status','board_creator','parent_id','pinned',
    'week_no','copy_from']

app = FastAPI(title="财务综合事务平台 FISP", docs_url=None, redoc_url=None)


# ---------------- 分级权限：异常处理与辅助（2026-11-02）----------------
if PERM_ENABLED:
    @app.exception_handler(PermError)
    async def _perm_error_handler(request: Request, exc: PermError):
        # 统一越权返回形式：**HTTP 403 + 固定错误体**。
        # 错误体结构（前端与外部调用方据此判断）：
        # {error: PERMISSION_DENIED, code: <细分错误码>, message: <可读提示>,
        #  need_level: 4, need_role: 看板负责人, have_level: 1, have_role: 参与人,
        #  resource: board:xxx, op: delete}
        return JSONResponse(status_code=403, content=exc.to_dict())


def perm_chain(board_id=None, column_id=None, card_id=None):
    # 定位资源链（架构 → 看板 → 板块 → 事项）
    return resource_chain(dbq, board_id=board_id, column_id=column_id, card_id=card_id)


def perm_check(username, chain, op, resource_level, resource_desc='', min_level=None):
    # 分级权限校验 —— 不通过直接抛 PermError（→ 403）。
    #
    # ⚠️ **两个维度必须分开**（本项目踩过坑）：
    #   · resource_level = **目标资源在哪一层**（架构/看板/板块/事项）
    #   · min_level      = **执行该操作所需的最低角色等级**
    #   之前把两者混用一个参数 → 「架构负责人改事项」被误判成 level_mismatch。
    #
    # min_level 省略时用 perm.py 的默认门槛（OP_MIN_LEVEL）。
    # 管理员（role=admin）与超管（username=admin）超脱本体系，拥有全部权限；
    # 但「配置管理员权限」只允许超管。
    if not PERM_ENABLED:
        return
    if min_level is None:
        require_perm(dbq, username, chain, op, resource_level,
                     resource_desc=resource_desc,
                     is_admin=is_admin(username), is_super=(username == SUPER_ADMIN))
    else:
        require_perm_level(dbq, username, chain, op, resource_level, min_level,
                           resource_desc=resource_desc,
                           is_admin=is_admin(username), is_super=(username == SUPER_ADMIN))


def perm_check_pass(username, chain, op, resource_level, min_level=None):
    # 「能不能做」的**布尔版**判定 —— 不抛异常，用于给前端渲染能力标记。
    # 与 perm_check() 共用同一套判定逻辑（perm.py 的 can_do），
    # 保证「前端显示能做」与「后端真放行」永不打架。
    if not PERM_ENABLED:
        return True
    if username == SUPER_ADMIN:
        return True
    if is_admin(username):
        return True
    if min_level is None:
        ok, _info = can_do(dbq, username, chain, op, resource_level,
                           is_admin=False, is_super=False)
    else:
        ok, _info = can_do_level(dbq, username, chain, op, resource_level, min_level,
                                 is_admin=False, is_super=False)
    return bool(ok)


def perm_check_arch_scope(username, op, resource_desc='', node_id=None):
    # 「在所属架构下新增看板」这类**没有具体目标资源**的操作。
    # 判定：操作者是否是**任一架构节点**的负责人（架构负责人及以上）。
    # ⚠️ 边界：若操作者不是任何架构的负责人 → 拒绝（fail-closed）。
    #   管理员/超管超脱本体系，直接放行。
    if not PERM_ENABLED:
        return
    if username == SUPER_ADMIN or is_admin(username):
        return
    scope = _arch_scope_nodes(dbq, username)
    if not scope:
        raise PermError(E_NOT_OWNER,
                        '只有架构负责人才能在该架构下新增看板',
                        need_level=LV_ARCH_OWNER, have_level=LV_NONE,
                        resource=resource_desc, op=op)
    if node_id and node_id not in scope:
        raise PermError(E_CROSS_SCOPE,
                        '无权在该架构下执行此操作（不在你的负责范围内）',
                        need_level=LV_ARCH_OWNER, have_level=LV_ARCH_OWNER,
                        resource=resource_desc, op=op)


def perm_level_of(username, chain):
    # 取操作者对某资源的有效角色等级（供前端展示「你在这里是什么身份」）
    if not PERM_ENABLED:
        return LV_NONE
    if username == SUPER_ADMIN:
        return LV_SUPER
    if is_admin(username):
        return LV_ADMIN
    return effective_level(dbq, username, chain)

# ---------------- 数据库 ----------------
_WAL_READY = False
_local = threading.local()

def get_conn():
    """**每线程复用**一个 SQLite 连接。

    为什么复用（实测数据，Windows 本地）：
      · 新建连接并执行**第一条**语句要 ~1.15ms（文件锁开销），之后的语句几乎免费；
      · 一次权限判定要查 20 多个小表 → 旧写法（每次查询开+关一个连接）
        白花 20~30ms，列表接口整体变慢；
      · 改成每线程一个连接后，连接开销只付一次，DB 相关操作快约 10 倍。

    线程安全：FastAPI 的同步接口跑在线程池里，每个线程各持一份连接，
    互不共享（`check_same_thread=False` 只是兜底）。
    """
    conn = getattr(_local, 'conn', None)
    if conn is not None:
        return conn
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    if not _WAL_READY:
        # WAL 是**数据库文件级**设置（写进文件头），设置一次即持久生效，
        # 不需要每次连接都执行。
        try:
            conn.execute('PRAGMA journal_mode=WAL')
            globals()['_WAL_READY'] = True
        except sqlite3.Error:
            pass
    _local.conn = conn
    return conn

def dbq(sql, params=()):
    conn = get_conn()
    try:
        return conn.execute(sql, params).fetchall()
    except Exception:
        # 连接是复用的：出错时必须回滚，避免把未提交事务留给后续请求
        try:
            conn.rollback()
        except Exception:
            pass
        raise

def dbe(sql, params=()):
    conn = get_conn()
    try:
        cur = conn.execute(sql, params)
        conn.commit()
        return cur
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise

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

def _member_display_name(username: str) -> str:
    """账号对应的成员姓名（顶栏显示「姓名(账号)」用）。
    账号未绑定成员、或绑定的姓名与账号相同（本身就是姓名）时返回空串，
    由前端回退为「只显示账号」。"""
    row = dbq('SELECT name FROM team_members WHERE account=? LIMIT 1', (username,))
    if not row:
        return ''
    name = (row[0]['name'] or '').strip()
    if not name or name == username:
        return ''
    return name

_LEADER_ALL = '__ALL_BOARDS__'   # 负责人范围含'*'（全量）的标记

def _all_board_ids() -> set:
    """全部看板 id 集合（boards 表 ∪ cards 派生）。"""
    return {b['board_id'] for b in _all_boards()}


def _node_bound_boards(node: dict, owned=None, wg_by_id=None) -> set:
    """单个架构节点「绑定」的看板集合（按节点类型派生，与看板管理口径一致）。

    · 中心(center) = 全部看板（管理层全范围）
    · 部门(dept)   = 归属该部门的看板（board_config.dept_node_id 派生，唯一真相）
    · 小组(group)  = 工作组手工勾选的看板（workgroups.boards）

    【修复】此前部门/中心节点一律去读 workgroups.boards，而该字段对
    部门/中心恒为空 → 负责范围层算出来永远是空集，负责人权限范围形同虚设。
    这里改为按节点类型派生，与「看板管理 · 归属部门」保持同一真相。
    """
    ntype = node.get('node_type')
    if ntype == 'center':
        return _all_board_ids()
    if ntype == 'dept':
        owned = owned if owned is not None else _dept_owned_boards()
        return set(owned.get(node['id'], set()))
    # 小组节点：读工作组的工绑定
    if wg_by_id is None:
        wg_by_id = {r['id']: dict(r) for r in dbq('SELECT id, boards FROM workgroups')}
    wg = wg_by_id.get(node.get('wg_id') or 0)
    raw = (wg['boards'] or '').strip() if wg else ''
    if raw == '*':
        return _all_board_ids()
    return {x for x in raw.split(',') if x} if raw else set()


def _node_arch_boards(node: dict, owned=None, wg_by_id=None, nmap=None) -> set:
    """节点「**架构下所有看板**」（2026-11-03）。

    = ① 本节点归属的看板（dept/center 口径：board_config.dept_node_id）
    + ② 本节点**及其全部后代**小组节点**已手工绑定**的看板（workgroups.boards）

    ⚠️ 为什么需要它（用户反馈的根因）：
      【架构管理】的「板块绑定」勾选池原来取 `parentBoardLimit(父节点)`
      = 父部门的**归属**看板 → 部门下的小组永远显示「未绑定板块」且勾不到任何东西
      （子组被父部门的归属范围卡死）。部门长/组长需要的恰恰是
      「本部门架构下所有看板」，才能给子组绑定。

    ⚠️ 不改变可见性口径 —— 只用于【架构管理】的绑定勾选池。
    """
    if not node:
        return set()
    if owned is None:
        owned = _dept_owned_boards()
    if wg_by_id is None:
        wg_by_id = {r['id']: dict(r) for r in dbq('SELECT id, boards FROM workgroups')}
    out = set()
    nid = node['id']
    # ① 本节点归属的看板
    out |= set(owned.get(nid, set()))
    # ② 本节点及其全部后代小组已绑定的看板
    if nmap is None:
        nmap = _org_node_map()
    for sub in [nid] + list(_org_node_descendants(nid, list(nmap.values()))):
        sub_node = nmap.get(sub)
        if not sub_node:
            continue
        wg = wg_by_id.get(sub_node.get('wg_id') or 0)
        raw = (wg['boards'] or '').strip() if wg else ''
        if raw == '*':
            out |= _all_board_ids()
        elif raw:
            out |= {x for x in raw.split(',') if x}
    return out


def _leader_scope_boards(username: str) -> set:
    """负责范围层：负责人额外拥有的看板（其负责节点 **及其全部后代** 绑定的看板）。"""
    nodes = _org_leader_nodes(username)
    if not nodes:
        return set()
    nmap = _org_node_map()
    owned = _dept_owned_boards()
    wg_by_id = {r['id']: dict(r) for r in dbq('SELECT id, boards FROM workgroups')}
    out = set()
    for n in nodes:
        nid = n['id']
        for sub in [nid] + list(_org_node_descendants(nid, list(nmap.values()))):
            node = nmap.get(sub)
            if node:
                out |= _node_bound_boards(node, owned, wg_by_id)
    return out


def _leader_boards(username: str):
    """【兼容保留·诊断用】负责人（部门长/组长）负责范围绑定的看板并集。

    权限判定不再走这里 —— 实际判定走 _leader_scope_boards()（按节点类型派生绑定）。
    保留本函数是为了兼容既有引用/测试，并便于排查「负责人范围」相关问题。

    登录账号 → 关联的成员中文名也要匹配（workgroups.leader 存的是成员名）。
    返回 None=非负责人；_LEADER_ALL=负责人且范围含'*'（全量）；set=负责人受限看板（可为空）。"""
    candidates = [username]
    row = dbq('SELECT name FROM team_members WHERE account=?', (username,))
    if row and row[0]['name'] and row[0]['name'] != username:
        candidates.append(row[0]['name'])
    marks = ','.join('?' * len(candidates))
    rows = dbq(f'SELECT id, parent_id, boards FROM workgroups WHERE leader IN ({marks})', candidates)
    # 【架构管理】优先：若该成员在架构管理里有「负责人」岗位任命（部门长/组长/
    # 中心负责人/总经理），以其负责范围为准 —— 旧 workgroups.leader 字段仅作回退，
    # 避免两套机制并存时负责人范围被旧字段带偏。
    org_rows = _org_leader_nodes(username)
    if org_rows:
        scope = _leader_scope_boards(username)
        if scope >= _all_board_ids() and scope:
            return _LEADER_ALL
        return scope
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


def _org_leader_nodes(username):
    """该成员在【架构管理】中担任负责人的节点列表（来自 org_appointments）。

    负责人岗位：group_leader(组长) / dept_head(部门长) / center_head(中心负责人)
    / gm(总经理)。返回 [{'id','parent_id','node_type','wg_id'}]；
    节点绑定的看板由 _node_bound_boards() 按节点类型派生（不再直接读 workgroups.boards）。
    """
    candidates = [username]
    row = dbq('SELECT name FROM team_members WHERE account=?', (username,))
    if row and row[0]['name'] and row[0]['name'] != username:
        candidates.append(row[0]['name'])
    marks = ','.join('?' * len(candidates))
    rows = dbq(f"SELECT DISTINCT n.id, n.parent_id, n.node_type, n.wg_id"
                   f" FROM org_appointments a"
                   f" JOIN org_nodes n ON n.id = a.node_id"
                   f" JOIN team_members m ON m.id = a.member_id"
                   f" WHERE a.role_key IN ('group_leader','dept_head','center_head','gm')"
                   f" AND (m.account IN ({marks}) OR m.name IN ({marks}) OR m.account=? OR m.name=?)",
                 list(candidates) + list(candidates) + [username, username])
    return [dict(r) for r in rows]


# ---------------- 归属部门（架构层级）与板块归属 ----------------
# 看板的「归属部门」不再用固定枚举，而是绑定到 org_nodes 的中心/部门节点：
#   中心级部门（如财务中心）= 全部板块，其板块对全员展示；
#   部门级节点 = 该部门拥有的板块，挂靠该部门的成员可见。
# 看板管理（board_config.dept_node_id）是唯一真相，架构管理里的
# 「板块绑定」按此联动展示，避免两处口径不一致。
def _dept_nodes():
    """架构中的部门层级节点（中心 + 部门），中心在前、按 id 排序。"""
    rows = dbq("SELECT id, name, node_type, parent_id FROM org_nodes "
               "WHERE node_type IN ('center','dept') ORDER BY id")
    return [dict(r) for r in rows]


def _dept_options():
    """归属部门下拉选项（供看板管理使用）。"""
    return [{'id': r['id'], 'name': r['name'], 'node_type': r['node_type'],
             'is_center': 1 if r['node_type'] == 'center' else 0} for r in _dept_nodes()]


def _dept_names():
    """架构中的部门名称集合（架构为空时回退到历史固定清单）。"""
    names = {r['name'] for r in _dept_nodes()}
    return names or set(DEPT_ORDER)


def _dept_order():
    """目录树展示用的部门顺序：历史顺序在前（仅保留架构里仍存在的），新增部门追加在后。"""
    exist = {r['name'] for r in _dept_nodes()}
    if not exist:
        return list(DEPT_ORDER)
    ordered = [d for d in DEPT_ORDER if d in exist]
    ordered += [n for n in sorted(exist) if n not in ordered]
    return ordered


def _center_node_ids():
    return {r['id'] for r in _dept_nodes() if r['node_type'] == 'center'}


def _dept_owned_boards():
    """{部门节点 id: set(board_id)} —— 看板按「归属部门」的归属关系。"""
    out = defaultdict(set)
    for r in dbq('SELECT board_id, dept_node_id FROM board_config WHERE dept_node_id > 0'):
        out[r['dept_node_id']].add(r['board_id'])
    return out


def _org_node_map():
    return {r['id']: dict(r) for r in
            dbq('SELECT id, name, node_type, parent_id, wg_id FROM org_nodes')}


def _dept_ancestor_of_node(node_id, nmap=None):
    """节点的最近部门层级祖先（自身若是中心/部门则取自身）。找不到返回 None。"""
    nmap = nmap or _org_node_map()
    cur = nmap.get(node_id)
    guard = 0
    while cur and guard < 20:
        guard += 1
        if cur['node_type'] in ('center', 'dept'):
            return cur
        cur = nmap.get(cur['parent_id']) if cur.get('parent_id') else None
    return None


def _member_authority_nodes(username):
    """该成员的**权威组织节点**集合（架构管理优先）。

    数据来源与优先级：
      ① org_appointments（【架构管理】的「任命」）—— 唯一权威源；
      ② team_members.workgroups（【人员与账号管理】的「工作组选择」）——
         仅当该成员在架构管理里**没有任何任命**时才作为回退。

    返回 (node_ids:set, source:str)
      source: 'org' = 来自架构管理任命
              'legacy' = 回退旧工作组字段
              'none' = 无任何归属
    node_ids 是 org_nodes.id 集合；小组节点向上取最近的部门/中心祖先。
    """
    nmap = _org_node_map()
    node_ids = set()
    member_ids = [r['id'] for r in
                  dbq('SELECT id FROM team_members WHERE account=? OR name=?', (username, username))]
    # ---- ① 架构管理任命（权威）----
    if member_ids:
        marks = ','.join('?' * len(member_ids))
        for r in dbq(f'SELECT DISTINCT node_id FROM org_appointments WHERE member_id IN ({marks})',
                     member_ids):
            node_ids.add(r['node_id'])
    if node_ids:
        scope = set()
        for nid in node_ids:
            anc = _dept_ancestor_of_node(nid, nmap)
            if anc:
                scope.add(anc['id'])
        return scope, 'org'
    # ---- ② 回退：旧 workgroups 字段 ----
    wg_by_name = {r['name']: r['id'] for r in dbq('SELECT id, name FROM workgroups')}
    node_by_wg = {n['wg_id']: n['id'] for n in nmap.values() if n.get('wg_id')}
    for r in dbq('SELECT workgroups FROM team_members WHERE account=? OR name=?', (username, username)):
        for nm in (r['workgroups'] or '').split(';'):
            nm = nm.strip()
            if not nm:
                continue
            nid = node_by_wg.get(wg_by_name.get(nm, 0))
            if nid:
                node_ids.add(nid)
    scope = set()
    for nid in node_ids:
        anc = _dept_ancestor_of_node(nid, nmap)
        if anc:
            scope.add(anc['id'])
    return scope, ('legacy' if scope else 'none')


def _member_workgroup_names(username):
    """该成员的工作组名称列表（按同一优先级推导）。

    ① 成员在架构管理里有任命 → 用其任命的**小组/部门节点**名称（权威）；
    ② 否则回退 team_members.workgroups（旧字段）。

    架构管理里「任命到部门/中心」的成员，其 workgroups 字段可能为空，
    但按权威源应视为归属该部门/中心 —— 这里返回对应节点名，
    供 _group_boards 做「祖先部门传导」计算。
    """
    nmap = _org_node_map()
    member_ids = [r['id'] for r in
                  dbq('SELECT id FROM team_members WHERE account=? OR name=?', (username, username))]
    if member_ids:
        marks = ','.join('?' * len(member_ids))
        rows = dbq(f"SELECT DISTINCT n.name, n.node_type, n.wg_id, n.parent_id"
                   f" FROM org_appointments a JOIN org_nodes n ON n.id=a.node_id"
                   f" WHERE a.member_id IN ({marks})", member_ids)
        if rows:
            # 权威源：按 org_nodes 树取该成员所属节点的**工作组的祖先链**
            names = []
            by_id = {r['id']: r for r in dbq('SELECT id, name, parent_id FROM workgroups')}
            for r in rows:
                # 该节点自身的 workgroups 名
                wg_name = ''
                if r['wg_id']:
                    wr = by_id.get(r['wg_id'])
                    if wr:
                        wg_name = wr['name']
                if wg_name and wg_name not in names:
                    names.append(wg_name)
            return names, 'org'
    row = dbq('SELECT workgroups FROM team_members WHERE account=?', (username,))
    if row and row[0]['workgroups']:
        return [g.strip() for g in row[0]['workgroups'].split(';') if g.strip()], 'legacy'
    return [], 'none'


def _member_appointed_nodes(username):
    """该成员**直接被任命到的**架构节点 id 集合（不做向上提升）。

    与 _member_authority_nodes 的区别：
      · _member_authority_nodes：把小组节点**提升**到最近的部门/中心祖先，
        用于回答「这个成员属于哪个部门」（展示用）；
      · 本函数：保留**原始任命节点**，用于权限判定 ——
        因为「小组的成员」与「部门的成员」可见的看板**不同**：
          · 任命到部门(dept)/中心(center) → 可见该节点**自己拥有**的看板；
          · 任命到小组(group)             → 可见该小组**自己绑定**的看板
            （workgroups.boards，没绑定就是没有），
            **不继承父部门的看板** ← 2026-11-02 修复（见 _dept_stage_boards）

    返回 (node_ids:set, source:str)；source 同 _member_authority_nodes。
    """
    nmap = _org_node_map()
    node_ids = set()
    member_ids = [r['id'] for r in
                  dbq('SELECT id FROM team_members WHERE account=? OR name=?', (username, username))]
    if member_ids:
        marks = ','.join('?' * len(member_ids))
        for r in dbq(f'SELECT DISTINCT node_id FROM org_appointments WHERE member_id IN ({marks})',
                     member_ids):
            node_ids.add(r['node_id'])
        if node_ids:
            return node_ids, 'org'
    # 回退：旧 workgroups 字段 → 映射到对应 org_nodes
    wg_by_name = {r['name']: r['id'] for r in dbq('SELECT id, name FROM workgroups')}
    node_by_wg = {n['wg_id']: n['id'] for n in nmap.values() if n.get('wg_id')}
    for r in dbq('SELECT workgroups FROM team_members WHERE account=? OR name=?', (username, username)):
        for nm in (r['workgroups'] or '').split(';'):
            nm = nm.strip()
            if not nm:
                continue
            nid = node_by_wg.get(wg_by_name.get(nm, 0))
            if nid:
                node_ids.add(nid)
    return node_ids, ('legacy' if node_ids else 'none')


def _member_dept_scope(username):
    """成员的归属部门范围（部门层级节点 id 集合）。

    **架构管理优先**：org_appointments（任命）为唯一权威源；
    该成员在架构管理里无任何任命时，才回退 team_members.workgroups（旧字段）。
    详见 _member_authority_nodes。
    """
    scope, _src = _member_authority_nodes(username)
    return scope


def _dept_stage_boards(username):
    """第一层过滤（归属部门）：成员可见的看板集合。

    规则（**fail-closed**：本层永远返回显式集合，不再用 None 兼表「全部」）：
      1) 成员**挂靠部门**的看板 —— 该部门拥有的看板对成员可见；
         ⚠️ **小组(group)不按父部门算**（2026-11-02 修复）：
            小组成员的可见范围 = 该小组**自己绑定**的看板，
            小组没绑定 = 没有。详见下方注释。
      2) 中心级归属的看板 —— 对全员展示（财务中心 = 管理层全范围）；
      3) 未归属部门的看板 —— 全员可见（对应目录树里的「未配置」节点）；
      4) 成员挂靠的是中心 → 管理层全范围（全部看板）；
      5) 成员**没有任何架构归属**（无任命、无工作组）→ 只能看公共看板，
         其余一律不可见 —— 无授权即不可见（此前这里返回 None ＝「不收窄」，
         与账号默认 allowed_boards='*' 叠加后，普通账号反而能看到全部看板）。
    """
    all_ids = _all_board_ids()
    owner = {}                          # board_id → 归属部门节点 id
    for r in dbq('SELECT board_id, dept_node_id FROM board_config'):
        owner[r['board_id']] = r['dept_node_id']
    centers = _center_node_ids()
    public = set()                      # 公共看板：未归属部门 / 归属中心
    for bid in all_ids:
        nid = owner.get(bid, 0)
        if not nid or nid in centers:
            public.add(bid)
    # ⚠️ **用「原始任命节点」而不是「向上提升后的部门」**（2026-11-02 修复）
    #
    # 此前 scope 来自 _member_authority_nodes()，它把**小组节点提升**到最近的
    # 部门祖先 → 小组（费用组/税务组）的成员被当成「核算部的成员」，
    # 继承了核算部拥有的**全部看板**。
    # 但小组既然**没有绑定任何看板**（workgroups.boards 为空），
    # 它的成员就**不该看到那些看板** —— 小组成员与部门成员的可见范围必须不同。
    #
    # 修正后的分节点类型语义（与 _node_bound_boards 完全一致）：
    #   · 任命到部门(dept)/中心(center) → 该节点**自己拥有**的看板；
    #   · 任命到小组(group)              → 该小组**自己绑定**的看板
    #     （workgroups.boards；没绑定 = 没有），**不继承父部门**。
    scope = _member_appointed_nodes(username)[0]
    if not scope:
        return public                   # 无架构归属 → 只能看公共看板
    nmap = _org_node_map()
    owned = _dept_owned_boards()
    wg_by_id = {r['id']: dict(r) for r in dbq('SELECT id, boards FROM workgroups')}
    # 挂靠中心 = 管理层全范围（中心层仍然优先）
    if any(nmap.get(nid, {}).get('node_type') == 'center' for nid in scope):
        return set(all_ids)
    visible = set(public)
    for nid in scope:
        node = nmap.get(nid)
        if not node:
            continue
        visible |= _node_bound_boards(node, owned, wg_by_id)
    return visible


def _group_boards(username: str):
    """第三层过滤（工作组绑定）：成员**所属节点自己**的显式看板绑定。

    返回 set(board_id) = 已配置白名单（按它**再收窄**）；
    返回 None = 未配置绑定（不收窄，跟随前两层的结果）。

    ⚠️ **不再沿父链向上收集**（2026-11-02 修复）：
       此前会沿 workgroups 父链一路向上收，导致
       「费用组成员」拿到「核算部」上绑的看板、「核算部成员」拿到「财务中心」旁的绑定。
       节点的绑定**只属于该节点自己** —— 与 _node_bound_boards 的分类型口径一致：
         · 部门/中心 → 该节点自己拥有的看板（归第一层 _dept_stage_boards 管）
         · 小组     → 该小组自己勾选的看板（workgroups.boards；没勾 = 没有）

    ⚠️ 与第一层（_dept_stage_boards）的分工（2026-11-02 澄清）：
       · 第一层：算「成员被任命到的节点**各自**拥有/绑定了哪些看板」→ 并集，**放大**；
         小组节点的绑定在这里就已经生效（_node_bound_boards）。
       · 本层：**账号级显式白名单**（收窄）——
         成员被任命到小组且该小组勾选了看板 → 该白名单把可见范围**限制**到这些看板。
       两者语义相反，不可混用；小组成员既能看到本组绑定的看板，
       又不会因为「同部门的其他人能看到更多」而越权。
    """
    if is_admin(username):
        return None
    # 架构管理优先：成员在架构管理里有任命时，用其**被任命到的节点**；
    # 否则回退旧 workgroups 字段。
    node_ids, _src = _member_appointed_nodes(username)
    merged = set()
    bound = False
    if node_ids:
        nmap = _org_node_map()
        wg_by_id = {r['id']: dict(r) for r in dbq('SELECT id, boards FROM workgroups')}
        for nid in node_ids:
            node = nmap.get(nid)
            if not node:
                continue
            # 只取**小组节点自己的**显式绑定（部门/中心的归属看板归第一层管）
            if node.get('node_type') != 'group':
                continue
            raw = (wg_by_id.get(node.get('wg_id') or 0, {}).get('boards') or '').strip()
            if raw == '*':
                return None  # 显式绑定全部 → 本层不收窄
            if raw:
                bound = True
                merged |= {x for x in raw.split(',') if x}
    else:
        # 回退：旧 workgroups 字段（只有旧字段、没有架构任命时）
        names, _src = _member_workgroup_names(username)
        all_rows = dbq('SELECT id, name, parent_id, boards FROM workgroups')
        by_name = {r['name']: r for r in all_rows}
        for nm in names:
            cur = by_name.get(nm)
            if not cur:
                continue
            b = (cur['boards'] or '').strip()
            if b == '*':
                return None
            if b:
                bound = True
                merged |= {x for x in b.split(',') if x}
    return merged if bound else None


def _arch_scope_boards(username: str, dept_boards: set) -> set:
    """架构授权集 = 归属部门层 ∪ 负责范围层，再按工作组绑定层收窄。"""
    boards = set(dept_boards)
    # ② 负责范围层：负责人额外拥有其负责范围（节点 + 全部后代）绑定的看板
    boards |= _leader_scope_boards(username)
    # ③ 工作组绑定层：显式白名单 → 收窄
    gb = _group_boards(username)
    if gb is not None:
        boards &= gb
    return boards

# ---------------- 负责人（owner）----------------
# ⚠️ **语义在 2026-11-02 修订过（原为 ACL「仅负责人可见」）：**
#
#   owner（负责人）= **看板 / 板块的管理权**，**不再收窄可见性**。
#     · 看板负责人 → 有权修改该看板的基本信息（归属部门 / 属性 / 状态 / 备注）
#     · 板块负责人 → 在【板块编辑】里配置，有权修改该板块基本信息
#   · **谁能看见某个看板** → 统一由【架构管理】的看板绑定决定
#     （部门归属 + 负责人负责范围 + 工作组绑定），与 owner 无关。
#   · **参与人（participants）机制整体下线** —— 权限来源收敛为单一出处，
#     避免出现「两套可见性规则互相打架」的历史包袱。
#
# ⚠️ 为什么 owner 存**账号**而不是姓名：账号是登录唯一标识，
#    姓名可能重复或被改。展示时由 _member_display_name 映射成「姓名(账号)」。
def board_owner(board_id: str) -> str:
    """看板负责人账号（无则空串）"""
    row = dbq('SELECT owner FROM boards WHERE board_id=? LIMIT 1', (board_id,))
    return (row[0]['owner'] or '').strip() if row else ''


def column_owner(col_key: str) -> str:
    """板块负责人账号（无则空串）"""
    row = dbq('SELECT owner FROM board_columns WHERE col_key=? LIMIT 1', (col_key,))
    return (row[0]['owner'] or '').strip() if row else ''


def is_board_manager(username: str, board_id: str) -> bool:
    """该账号是否可管理该看板的基本信息：管理员，或该看板的负责人"""
    if is_admin(username):
        return True
    o = board_owner(board_id)
    return bool(o) and o == username


def is_column_manager(username: str, col_key: str) -> bool:
    """该账号是否可管理该板块的基本信息：管理员，或该板块的负责人"""
    if is_admin(username):
        return True
    o = column_owner(col_key)
    return bool(o) and o == username


def _acl_set(raw) -> set:
    """（兼容保留）解析逗号/分号分隔的名单 → 集合。参与人机制已下线，仅供旧数据清理用。"""
    if not raw:
        return set()
    return {x.strip() for x in str(raw).replace(';', ',').split(',') if x.strip()}



# ---------------- 数据不变量：每板块至少一个事项 ----------------
# 用户 2026-11-02 要求：「每个板块至少保留一个事项，没有的就删除；
#   看板若无任何板块、或所有板块都被清理为空，则一并删除该看板。」
#
# 本函数在**删除事项之后**调用，保证不变量持续成立；
# 一次性全量清理由 ops/cleanup_empty.py 负责（幂等，可重复跑）。
def cleanup_empty_columns_and_boards() -> dict:
    """删除空板块与空看板（运行时调用，幂等）

    判定口径：事项按 **column_id** 匹配板块（column_id 是权威标识）；
    column_id 为空的历史脏数据不计入任何板块 —— 它们本就不属于任何板块，
    不应让空板块被误判为「非空」。

    ⚠️ 顺序不能颠倒：先删空板块，再据此判断哪些看板变成空看板。
    ⚠️ 「板块全被清理为空」的看板：若它还残留未删事项（板块外的孤儿事项），
       **不删看板** —— 那些事项会无处安放，删看板等于连带删数据。
    """
    dead_cols = [dict(r) for r in dbq("""
        SELECT bc.col_key, bc.board_id, bc.column_id FROM board_columns bc
        WHERE bc.column_id <> '' AND NOT EXISTS (
            SELECT 1 FROM cards cd WHERE cd.deleted = 0 AND cd.column_id = bc.column_id
        )
    """)]
    dead_by_board = {}
    for c in dead_cols:
        dead_by_board.setdefault(c['board_id'], set()).add(c['column_id'])

    deleted_cols = 0
    for c in dead_cols:
        dbe('DELETE FROM board_columns WHERE col_key=?', (c['col_key'],))
        deleted_cols += 1

    # 看板判定：剩余板块数为 0 且无未删事项 → 空看板
    dead_boards = []
    for r in dbq('SELECT board_id, board_name FROM boards'):
        bid = r['board_id']
        total = dbq('SELECT COUNT(*) n FROM board_columns WHERE board_id=?', (bid,))[0]['n']
        dead = len(dead_by_board.get(bid, set()))
        if total - dead > 0:
            continue                        # 还有存活板块 → 保留
        cards = dbq('SELECT COUNT(*) n FROM cards WHERE deleted=0 AND board_id=?', (bid,))[0]['n']
        if cards > 0:
            continue                        # 还有事项（板块外的孤儿）→ 保留看板
        dead_boards.append((bid, r['board_name']))

    deleted_boards = 0
    for bid, bname in dead_boards:
        dbe('DELETE FROM board_columns WHERE board_id=?', (bid,))
        dbe('DELETE FROM board_config WHERE board_id=?', (bid,))
        dbe('DELETE FROM boards WHERE board_id=?', (bid,))
        deleted_boards += 1

    return {'deleted_columns': deleted_cols, 'deleted_boards': deleted_boards}


def user_allowed(username: str):
    """返回 (boards, columns)：
    boards=None=全部看板，否则 set(board_id)（普通用户**永远**是显式集合）
    columns=None=全部板块，否则 dict {board_id: set(column_id)}（缺省=该看板全部板块）

    判定流程：
      ⓪ 超级管理员（role=admin，含内置 admin 账号）→ 直接返回 (None, None)，
         拥有当前及未来新增的全部权限，**不受架构权限过滤限制**；
      ① 架构授权集（fail-closed）—— 由 _arch_scope_boards() 汇总三层：
         · 归属部门层：挂靠部门拥有的看板（board_config.dept_node_id 派生）
         · 负责范围层：负责人额外拥有其负责范围（节点+后代）绑定的看板
         · 工作组绑定层：显式白名单收窄
         无任何架构归属的成员 → 只能看公共看板（未归属部门 / 归属中心）；
      ② 账号级白名单（users.allowed_boards）与①取交集 —— '*' 表示不额外收窄；
      ③ 板块级白名单（users.allowed_columns）在可见看板内继续收窄板块；
      ④ 负责人（owner）**不参与可见性判定**（2026-11-02 语义修订）——
         负责人 = 看板 / 板块的**管理权**（可改基本信息），不是可见性开关。
         谁能看见看板，完全由 ①~③ 决定；参与人（participants）机制已下线。

    【修复】此前普通用户的 boards 为 None（=全部）当且仅当「账号 allowed_boards='*'
    且架构层未收窄」，而架构层在「成员无归属」时返回 None（不收窄）→ 未接入架构的
    普通账号能看到**全部**看板与板块。现改为架构层永远返回显式集合（fail-closed）。
    """
    u = get_user(username)
    if not u:
        return set(), {}
    if is_admin(username):
        return None, None
    # ① 架构授权集
    dept_boards = _dept_stage_boards(username)
    boards = _arch_scope_boards(username, dept_boards)
    # ② 账号级看板白名单（与架构授权集取交集）
    raw_b = u.get('allowed_boards') or '*'
    if raw_b != '*':
        boards &= set(x for x in raw_b.split(',') if x)
    # ③ 账号级板块白名单（JSON: {board_id: [column_id]}）
    raw_c = u.get('allowed_columns') or '*'
    if raw_c == '*':
        cols = None
    else:
        try:
            cols = {k: set(v) for k, v in json.loads(raw_c).items() if v} or None
        except Exception:
            cols = None
    # ④ 负责人层（2026-11-02 语义修订）：**不再收窄可见性**。
    #    负责人 = 管理权（可改看板 / 板块基本信息），可见性完全由 ①~③ 决定。
    #    旧实现里 ACL 层会把「配了 owner/参与人」的看板对其他人藏起来，
    #    与【架构管理】的绑定规则互相打架 —— 现已移除该层。
    return boards, cols


def can_edit(username: str) -> bool:
    return user_role(username) in ('editor', 'admin') or username == SUPER_ADMIN


def is_admin(username: str) -> bool:
    """管理员判定：角色为 admin 即管理员（内置 admin 账号恒为管理员）。

    ★ 超级管理员语义：拥有当前及未来新增的**全部**权限，
      不受架构权限过滤限制（user_allowed 直接返回 None/None）。
      判定口径必须全局唯一 —— 此前 user_allowed 用「账号名 == 'admin'」、
      require_admin 用「角色 == 'admin'」，两套口径不一致，导致 role=admin 的
      账号（如 dsy）被架构层过滤，却又能调全部管理接口。
    """
    if username == SUPER_ADMIN:
        return True
    return user_role(username) == 'admin'


# 板块级写权限：**不再对特定板块开特例**。
# 写操作的准入统一由「账号角色（admin/editor/viewer）+ 板块归属 + 板块可见性」判定，
# 详见 user_allowed() 与各写接口里的 check_board_access / check_column_access。

def check_board_access(board_id: str, username: str):
    """写操作的看板准入校验（所有涉及 board_id 的写接口都要过这一关）。

    ① 看板对该用户**不可见** → 拒绝（【架构管理】的归属 + 工作组绑定决定可见范围）；
    ② 可见但角色无编辑权（viewer） → 拒绝。

    此前这条职责由「成本看板仅管理员」特例顺带兜底，特例移除后必须补上，
    否则看不见看板的人仍能直接调 API 改写该看板的卡片。
    """
    if not board_id:
        return
    boards, _cols = user_allowed(username)
    if boards is not None and board_id not in boards:
        raise HTTPException(403, '无权访问该看板')
    if not can_edit(username):
        raise HTTPException(403, '无编辑权限，请联系管理员')


def check_column_access(board_id: str, column_id: str, username: str):
    """板块级写准入校验：账号被限定了某看板的板块白名单时，
    不得把事项写入**不可见**的板块（板块权限 = 可见性约束）。"""
    if not (board_id and column_id):
        return
    if is_admin(username):
        return
    _boards, columns = user_allowed(username)
    if columns is None:
        return
    allowed = columns.get(board_id)
    if allowed is not None and column_id not in allowed:
        raise HTTPException(403, '无权操作该板块')


def check_card_access(card_id: str, username: str, need_edit: bool = False):
    """按卡片定位其看板，校验当前用户对该看板的可见性（读接口用）。

    读接口此前只有 require_auth，可见性完全依赖前端隐藏 → 直接调 API
    仍能读到不可见看板的卡片 / 评论 / 子事项（越权读）。这里统一兜住。
    """
    row = dbq('SELECT board_id, column_id FROM cards WHERE card_id=? AND deleted=0', (card_id,))
    if not row:
        raise HTTPException(404, '事项不存在')
    boards, columns = user_allowed(username)
    bid = row[0]['board_id']
    if boards is not None and bid not in boards:
        raise HTTPException(403, '无权访问该看板')
    if need_edit and not can_edit(username):
        raise HTTPException(403, '无编辑权限，请联系管理员')
    return dict(row[0])

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


def require_writer(username: str = Depends(require_auth)):
    """写操作的**粗闸门**：只要求「已登录」。

    ⚠️ **分级权限模型（2026-11-02）**：写权限的最终裁决权在 `perm_check()`，
    这里**不再**用 `viewer/editor` 粗粒度角色拦截 ——
    否则「参与人」「板块负责人」这类**细粒度身份**会在到达内核之前就被挡掉。

    理由：旧模型只有三档粗角色（viewer/editor/admin），新模型有六级细角色
    （参与人 / 事项负责人 / 板块负责人 / 看板负责人 / 架构负责人 / 管理员）。
    粗闸门与细角色并存时，**以细角色为准** —— 有身份的人放行，没身份的人由内核拒绝。

    ⚠️ `can_edit()` 仍保留给「非分级」的老接口（如资料页、公告）使用。
    """
    return username

# ---------------- 审计日志 ----------------
def client_ip(request: Request) -> str:
    # request 可能为 None（内部调用 / 测试直调函数时）→ 兜底返回空串，
    # 否则访问 request.headers 会抛 AttributeError，导致整个写接口 500
    if request is None:
        return ''
    fwd = request.headers.get('x-forwarded-for')
    if fwd:
        return fwd.split(',')[0].strip()
    return request.client.host if request.client else ''

def _login_attempt(username: str):
    """取某账号的登录失败状态；无记录返回默认（0 次、未锁定）。"""
    rows = dbq('SELECT * FROM login_attempts WHERE username=?', (username,))
    if not rows:
        return {'username': username, 'fail_count': 0, 'last_fail_ts': 0.0,
                'locked': 0, 'last_ip': ''}
    return dict(rows[0])

def _login_lock_state(username: str):
    """返回 (是否禁止登录, 剩余秒数, 提示文案)。

    规则：
      · 永久锁定（fail_count >= 10）→ 一直禁止，需 admin 重置
      · 失败 >= 5 次 → 冷却 180 秒，从最后一次失败起算
      · 其余 → 允许
    """
    st = _login_attempt(username)
    cnt = int(st.get('fail_count') or 0)
    if int(st.get('locked') or 0) or cnt >= LOGIN_LOCK_THRESHOLD:
        return True, 0, '密码错误次数过多，账号已锁定，请联系管理员重置密码'
    if cnt >= LOGIN_FAIL_THRESHOLD:
        last = float(st.get('last_fail_ts') or 0)
        elapsed = time.time() - last
        left = int(LOGIN_COOLDOWN - elapsed)
        if left > 0:
            return True, left, f'密码错误次数过多，请 {left} 秒后再试'
    return False, 0, ''

def _login_record_fail(username: str, ip: str):
    """记录一次登录失败，返回新的失败次数。"""
    st = _login_attempt(username)
    cnt = int(st.get('fail_count') or 0) + 1
    locked = 1 if cnt >= LOGIN_LOCK_THRESHOLD else int(st.get('locked') or 0)
    dbe("""INSERT INTO login_attempts (username, fail_count, last_fail_ts, locked, last_ip, updated_at)
             VALUES (?,?,?,?,?,datetime('now','localtime'))
             ON CONFLICT(username) DO UPDATE SET
               fail_count=excluded.fail_count, last_fail_ts=excluded.last_fail_ts,
               locked=excluded.locked, last_ip=excluded.last_ip,
               updated_at=excluded.updated_at""",
        (username, cnt, time.time(), locked, ip or ''))
    return cnt

def _login_record_success(username: str):
    """登录成功 → 清零失败计数（但不清除永久锁定）。"""
    dbe('DELETE FROM login_attempts WHERE username=?', (username,))

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

# ---------------- 板块（看板内的分组，如「成本组（第1周）」）----------------
# 板块此前只隐含在 cards.column_name 中，没有独立记录，导致「创建日期 / 性质 /
# 置顶」无处存放。board_columns 表承载这些元信息。
# 业务主键 col_key = board_id + '::' + column_name：
#   column_id 在同一看板内唯一，但历史数据存在 column_id 为空的分组，
#   用组合键更稳妥，也不会因 column_id 缺失而无法定位板块。
COLUMN_NATURES = {'日常', '专项'}
# 板块「完成情况」取值（2026-11-04 需求3）——与事项 status 同一套语义
# open=未完成 / progressing=进行中 / done=已完成
COLUMN_COMPLETIONS = ('open', 'progressing', 'done')


def col_key(board_id, column_name):
    return '%s::%s' % (board_id or '', column_name or '')


def _ts(v):
    """把 'YYYY-MM-DD' 或 'YYYY-MM-DD HH:MM:SS' 归一成可比较的时间戳（越大越新）"""
    s = (v or '').strip()
    if not s:
        return 0.0
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d'):
        try:
            return time.mktime(time.strptime(s[:19] if fmt != '%Y-%m-%d' else s[:10], fmt))
        except ValueError:
            continue
    return 0.0


def ensure_column(board_id, column_name, column_id='', creator='', created_at=''):
    """确保板块元信息存在；不存在则按默认值建一条（幂等）

    先按 (board_id, column_id) 找已登记的板块 —— 命中就直接复用，
    避免同一个板块被登记成两行（col_key 不一致 → 后续改名 / 置顶会对不上）。
    """
    if not (board_id and column_name):
        return None
    if column_id:
        row = dbq('SELECT col_key FROM board_columns WHERE board_id=? AND column_id=? LIMIT 1',
                  (board_id, column_id))
        if row:
            return row[0]['col_key']
    key = col_key(board_id, column_name)
    if dbq('SELECT col_key FROM board_columns WHERE col_key=?', (key,)):
        return key
    cid = column_id or ('COL' + str(int(time.time() * 1000)))
    ca = created_at or time.strftime('%Y-%m-%d %H:%M:%S')
    dbe('INSERT OR IGNORE INTO board_columns (col_key, column_id, board_id, column_name, created_at, creator, nature, year, pinned)'
        ' VALUES (?,?,?,?,?,?,?,?,0)',
        (key, cid, board_id, column_name, ca, creator or '', '日常', (ca or '')[:4]))
    return key


def visible_columns(username, boards, columns, board_id=None, counts=None, board_ids=None):
    """列出当前用户可见的板块元信息（按置顶优先、创建时间降序）

    counts: {col_key: (总数, 已完成数)}，用于板块进度条
    """
    rows = dbq('SELECT * FROM board_columns')
    out = []
    for r in rows:
        d = dict(r)
        if boards is not None and d['board_id'] not in boards:
            continue
        if board_id and d['board_id'] != board_id:
            continue
        if board_ids and d['board_id'] not in board_ids:
            continue
        # 板块级权限：用户被限定在某几个 column_id 时，看板内未授权的板块不展示
        if columns is not None:
            allowed = columns.get(d['board_id'])
            if allowed is not None and d['column_id'] not in allowed:
                continue
        n, dn = (counts or {}).get(d['col_key'], (0, 0))
        d['card_count'] = n
        d['done_count'] = dn
        d['pinned'] = int(d.get('pinned') or 0)
        out.append(d)
    # 排序：置顶优先；置顶项内部与普通项各自按创建时间降序
    out.sort(key=lambda d: (0 if d['pinned'] else 1, -_ts(d.get('created_at')), d['column_name']))
    return out

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
def _ws_message_boards(msg: dict):
    """取出实时消息涉及的看板 id 集合；定位不到时返回 None（= 不按看板过滤）。"""
    bid = msg.get('board_id')
    if bid:
        return {bid}
    cid = msg.get('card_id')
    if cid and cid != '*':
        row = dbq('SELECT board_id FROM cards WHERE card_id=?', (cid,))
        if row:
            return {row[0]['board_id']}
    return None


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
        """推送给所有在线连接（可选排除某用户）。

        可见性：消息能定位到看板时，只推送给**能看到该看板**的账号 ——
        否则不可见看板的卡片 id 会通过实时通道泄漏给无权用户。
        定位不到看板（如 card_id='*' 的全局刷新信号）时照常广播。
        """
        dead = []
        boards = _ws_message_boards(msg)
        vis_cache = {}
        for username, sockets in list(self.conns.items()):
            if exclude and username == exclude:
                continue
            if boards is not None:
                if username not in vis_cache:
                    vis, _c = user_allowed(username)
                    vis_cache[username] = vis
                vis = vis_cache[username]
                if vis is not None and not (boards & vis):
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
    st = _login_attempt(req.username)
    cnt = int(st.get('fail_count') or 0)
    # 永久锁定（失败 >= 10 次）：任何密码都不放行，需管理员重置
    if int(st.get('locked') or 0) or cnt >= LOGIN_LOCK_THRESHOLD:
        tip = '密码错误次数过多，账号已锁定，请联系管理员重置密码'
        audit_log(req.username, ip, 'login', '账号登录', f'登录被拒：{tip}', 'denied')
        raise HTTPException(423, tip)

    u = get_user(req.username)
    pwd_ok = bool(u) and verify_pw(req.password, u['password_hash'])

    if pwd_ok:
        # 密码正确：即使处于冷却期也放行（受限的是「密码错误」，不是「登录」），并清零计数
        _login_record_success(req.username)
        audit_log(req.username, ip, 'login', '账号登录', f'登录成功（角色：{u["role"]}）', 'success')
        return {'token': make_token(req.username), 'username': req.username,
                'role': u['role']}

    # 密码错误：累加失败次数
    cnt = _login_record_fail(req.username, ip)
    if cnt >= LOGIN_LOCK_THRESHOLD:
        detail = (f'登录失败：账号或密码错误（已连续失败 {cnt} 次，'
                   f'账号已锁定，需管理员重置密码）')
        audit_log(req.username, ip, 'login', '账号登录', detail, 'failed')
        raise HTTPException(423, '密码错误次数过多，账号已锁定，请联系管理员重置密码')
    if cnt >= LOGIN_FAIL_THRESHOLD:
        # 进入冷却：本次失败时间重新起算冷却窗口
        detail = (f'登录失败：账号或密码错误（已连续失败 {cnt} 次，'
                   f'请 {LOGIN_COOLDOWN} 秒后再试）')
        audit_log(req.username, ip, 'login', '账号登录', detail, 'failed')
        raise HTTPException(429, f'密码错误次数过多，请 {LOGIN_COOLDOWN} 秒后再试',
                            headers={'Retry-After': str(LOGIN_COOLDOWN)})
    detail = f'登录失败：账号或密码错误（已连续失败 {cnt} 次）'
    audit_log(req.username, ip, 'login', '账号登录', detail, 'failed')
    raise HTTPException(401, '账号或密码错误')


@app.get('/api/login/lock-status')
def login_lock_status(username: str = ''):
    """登录前查询账号的锁定状态（供登录页提示剩余冷却时间）。"""
    if not username:
        return {'blocked': False, 'retry_after': 0, 'message': ''}
    blocked, left, tip = _login_lock_state(username)
    return {'blocked': blocked, 'retry_after': left, 'message': tip}


class LoginLockResetReq(BaseModel):
    username: str = ''


@app.get('/api/admin/login-locks')
def list_login_locks(username: str = Depends(require_admin)):
    """管理员查看登录锁定列表。"""
    rows = dbq("""SELECT username, fail_count, last_fail_ts, locked, last_ip, updated_at
                    FROM login_attempts ORDER BY fail_count DESC, updated_at DESC""")
    now = time.time()
    out = []
    for r in rows:
        d = dict(r)
        cnt = int(d.get('fail_count') or 0)
        left = 0
        if not int(d.get('locked') or 0) and cnt >= LOGIN_FAIL_THRESHOLD:
            left = max(0, int(LOGIN_COOLDOWN - (now - float(d.get('last_fail_ts') or 0))))
        d['retry_after'] = left
        d['locked'] = bool(int(d.get('locked') or 0)) or cnt >= LOGIN_LOCK_THRESHOLD
        out.append(d)
    return {'locks': out, 'thresholds': {'fail': LOGIN_FAIL_THRESHOLD,
                                         'cooldown': LOGIN_COOLDOWN,
                                         'lock': LOGIN_LOCK_THRESHOLD}}


@app.post('/api/admin/login-lock/reset')
def reset_login_lock(req: LoginLockResetReq, username: str = Depends(require_admin),
                     request: Request = None):
    """管理员重置账号的登录失败计数 / 解除锁定。"""
    target = (req.username or '').strip()
    if not target:
        raise HTTPException(400, '请指定账号')
    dbe('DELETE FROM login_attempts WHERE username=?', (target,))
    audit_log(username, client_ip(request), 'login_lock_reset', target,
              f'管理员重置登录锁定状态：{target}', 'success')
    return {'ok': True, 'username': target}

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
    dept_map = {r['board_id']: (r['dept'], r['dept_node_id'])
                for r in dbq('SELECT board_id, dept, dept_node_id FROM board_config')}
    # 人员选择层级约束（2026-11-04）：板块弹窗的选人池 = **所属看板**的负责人与参与人
    # → /api/me 每看板下发 owner / participants（boards 表字段，_all_boards 不查这两列）
    _acl_map = {r['board_id']: (r['owner'] or '', r['participants'] or '')
                for r in dbq('SELECT board_id, owner, participants FROM boards')}
    boards_out = []
    for b in allb:
        item = dict(b)
        dn, dnode = dept_map.get(b['board_id'], ('', 0))
        item['dept'] = dn
        item['dept_node_id'] = dnode or 0
        item['owner'], item['participants'] = _acl_map.get(b['board_id'], ('', ''))
        # 板块弹窗的负责人/参与人指派门槛（2026-11-04）：与后端写接口**同一判定**，
        # 前端不再手写 is_admin（#43 同款问题的教训）。
        #   can_edit          → 可指派板块参与人（板块负责人及以上，看板/架构负责人继承）
        #   can_assign_owner  → 可指派板块负责人（架构负责人及以上）
        _chain = perm_chain(board_id=b['board_id'])
        item['can_edit'] = perm_check_pass(username, _chain, OP_UPDATE, LV_BOARD_OWNER)
        item['can_assign_owner'] = perm_check_pass(username, _chain, OP_ASSIGN_OWNER, LV_BOARD_OWNER,
                                                   min_level=LV_ARCH_OWNER)
        boards_out.append(item)
    # 板块级权限信息（供前端配置/展示）
    col_info = None
    if columns is not None:
        col_info = {bid: sorted(cols) for bid, cols in columns.items()}
    # 个人资料（头像 / 个人照片 / 个人状态）—— 顶栏状态栏与个人界面使用
    prof = dbq('SELECT avatar, photo, status_text FROM users WHERE username=?', (username,))
    avatar = prof[0]['avatar'] if prof else ''
    photo = prof[0]['photo'] if prof else ''
    status_text = prof[0]['status_text'] if prof else ''
    # 显示名：顶栏展示「姓名(账号)」；账号未绑定成员时只显示账号
    display_name = _member_display_name(username)
    # 部门清单：**按权限过滤** —— 只保留该账号**有可见看板**的部门。
    # ⚠️ 此前用 _dept_order()（架构里的全部部门）→ 普通用户的目录树会列出
    #    自己无权访问的部门（如「管理部 0」），既暴露无权部门的组织信息，
    #    又让用户以为那里真的有事但点进去是空的。
    #    语义与 /api/cards 的可见范围保持一致：**看不到的部门就不出现**。
    #    管理员（boards=None=全部）仍看到全部部门。
    if boards is None:
        dept_list = _dept_order()
    else:
        seen = {item.get('dept') for item in boards_out if item.get('dept')}
        dept_list = [d for d in _dept_order() if d in seen]
    # 我管理的看板 / 板块（2026-11-02 负责人语义）：
    #   负责人 = 管理权（可改该看板 / 板块的基本信息），不代表可见性。
    #   前端据此决定「看板管理」入口是否显示给非管理员。
    managed_boards = [r['board_id'] for r in
                      dbq('SELECT board_id FROM boards WHERE owner=? AND owner<>?', (username, ''))]
    managed_columns = [r['col_key'] for r in
                       dbq('SELECT col_key FROM board_columns WHERE owner=? AND owner<>?', (username, ''))]
    # 权限画像（2026-11-03）：前端据此**动态渲染可配置范围**。
    # ⚠️ 判定口径全部来自 perm.py（effective_level），前端不做二次推断。
    arch_scope = sorted(_arch_scope_nodes(dbq, username))       # 我管辖的架构节点（含后代）
    leader_nodes = sorted(_arch_leader_nodes(dbq, username))    # 我担任负责人的节点
    # 可配置的看板（2026-11-03）：入口渲染需要这个数字，
    # ⚠️ **不能在前端数** —— 前端的看板列表要等打开看板管理才加载，首屏为空会误判成「无权限」。
    editable_boards = []
    if not is_admin(username):
        for b in dbq('SELECT board_id FROM boards'):
            if perm_check_pass(username, perm_chain(board_id=b['board_id']),
                               OP_UPDATE, LV_BOARD_OWNER):
                editable_boards.append(b['board_id'])
    return {'username': username, 'display_name': display_name, 'boards': boards_out, 'role': user_role(username),
            'can_edit': can_edit(username), 'is_admin': is_admin(username),
            'avatar': avatar, 'photo': photo, 'status_text': status_text,
            'allowed_columns': col_info,
            'managed_boards': managed_boards,      # 我是负责人的看板
            'managed_columns': managed_columns,    # 我是负责人的板块
            # ↓↓↓ 权限画像（新增）
            'arch_scope': arch_scope,              # 我管辖的架构节点 id（含后代）
            'arch_leader_nodes': leader_nodes,     # 我担任负责人的节点 id
            'is_arch_owner': bool(leader_nodes),   # 是否架构负责人
            'editable_boards': editable_boards,    # 我能配置基本信息的看板（管理员=全部，前端不依赖列表加载时机）
            'depts': dept_list}   # 有序部门清单（**按权限过滤**：只含有可见看板的部门）

@app.get('/api/filter-options')
def filter_options(username: str = Depends(require_auth)):
    """筛选栏候选项：人员（负责人）名单 + 周数名单。

    · 人员候选 = **当前账号可见范围内**的事项里出现过的负责人姓名（去重、排序）。
      越权事项的负责人不会出现在这里 —— 筛选项本身也遵守权限过滤。
    · 周数候选 = 同理，取可见范围内出现过的 week_no。
    · 两者都作为「可输入下拉」的候选：前端允许手工输入任意文本，
      输入的内容按同样的语义参与过滤（找不到就查不到结果）。
    """
    boards, columns = user_allowed(username)
    # ⚠️ 必须带 board_id / column_id —— perm_pass() 要用它们做两级过滤，
    #    只 SELECT owner/week_no 会抛 KeyError（非管理员调用时 500）。
    rows = filter_rows(dbq('SELECT owner, week_no, board_id, column_id FROM cards WHERE deleted=0'),
                       boards, columns)
    people, weeks = set(), set()
    for r in rows:
        for n in (r.get('owner') or '').split(';'):
            n = n.strip()
            if n:
                people.add(n)
        w = (r.get('week_no') or '').strip()
        if w:
            weeks.add(w)
    return {'people': sorted(people), 'weeks': sorted(weeks, key=week_sort_key)}


@app.get('/api/overview')
def overview(board_id: Optional[str] = None, board_ids: Optional[str] = None,
             username: str = Depends(require_auth)):
    boards, columns = user_allowed(username)
    rows = filter_rows(dbq("SELECT board_id, board_name, status, owner, column_id FROM cards WHERE deleted=0 AND parent_id=''"), boards, columns)
    # 按板块过滤统计：前端切换板块时带 board_id → 统计带只反映当前板块，
    # 否则会出现「切到别的板块、数字却还是上一个板块的」。
    # ⚠️ board_id 为空串 = 不按板块过滤（全局统计），保持既有语义。
    # 多看板（2026-11-04）：board_ids 逗号分隔 → 统计带反映多选看板的合计。
    if board_ids and not board_id:
        _bset = {x.strip() for x in board_ids.split(',') if x.strip()}
        if _bset:
            rows = [r for r in rows if r['board_id'] in _bset]
    elif board_id:
        rows = [r for r in rows if r['board_id'] == board_id]
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

def _status_text(st):
    """状态 → 中文文案（与前端 statusText 同口径）"""
    return '已完成' if st == 'done' else ('进行中' if st == 'progressing' else '未完成')


def _completion_text(st):
    """板块完成情况 → 中文文案（与事项 status 同一套语义）"""
    return '已完成' if st == 'done' else ('进行中' if st == 'progressing' else '未完成')


def _filter_cards_for_user(username, boards, columns, *, board_id=None, board_ids=None,
                            status=None, owner=None, column=None, q=None,
                            created_start=None, created_end=None, cc=None, week=None,
                            person=None, years=None, card_id=None, parent_id=None,
                            level='top', board_set=None):
    """按用户可见范围 + 页面筛选条件过滤事项（**列表与导出共用**）

    返回 (mine, week_options, col_hit_keys)：
      mine         —— 过滤后的事项行（dict 列表）
      week_options —— 当前范围内出现过的周数集合（按 年*100+周号 排序）
      col_hit_keys —— 搜索命中板块的 col_key 集合

    ⚠️ 参数与 /api/cards 的查询参数**一一对应**，保证「页面筛选 → 导出结果」一致。
    """
    # 创建日期区间：条件下推到 SQL（substr 取日期部分，带时分秒也能正确比较）
    cf = _norm_date(created_start)
    ct = _norm_date(created_end)
    if cf and ct and cf > ct:
        cf, ct = ct, cf          # 起止颠倒时自动纠正
    if cf or ct:
        w, p = ['deleted=0'], []
        if cf:
            w.append('substr(created,1,10) >= ?')
            p.append(cf)
        if ct:
            w.append('substr(created,1,10) <= ?')
            p.append(ct)
        pool = [dict(r) for r in dbq('SELECT * FROM cards WHERE ' + ' AND '.join(w), p)]
    else:
        pool = [dict(r) for r in dbq('SELECT * FROM cards WHERE deleted=0')]
    mine = filter_rows(pool, boards, columns)
    # 层级过滤：card_id 精确查询不受层级限制；parent_id → 该父项的子事项；
    # level='top' → 只看顶层；level='all' → 全部层级（导出用）
    if card_id:
        mine = [r for r in mine if r['card_id'] == card_id]
    elif parent_id:
        mine = [r for r in mine if r.get('parent_id') == parent_id]
    elif level == 'top':
        mine = [r for r in mine if not r.get('parent_id')]
    # 看板维度
    if board_set is not None:
        mine = [r for r in mine if r['board_id'] in board_set]
    elif board_id:
        mine = [r for r in mine if r['board_id'] == board_id]
    elif board_ids:
        _bset = {x.strip() for x in board_ids.split(',') if x.strip()}
        if _bset:
            mine = [r for r in mine if r['board_id'] in _bset]
    # 归属年份（绑定在板块层）—— 在一切统计之前生效
    if years:
        yset = {y.strip() for y in years.split(',') if y.strip()}
        if yset:
            if board_id:
                _yrows = dbq('SELECT column_name, year FROM board_columns WHERE board_id=?',
                             (board_id,))
                _ymap = {(board_id, r['column_name']): (r['year'] or '') for r in _yrows}
            else:
                _yrows = dbq('SELECT board_id, column_name, year FROM board_columns')
                _ymap = {(r['board_id'], r['column_name']): (r['year'] or '') for r in _yrows}
            mine = [r for r in mine
                    if _ymap.get((r['board_id'], r.get('column_name') or ''), '') in yset]
    # 状态多选（逗号分隔 = 任一命中）；open = 未完成（非 done 且非 progressing）
    if status:
        _sset = {x.strip() for x in status.split(',') if x.strip()}
        if _sset:
            def _status_hit(r):
                st = r['status']
                if 'done' in _sset and st == 'done':
                    return True
                if 'progressing' in _sset and st == 'progressing':
                    return True
                if 'open' in _sset and st != 'done' and st != 'progressing':
                    return True
                return False
            mine = [r for r in mine if _status_hit(r)]
    if owner == OWNER_NONE:
        mine = [r for r in mine if not (r.get('owner') or '').strip()]
    elif owner:
        onames = [x.strip() for x in owner.split(',') if x.strip()]
        if len(onames) > 1:
            mine = [r for r in mine
                    if any(nm in (r.get('owner') or '') for nm in onames)]
        else:
            mine = [r for r in mine if owner in (r.get('owner') or '')]
    if cc:
        cnames = [x.strip() for x in cc.split(',') if x.strip()]
        if cnames:
            mine = [r for r in mine
                    if any(nm in (r.get('cc') or '') for nm in cnames)]
    if person:
        pnames = [x.strip() for x in person.split(',') if x.strip()]
        if pnames:
            want_none = OWNER_NONE in pnames
            real = [p for p in pnames if p != OWNER_NONE]
            def _person_hit(r):
                o = r.get('owner') or ''
                if want_none and not o.strip():
                    return True
                return any(nm in o for nm in real)
            if want_none or real:
                mine = [r for r in mine if _person_hit(r)]
    if column:
        mine = [r for r in mine if (r.get('column_name') or '') == column]
    # 周数维度：可选周数在**应用周数筛选之前**统计 → 勾选某周后其余周仍可选
    week_options = sorted({(r.get('week_no') or '').strip()
                           for r in mine if (r.get('week_no') or '').strip()},
                          key=week_sort_key)
    if week:
        wset = {x.strip() for x in week.split(',') if x.strip()}
        if wset:
            mine = [r for r in mine if (r.get('week_no') or '').strip() in wset]
    # 搜索：同时命中「事项」（名称/描述）与「板块」（板块名）
    col_hit_keys = set()
    if q:
        ql = q.lower()
        for r in mine:
            cn = (r.get('column_name') or '')
            if cn and ql in cn.lower():
                col_hit_keys.add(col_key(r['board_id'], cn))
        card_hit = set()
        for r in mine:
            if (ql in (r.get('card_name') or '').lower()
                    or ql in (r.get('description') or '').lower()):
                card_hit.add(r['card_id'])
        mine = [r for r in mine
                if col_key(r['board_id'], r.get('column_name') or '') in col_hit_keys
                or r['card_id'] in card_hit]
        for r in mine:
            r['match_type'] = ('column'
                               if col_key(r['board_id'], r.get('column_name') or '') in col_hit_keys
                               else 'card')
    return mine, week_options, col_hit_keys


@app.get('/api/cards')
def cards(board_id: Optional[str] = None, status: Optional[str] = None,
          owner: Optional[str] = None, column: Optional[str] = None,
          q: Optional[str] = None, page: int = 1, size: int = 50,
          parent_id: Optional[str] = None, card_id: Optional[str] = None,
          created_start: Optional[str] = None, created_end: Optional[str] = None,
          cc: Optional[str] = None, week: Optional[str] = None,
          person: Optional[str] = None, years: Optional[str] = None,
          board_ids: Optional[str] = None,
          username: str = Depends(require_auth), request: Request = None):
    if card_id:
        audit_log(username, client_ip(request), 'view', f'卡片 {card_id}', '查看卡片详情', 'success')
    boards, columns = user_allowed(username)
    # 全量行：子事项计数（sub_count）必须看到所有卡片，不能被筛选条件裁剪
    all_rows = [dict(r) for r in dbq('SELECT * FROM cards WHERE deleted=0')]
    # 子事项计数（全量统计 parent 指向）
    sub_count = defaultdict(int)
    # 注意：父事项与子事项的负责人**各自独立存储**，不做任何关联或继承，
    # 因此这里不汇总子事项负责人（此前 sub_owners 汇总会让父事项行
    # 显示子事项的责任人，违背「父事项负责人单独设置」的语义，已移除）
    for r in all_rows:
        if r.get('parent_id'):
            sub_count[r['parent_id']] += 1
    # ★ 过滤逻辑抽到 _filter_cards_for_user —— /api/export/xlsx 共用同一套，
    #   保证「页面筛选条件对导出结果生效」（2026-11-04 需求5）
    mine, week_options, col_hit_keys = _filter_cards_for_user(
        username, boards, columns,
        board_id=board_id, board_ids=board_ids, status=status, owner=owner,
        column=column, q=q, created_start=created_start, created_end=created_end,
        cc=cc, week=week, person=person, years=years,
        card_id=card_id, parent_id=parent_id, level='top')
    total = len(mine)
    # 板块元信息 + 进度统计：基于**全量**过滤结果，不受分页影响，
    # 否则板块进度条上的「已完成/总数」会与实际列出的事项对不上
    ccnt, dcnt = defaultdict(int), defaultdict(int)
    for r in mine:
        k = col_key(r['board_id'], r['column_name'])
        ccnt[k] += 1
        if r['status'] == 'done':
            dcnt[k] += 1
    counts = {k: (ccnt[k], dcnt[k]) for k in ccnt}
    _vc_ids = None
    if not board_id and board_ids:
        _vc_ids = {x.strip() for x in board_ids.split(',') if x.strip()}
    cols_meta = visible_columns(username, boards, columns, board_id, counts, board_ids=_vc_ids)
    if column:
        cols_meta = [c for c in cols_meta if c['column_name'] == column]
    # 板块命中清单（供前端把该板块的事项归到一起展示）
    col_hits = [c for c in cols_meta if c['col_key'] in col_hit_keys] if q else []
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
    return {'total': total, 'page': page, 'size': size, 'cards': out,
            'columns': cols_meta, 'column_hits': col_hits, 'q': q,
            'weeks': week_options}

# ---------------- API：板块（新建 / 编辑 / 置顶）----------------
class ColumnCreate(BaseModel):
    board_id: str
    column_name: str
    created_at: str = ''     # 创建日期（必填，允许 YYYY-MM-DD 或含时分秒）
    nature: str = '日常'      # 性质：日常 / 专项
    year: str = ''           # 归属年份（如 2026）
    # 板块参与人（2026-11-03）：账号列表（逗号分隔）。
    # 参与人 = 可修改该板块的**可见内容**，但无增删与指派权（见 perm.py）。
    participants: str = ''
    # 板块负责人（2026-11-04）：指定权 = 架构负责人及以上（与编辑板块同口径）。
    owner: str = ''
    # 板块「完成情况」（2026-11-04 需求3）：open / progressing / done
    # ⚠️ 与进度条（done/total 自动统计）**互不冲突**：
    #    进度条是统计口径，本字段是**板块负责人对整体完成度的声明**。
    completion: str = 'open'


class ColumnUpdate(BaseModel):
    col_key: str             # 原 col_key（定位板块用）
    board_id: str = ''       # 所属看板（板块尚未登记时用于定位）
    column_name: str = ''    # 新名称
    created_at: str = ''     # 创建日期
    nature: str = ''         # 性质
    year: str = ''           # 归属年份
    owner: str = ''          # 板块负责人账号（'' = 不改；'__CLEAR__' = 清除）
    # 板块「完成情况」（2026-11-04 需求3）：open / progressing / done
    # None = 不改；非 None = 覆盖。
    # ⚠️ 只有**该板块负责人本人或管理员**能改（其他成员提交会被 403 拒绝）。
    completion: Optional[str] = None
    # 板块参与人（2026-11-03）：账号列表。
    # ⚠️ 语义与 owner 不同：**None = 不改**（不传该字段）；
    #    传空串 = 清空参与人；传列表 = 覆盖。
    participants: str = None
    # ⚠️ owner 语义（2026-11-02）：板块负责人 = 该板块的**管理权**，
    #    在【板块编辑】弹窗里配置；不影响板块可见性（可见性由架构绑定决定）。
    #    仅管理员可改负责人本身；板块负责人（editor）改其他字段不受此限。


class ColumnPinReq(BaseModel):
    col_key: str
    pinned: bool = False


def _norm_year(v):
    """归属年份：留空允许（历史板块），非空必须是 4 位数字"""
    y = (v or '').strip()
    if y and not re.match(r'^\d{4}$', y):
        raise HTTPException(400, '归属年份应为 4 位数字，如 2026')
    return y


class PinReq(BaseModel):
    """事项置顶请求（板块置顶另用 ColumnPinReq，需要带 col_key）"""
    pinned: bool = False


@app.post('/api/columns')
async def create_column(req: ColumnCreate, username: str = Depends(require_writer), request: Request = None):
    """新建板块：创建日期必填（默认当天），创建人取当前登录用户（前端锁定，服务端也强制）

    ⚠️ **归属年份在板块层绑定，且是单值必填**（年份已从看板层下沉到这里）：
    每个板块绑定唯一归属年份；未填时默认取创建年份。
    """
    name = (req.column_name or '').strip()
    if not name:
        raise HTTPException(400, '板块名称不能为空')
    if not req.board_id:
        raise HTTPException(400, '请选择所属看板')
    if req.nature not in COLUMN_NATURES:
        raise HTTPException(400, '性质只能是「日常」或「专项」')
    created = (req.created_at or '').strip()
    if not created:
        # 创建日期为必填项：前端日期选择器已默认预填当天，服务端同样强制校验，
        # 避免绕过前端直接调接口时产生无日期的板块
        raise HTTPException(400, '创建日期为必填项')
    if not re.match(r'^\d{4}-\d{2}-\d{2}', created):
        raise HTTPException(400, '创建日期格式应为 YYYY-MM-DD')
    if not dbq('SELECT board_id FROM boards WHERE board_id=?', (req.board_id,)):
        raise HTTPException(404, '所属看板不存在')
    # 分级权限（2026-11-02）：新增板块 = 看板负责人及以上（架构负责人继承）
    # ⚠️ **权限内核先于可见性校验**（与 update_card 同款理由）：
    #    可见性 403 会掩盖分级权限的真实原因，错误体就不统一了。
    perm_check(username, perm_chain(board_id=req.board_id), OP_CREATE, LV_BOARD_OWNER,
               'board:' + req.board_id, min_level=LV_BOARD_OWNER)
    # 看板必须存在且对当前用户可见
    boards, _cols = user_allowed(username)
    if boards is not None and req.board_id not in boards:
        raise HTTPException(403, '无权在该看板下新建板块')
    key = col_key(req.board_id, name)
    if dbq('SELECT col_key FROM board_columns WHERE col_key=?', (key,)):
        raise HTTPException(409, '该看板下已存在同名板块')
    year = _norm_year(req.year) or created[:4]   # 归属年份：单值必填，未填默认取创建年份
    # 板块负责人（2026-11-04）：指定权 = **架构负责人及以上**；未传 = 不指定
    new_owner = ''
    if (req.owner or '').strip():
        perm_check(username, perm_chain(board_id=req.board_id), OP_ASSIGN_OWNER, LV_BOARD_OWNER,
                   'board:' + req.board_id, min_level=LV_ARCH_OWNER)
        new_owner = _norm_acl_owner(req.owner)
    # ⚠️ 参与人此前**模型有字段但 create 没落库**（静默丢弃）—— 一并补上
    parts = _norm_acl_participants(req.participants) if (req.participants or '').strip() else ''
    new_cid = 'COL' + str(int(time.time() * 1000))
    # 新建板块的完成情况（2026-11-04 需求3）：创建者声明，默认未完成
    new_completion = (req.completion or '').strip() or 'open'
    if new_completion not in COLUMN_COMPLETIONS:
        raise HTTPException(400, '完成情况只能是「未完成」「进行中」或「已完成」')
    dbe('INSERT INTO board_columns (col_key, column_id, board_id, column_name, created_at, creator, nature, year, pinned, owner, participants, completion)'
        ' VALUES (?,?,?,?,?,?,?,?,0,?,?,?)',
        (key, new_cid, req.board_id, name, created, username, req.nature, year, new_owner, parts, new_completion))
    log_action('__column__', username, 'create', f'新建板块 {name}')
    audit_log(username, client_ip(request), 'create', f'板块 {name}',
              f'新建板块：{name}（看板 {req.board_id}，性质 {req.nature}，归属年份 {year}，创建日期 {created}）', 'success')
    await ws_mgr.broadcast({'type': 'card_update', 'card_id': '*', 'by': username})
    return {'ok': True, 'col_key': key, 'column_id': new_cid, 'column_name': name,
            'created_at': created, 'creator': username, 'nature': req.nature,
            'year': year, 'pinned': 0, 'owner': new_owner, 'participants': parts}


@app.put('/api/columns')
async def update_column(req: ColumnUpdate, username: str = Depends(require_writer), request: Request = None):
    """编辑板块：名称 / 归属年份 / 创建日期 / 性质。

    板块尚未登记（历史数据没有 board_columns 行）时按「登记」处理，补一条元信息。
    改名会同步该看板下该板块所有事项的 column_name —— col_key = board_id::column_name，
    改名等于换 key，事项的 column_name 不跟着改就会掉出板块。
    """
    row = dbq('SELECT * FROM board_columns WHERE col_key=?', (req.col_key,))
    old = dict(row[0]) if row else None
    if old:
        board_id = old['board_id']
        old_name = old['column_name']
    else:
        board_id = (req.board_id or '').strip()
        old_name = ''
        if not board_id:
            raise HTTPException(400, '板块不存在，且未指定所属看板')
    name = (req.column_name or '').strip() or old_name
    if not name:
        raise HTTPException(400, '板块名称不能为空')
    # 分级权限（2026-11-02）：修改板块 = 板块负责人及以上（看板/架构负责人继承）
    # ⚠️ 权限内核先于可见性校验（原因见 update_card 的同款说明）
    perm_check(username, perm_chain(board_id=board_id, column_id=(old['column_id'] if old else '')),
               OP_UPDATE, LV_COLUMN_OWNER, 'column:' + (req.col_key or ''))
    # 权限：看板可见性校验
    boards, _cols = user_allowed(username)
    if boards is not None and board_id not in boards:
        raise HTTPException(403, '无权编辑该板块')
    # 负责人字段（2026-11-04 修订）：指定权 = **架构负责人及以上**（上级权，与看板
    # 负责人指派同口径）。原「仅管理员」与前端能力位脱节 —— #43 同款问题第四次。
    owner_val = (req.owner or '').strip()
    new_owner = None
    if owner_val:
        perm_check(username, perm_chain(board_id=board_id, column_id=(old['column_id'] if old else '')),
                   OP_ASSIGN_OWNER, LV_BOARD_OWNER, 'column:' + (req.col_key or ''),
                   min_level=LV_ARCH_OWNER)
        new_owner = _norm_acl_owner('' if owner_val == '__CLEAR__' else owner_val)
    nature = (req.nature or '').strip() or (old['nature'] if old else '日常')
    if nature not in COLUMN_NATURES:
        raise HTTPException(400, '性质只能是「日常」或「专项」')
    # ---- 板块「完成情况」（2026-11-04 需求3）----
    # 语义：由**板块负责人本人**（board_columns.owner == 当前账号）或管理员手动声明，
    #      其他成员**不可修改**（403）。None = 不改。
    new_completion = None
    if req.completion is not None:
        cv = (req.completion or '').strip() or 'open'
        if cv not in COLUMN_COMPLETIONS:
            raise HTTPException(400, '完成情况只能是「未完成」「进行中」或「已完成」')
        _col_owner = (old['owner'] if old else '') or ''
        _is_col_owner = bool(_col_owner) and (_col_owner == username)
        if not (_is_col_owner or is_admin(username)):
            raise HTTPException(403, '仅板块负责人可设置完成情况')
        new_completion = cv
    year = _norm_year(req.year)
    created = (req.created_at or '').strip() or (old['created_at'] if old else '')
    if not created:
        created = time.strftime('%Y-%m-%d %H:%M:%S')
    year = year or created[:4]   # 归属年份默认取创建年份
    new_key = col_key(board_id, name)
    if new_key != req.col_key and dbq('SELECT col_key FROM board_columns WHERE col_key=?', (new_key,)):
        raise HTTPException(409, '该看板下已存在同名板块')
    # 改名：同步该板块下所有事项的 column_name
    if old and name != old_name:
        dbe('UPDATE cards SET column_name=? WHERE board_id=? AND column_name=? AND deleted=0',
            (name, board_id, old_name))
    if old:
        if new_owner is not None:
            dbe('UPDATE board_columns SET owner=? WHERE col_key=?', (new_owner, req.col_key))
        if new_completion is not None:
            dbe('UPDATE board_columns SET completion=? WHERE col_key=?', (new_completion, req.col_key))
        # 板块参与人（2026-11-03）：None = 不改；传值 = 覆盖（空串 = 清空）
        if req.participants is not None:
            # ⚠️ 指派参与人是**上级权限**（板块负责人及以上）——
            #    与 owner 不同，owner 仅管理员可改。
            perm_check(username, perm_chain(board_id=board_id, column_id=old['column_id']),
                       OP_ASSIGN_PARTICIPANT, LV_COLUMN_OWNER, 'column:' + req.col_key,
                       min_level=LV_COLUMN_OWNER)
            dbe('UPDATE board_columns SET participants=? WHERE col_key=?',
                (_norm_acl_participants(req.participants), req.col_key))
        dbe('UPDATE board_columns SET col_key=?, column_name=?, year=?, created_at=?, nature=? WHERE col_key=?',
            (new_key, name, year, created, nature, req.col_key))
    else:
        new_cid = 'COL' + str(int(time.time() * 1000))
        parts = _norm_acl_participants(req.participants) if req.participants else ''
        dbe('INSERT INTO board_columns (col_key, column_id, board_id, column_name, created_at, creator, nature, year, pinned, owner, participants)'
            ' VALUES (?,?,?,?,?,?,?,?,0,?,?)',
            (new_key, new_cid, board_id, name, created, username, nature, year, new_owner or '', parts))
    log_action('__column__', username, 'update', f'编辑板块 {name}')
    audit_log(username, client_ip(request), 'update', f'板块 {name}',
              f'编辑板块：{name}（归属年份 {year or "未填"}，性质 {nature}）', 'success')
    await ws_mgr.broadcast({'type': 'card_update', 'card_id': '*', 'by': username})
    return {'ok': True, 'col_key': new_key, 'column_name': name, 'year': year,
            'nature': nature, 'created_at': created,
            'owner': (new_owner if new_owner is not None else (old['owner'] if old else ''))}


@app.post('/api/columns/pin')
async def pin_column(req: ColumnPinReq, username: str = Depends(require_writer), request: Request = None):
    """板块置顶/取消置顶（作用域：所在看板内部）"""
    row = dbq('SELECT * FROM board_columns WHERE col_key=?', (req.col_key,))
    if not row:
        raise HTTPException(404, '板块不存在')
    boards, _cols = user_allowed(username)
    if boards is not None and row[0]['board_id'] not in boards:
        raise HTTPException(403, '无权操作该板块')
    # 分级权限（2026-11-02）：置顶 = 修改板块（板块负责人及以上）
    perm_check(username, perm_chain(board_id=row[0]['board_id'], column_id=row[0]['column_id']),
               OP_UPDATE, LV_COLUMN_OWNER, 'column:' + req.col_key)
    val = 1 if req.pinned else 0
    dbe('UPDATE board_columns SET pinned=? WHERE col_key=?', (val, req.col_key))
    log_action('__column__', username, 'pin', f'{"置顶" if val else "取消置顶"}板块 {row[0]["column_name"]}')
    audit_log(username, client_ip(request), 'update', f'板块 {row[0]["column_name"]}',
              f'{"置顶" if val else "取消置顶"}板块：{row[0]["column_name"]}', 'success')
    await ws_mgr.broadcast({'type': 'card_update', 'card_id': '*', 'by': username})
    return {'ok': True, 'col_key': req.col_key, 'pinned': val}


@app.post('/api/cards/{card_id}/pin')
async def pin_card(card_id: str, req: PinReq, username: str = Depends(require_writer), request: Request = None):
    """事项置顶/取消置顶（作用域：所在板块内部）"""
    cur = dbq('SELECT card_id, board_id, card_name FROM cards WHERE card_id=? AND deleted=0', (card_id,))
    if not cur:
        raise HTTPException(404, '事项不存在或已删除')
    boards, columns = user_allowed(username)
    if not perm_pass(dict(cur[0]), boards, columns):
        raise HTTPException(403, '无权操作该事项')
    val = 1 if req.pinned else 0
    dbe('UPDATE cards SET pinned=?, modified=? WHERE card_id=?',
        (val, time.strftime('%Y-%m-%d %H:%M:%S'), card_id))
    log_action(card_id, username, 'pin', f'{"置顶" if val else "取消置顶"} {cur[0]["card_name"]}')
    audit_log(username, client_ip(request), 'update', f'事项 {cur[0]["card_name"]}',
              f'{"置顶" if val else "取消置顶"}事项：{cur[0]["card_name"]}', 'success')
    await ws_mgr.broadcast({'type': 'card_update', 'card_id': '*', 'by': username})
    return {'ok': True, 'card_id': card_id, 'pinned': val}

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
    week_no: str = ''         # 周数维度（如 2026年第41周）；留空 = 按创建日期自动计算

class CommentReq(BaseModel):
    content: str
    mentions: list[str] = []      # 被 @ 的成员姓名列表（分号分隔落库）

def log_action(card_id, username, action, detail=''):
    dbe('INSERT INTO actions (card_id, username, action, detail) VALUES (?,?,?,?)',
        (card_id, username, action, detail))

@app.put('/api/cards/{card_id}')
async def update_card(card_id: str, req: CardUpdate, username: str = Depends(require_writer), request: Request = None):
    # 锁检查
    holder = lock_mgr.who(card_id)
    if holder and holder != username:
        raise HTTPException(409, f'卡片已被 {holder} 编辑中，无法保存')
    fields = req.fields
    if 'card_id' in fields: fields.pop('card_id')
    if 'version' in fields: fields.pop('version')
    if not fields:
        raise HTTPException(400, '没有可更新的字段')
    # 乐观锁：先取当前 version + board_id
    cur = dbq('SELECT version, parent_id, begin, due, board_id FROM cards WHERE card_id=? AND deleted=0', (card_id,))
    if not cur:
        raise HTTPException(404, '卡片不存在或已删除')
    # 分级权限（2026-11-02）：修改事项分两档 ——
    #   · 内容字段（状态/描述/时间/周数…）→ 参与人级即可（OP_EDIT_CONTENT）
    #   · 归属类字段（负责人 owner / 参与人 cc）→ 需负责人级，且**单独判定**
    #     （授予他人权限比改内容权限更高）
    # ⚠️ 归属类字段必须**先剔除**，否则参与人改内容时会连带触发指派判定而被拒。
    # ⚠️ **权限内核先于可见性校验**：可见性（能不能看见）是独立维度，
    #    但它的 403 提示会掩盖分级权限的真实原因 —— 先跑内核，错误体才准确。
    assign_fields = {}
    if 'owner' in fields:
        assign_fields['owner'] = fields.pop('owner')
    if 'cc' in fields:
        assign_fields['cc'] = fields.pop('cc')
    _chain = perm_chain(card_id=card_id)
    if fields:
        perm_check(username, _chain, OP_EDIT_CONTENT, LV_CARD_OWNER, 'card:' + card_id,
                   min_level=LV_PARTICIPANT)
    if assign_fields.get('owner'):
        perm_check(username, _chain, OP_ASSIGN_OWNER, LV_CARD_OWNER, 'card:' + card_id,
                   min_level=LV_COLUMN_OWNER)
    if assign_fields.get('cc'):
        perm_check(username, _chain, OP_ASSIGN_PARTICIPANT, LV_CARD_OWNER, 'card:' + card_id,
                   min_level=LV_CARD_OWNER)
    # 归属字段判定通过后再合并回去（保证后续 UPDATE 语句带上它们）
    fields.update(assign_fields)
    check_board_access(cur[0]['board_id'], username)
    # 板块级校验：账号被限定了某看板的板块白名单时，不得把事项移入不可见的板块
    if fields.get('column_id'):
        check_column_access(cur[0]['board_id'], str(fields.get('column_id')), username)
    # 周数维度：格式校验；清空则回落到「按创建日期所在自然周」
    if 'week_no' in fields:
        raw = str(fields.get('week_no') or '').strip()
        if raw:
            fields['week_no'] = _norm_week(raw)
        else:
            crow = dbq('SELECT created FROM cards WHERE card_id=?', (card_id,))
            fields['week_no'] = week_label(crow[0]['created']) if crow else ''
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
async def create_card(req: CardCreate, username: str = Depends(require_writer), request: Request = None):
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
        # 层级限制：本期只支持「主事项 → 子事项」两层。
        # 父事项自身已有父级 → 说明它已经是子事项，不能再往下挂（防止出现第三层）。
        if (parent[0]['parent_id'] or ''):
            raise HTTPException(400, '本期不支持更深层级：子事项下不能再创建子事项')
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
    # 分级权限（2026-11-02）：新增事项 = 板块负责人及以上（看板/架构负责人继承）
    # ⚠️ 权限内核先于可见性校验（与 create_column 同款理由）
    perm_check(username, perm_chain(board_id=req.board_id, column_id=req.column_id),
               OP_CREATE, LV_COLUMN_OWNER, 'board:' + req.board_id, min_level=LV_COLUMN_OWNER)
    check_board_access(req.board_id, username)
    # 指派类字段（owner / cc）单独判定：授予他人权限，权限高于普通新增
    _flds = req.fields or {}
    if _flds.get('owner'):
        perm_check(username, perm_chain(board_id=req.board_id, column_id=req.column_id),
                   OP_ASSIGN_OWNER, LV_CARD_OWNER, 'board:' + req.board_id,
                   min_level=LV_COLUMN_OWNER)
    if _flds.get('cc'):
        perm_check(username, perm_chain(board_id=req.board_id, column_id=req.column_id),
                   OP_ASSIGN_PARTICIPANT, LV_CARD_OWNER, 'board:' + req.board_id,
                   min_level=LV_COLUMN_OWNER)
    vals.update(req.fields)
    vals['card_id'] = new_id
    vals['board_id'] = req.board_id
    vals['column_id'] = req.column_id or vals.get('column_id', '')
    # 板块级校验：账号被限定了某看板的板块白名单时，不得写入不可见的板块
    check_column_access(req.board_id, vals['column_id'], username)
    # 客户端没带板块名时，按 column_id 从板块元信息里取（避免事项挂到空板块名）
    if not vals.get('column_name') and vals.get('column_id'):
        crow = dbq('SELECT column_name FROM board_columns WHERE board_id=? AND column_id=? LIMIT 1',
                   (req.board_id, vals['column_id']))
        if crow:
            vals['column_name'] = crow[0]['column_name']
    vals['card_name'] = req.card_name
    vals['creator'] = username
    vals['created'] = time.strftime('%Y-%m-%d %H:%M:%S')
    vals['parent_id'] = req.parent_id
    # 周数维度：默认取**创建日期**所处的自然周；前端显式传入时以其为准（可手动调整）
    vals['week_no'] = _norm_week(req.week_no or vals.get('week_no', '')) or week_label(vals['created'])
    cols = [k for k in CARD_FIELDS if k in vals]
    dbe(f'INSERT INTO cards ({",".join(cols)}) VALUES ({",".join("?"*len(cols))})',
        [vals[k] for k in cols])
    # 事项带板块名时，确保板块元信息存在（否则该板块在板块列表里没有创建日期/性质/置顶位）
    cname = (vals.get('column_name') or '').strip()
    if cname and not req.parent_id:
        ensure_column(req.board_id, cname, vals.get('column_id') or '', username,
                      vals.get('created') or time.strftime('%Y-%m-%d %H:%M:%S'))
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
def create_board(req: BoardCreateReq, username: str = Depends(require_writer), request: Request = None):
    """新建看板（仅管理员）。写入 boards 表，立即可在标签页看到空看板。"""
    import time
    name = (req.board_name or '').strip()
    if not name:
        raise HTTPException(400, '看板名称不能为空')
    bid = 'B' + str(int(time.time() * 1000))
    # 分级权限（2026-11-02）：新增看板 = 架构负责人及以上
    # 作用域：该账号所辖架构节点（含后代）。架构未配置时由管理员/超管创建。
    perm_check_arch_scope(username, OP_CREATE, 'board:' + bid)
    dbe('INSERT OR REPLACE INTO boards (board_id, board_name, workspace_id, owner, sort, created_at) VALUES (?,?,?,?,?,?)',
        (bid, name, (req.workspace_id or '').strip(), (req.owner or username).strip(), req.sort, time.strftime('%Y-%m-%d %H:%M:%S')))
    audit_log(username, client_ip(request), 'board_create', f'看板 {bid}', f'新建看板：{name}', 'success')
    return {'ok': True, 'board_id': bid, 'board_name': name, 'workspace_id': (req.workspace_id or '').strip()}


# ---------------- API：复制（看板 / 板块 / 主事项 / 子事项） ----------------
# 统一约定：
#   ① **副本是全新记录**，与原记录不共享任何数据（新的主键 + 独立的配置行）；
#   ② 标题等关键字段在复制弹窗里可编辑，默认「原标题（副本）」；
#   ③ 复制后必须**重新选择上级归属**（看板 → 板块 → 主事项），
#      可选项仅限当前账号权限范围内的数据 —— 越权数据不可见、也不可选；
#   ④ 服务端对「源记录可见性」与「目标归属可见性」各校验一次，
#      前端过滤只是体验，服务端才是边界。
COPY_SUFFIX = '（副本）'


def _unique_copy_name(base: str, exists) -> str:
    """副本名称去重：'X（副本）' 已存在时追加序号 → 'X（副本2）'。"""
    name = base
    i = 1
    while exists(name):
        i += 1
        stem = base[:-1] if base.endswith('）') else base
        name = '%s%d%s' % (stem, i, '）')
    return name


class CopyBoardReq(BaseModel):
    # deep=True → **整套复制**：连带复制原看板下的板块、事项与子事项（2026-11-03）
    deep: bool = False
    board_name: str = ''       # 副本名称（留空 = 原名 +（副本））
    dept: str = ''             # 归属重选：归属部门
    dept_node_id: int = 0      # 归属重选：归属部门对应的架构节点 id
    attr: str = ''             # 归属重选：属性（日常/专项）
    status: str = ''           # 归属重选：状态（启用/封存）
    remark: str = ''


@app.post('/api/boards/{board_id}/copy')
async def copy_board(board_id: str, req: CopyBoardReq, username: str = Depends(require_writer),
                     request: Request = None):
    """复制看板：生成一份**独立副本**（配置随附，内容不复制）。

    · 副本与原看板不共享任何数据：新的 board_id + 独立的 board_config 行；
    · 归属重选：归属部门 / 属性 / 状态 / 备注 都能在复制弹窗里改；
    · 权限（2026-11-03 修订）：**对该看板有管理权即可复制**（can_edit 口径）——
      看板负责人 / 架构负责人（管辖范围内）/ 管理员。
      与 /api/boards 的 can_edit 能力位同一判定（perm.py 的 can_do），
      前端按钮显隐与后端放行天然一致。副本 owner = 当前账号。
    · ⚠️ deep=True 时整套复制（板块 + 事项 + 子事项），见 _deep_copy_board_content。
    · ⚠️ 归属年份不在看板层 —— 年份在板块层随板块复制（deep）或随配置沿用。
    """
    src = dbq('SELECT * FROM boards WHERE board_id=?', (board_id,))
    if not src:
        raise HTTPException(404, '看板不存在')
    src = dict(src[0])
    # 分级权限（2026-11-03）：复制看板 = 对源看板的**管理权**（can_edit 口径）。
    # ⚠️ 先于可见性校验（与 update_card 同款顺序）。
    perm_check(username, perm_chain(board_id=board_id),
               OP_UPDATE, LV_BOARD_OWNER, 'board:' + board_id,
               min_level=LV_BOARD_OWNER)
    cfg = dbq('SELECT * FROM board_config WHERE board_id=?', (board_id,))
    cfg = dict(cfg[0]) if cfg else {}
    # 归属重选：未填的项沿用原看板配置
    dept = (req.dept or cfg.get('dept') or '').strip()
    dept_node_id = req.dept_node_id or int(cfg.get('dept_node_id') or 0)
    if dept_node_id or dept:
        node_id, dept_name, _is_center = _resolve_dept_node(dept, dept_node_id)
        dept_node_id = node_id
        dept = dept_name or dept
    attr = (req.attr or cfg.get('attr') or '日常').strip()
    status = (req.status or cfg.get('status') or '启用').strip()
    remark = req.remark if req.remark != '' else (cfg.get('remark') or '')
    _validate_board_config(dept, attr, status)
    name = (req.board_name or '').strip() or (src['board_name'] + COPY_SUFFIX)
    if not name:
        raise HTTPException(400, '看板名称不能为空')
    new_bid = 'BCP' + str(int(time.time() * 1000))
    now = time.strftime('%Y-%m-%d %H:%M:%S')
    conn = get_conn()
    try:
        conn.execute('INSERT INTO boards (board_id, board_name, workspace_id, owner, sort, created_at, copy_from)'
                     ' VALUES (?,?,?,?,?,?,?)',
                     (new_bid, name, src['workspace_id'], username, src['sort'], now, board_id))
        conn.execute('INSERT INTO board_config (board_id, dept, dept_node_id, attr, status, remark, created_at)'
                     ' VALUES (?,?,?,?,?,?,?)',
                     (new_bid, dept, dept_node_id, attr, status, remark, now))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    # ── 整套复制（deep）：连带板块 + 事项 + 子事项（2026-11-03）──
    copied_cols = copied_cards = 0
    if getattr(req, 'deep', False):
        copied_cols, copied_cards = _deep_copy_board_content(
            board_id, new_bid, name, username, src.get('workspace_id') or '')
    log_action('__board__', username, 'copy', f'复制看板 {name}')
    audit_log(username, client_ip(request), 'board_copy', f'看板 {board_id}',
              f'复制看板「{src["board_name"]}」→「{name}」（归属部门 {dept or "未配置"}，属性 {attr}'
              + (f'；整套复制：板块 {copied_cols} 个、事项 {copied_cards} 条'
                 if getattr(req, 'deep', False) else '') + '）', 'success')
    await ws_mgr.broadcast({'type': 'card_update', 'card_id': '*', 'by': username})
    return {'ok': True, 'board_id': new_bid, 'board_name': name, 'copy_from': board_id,
            'dept': dept, 'dept_node_id': dept_node_id, 'attr': attr, 'status': status,
            'deep': bool(getattr(req, 'deep', False)),
            'copied_columns': copied_cols, 'copied_cards': copied_cards}


# ---------------- API：删除看板（连同其板块与事项） ----------------
# ⚠️ 语义（2026-11-04 用户要求）：「删除看板配置」这个操作**没用** ——
#    看板配置只是看板的一组维度（归属部门/属性/状态/备注），删掉配置并不删看板，
#    看板还在、事项还在，只是回到「未配置」状态 → 用户视角等于什么都没删掉。
#    改为**删除看板本身**：连同板块、事项、子事项、配置一起清掉。
#
# ① 单条：DELETE /api/boards/{board_id}
#    权限 = **看板负责人及以上**（can_delete 能力位，后端口径一致）。
# ② 批量：POST /api/boards/bulk-delete（仅管理员，与原「删除所选」口径相同）
#
# 事项采用**软删**（cards.deleted=1）—— 数据仍可通过全局备份/恢复找回，
# 但看板不会再出现在任何列表里（列表口径 = boards 表 ∪ 未删卡片派生的看板）。
BOARD_DELETE_FIELDS = ('board_config', 'board_columns', 'cards', 'card_subtasks')


def _purge_board(bid: str) -> dict:
    """物理清除一个看板及其附属数据（板块 / 事项 / 子事项 / 配置 / 绑定残留）。

    返回 {'cards': n, 'columns': n} —— 供接口回显删了什么。
    ⚠️ 事项走**软删**（deleted=1），便于事后用全局备份恢复找回。
    """
    bid = (bid or '').strip()
    conn = get_conn()
    try:
        n_cards = conn.execute('SELECT COUNT(*) FROM cards WHERE board_id=? AND deleted=0',
                                (bid,)).fetchone()[0]
        n_cols = conn.execute('SELECT COUNT(*) FROM board_columns WHERE board_id=?',
                               (bid,)).fetchone()[0]
        # ① 事项软删（主事项与子事项同表 → 一并处理）
        conn.execute('UPDATE cards SET deleted=1 WHERE board_id=? AND deleted=0', (bid,))
        # ② 子事项清单（card_subtasks）与评论/操作记录随事项失效
        conn.execute('DELETE FROM card_subtasks WHERE card_id IN '
                     '(SELECT card_id FROM cards WHERE board_id=?)', (bid,))
        # ③ 板块 / 配置 / 看板本体
        conn.execute('DELETE FROM board_columns WHERE board_id=?', (bid,))
        conn.execute('DELETE FROM board_config WHERE board_id=?', (bid,))
        conn.execute('DELETE FROM boards WHERE board_id=?', (bid,))
        # ④ 清掉绑定残留：工作组绑定的看板列表（逗号分隔）里去掉该 board_id
        for r in conn.execute('SELECT id, boards FROM workgroups').fetchall():
            raw = (r['boards'] or '').strip()
            if not raw or raw == '*':
                continue
            items = [x for x in raw.split(',') if x]
            kept = [x for x in items if x != bid]
            if len(kept) != len(items):
                conn.execute('UPDATE workgroups SET boards=? WHERE id=?',
                             (','.join(kept), r['id']))
        # ⑤ 账号可见看板白名单（users.allowed_boards，'*' 表示全部 → 不动）
        for r in conn.execute('SELECT id, allowed_boards FROM users').fetchall():
            raw = (r['allowed_boards'] or '').strip()
            if not raw or raw == '*':
                continue
            items = [x for x in raw.split(',') if x]
            kept = [x for x in items if x != bid]
            if len(kept) != len(items):
                conn.execute('UPDATE users SET allowed_boards=? WHERE id=?',
                             (','.join(kept), r['id']))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return {'cards': n_cards, 'columns': n_cols}


@app.delete('/api/boards/{board_id}')
async def delete_board(board_id: str, username: str = Depends(require_writer),
                       request: Request = None):
    """删除**看板本身**（连同板块、事项、子事项、配置）。

    权限（2026-11-04）：看板负责人及以上（与 /api/boards 的 can_delete 能力位同口径）。
    ⚠️ 不可逆（事项为软删，可用全局备份恢复找回）。
    """
    bid = (board_id or '').strip()
    row = dbq('SELECT board_name FROM boards WHERE board_id=?', (bid,))
    if not row:
        # 兼容「仅有卡片、未登记 boards 元数据」的历史看板
        crow = dbq('SELECT board_name FROM cards WHERE board_id=? AND deleted=0 LIMIT 1', (bid,))
        if not crow:
            raise HTTPException(404, '看板不存在')
        name = crow[0]['board_name']
    else:
        name = row[0]['board_name']
    # 分级权限：删除看板 = 看板负责人及以上（min_level 显式给定，与能力位一致）
    perm_check(username, perm_chain(board_id=bid), OP_DELETE, LV_BOARD_OWNER,
               'board:' + bid, min_level=LV_BOARD_OWNER)
    stat = _purge_board(bid)
    audit_log(username, client_ip(request), 'board_delete', f'看板 {bid}',
              f'删除看板「{name}」（连带板块 {stat["columns"]} 个、事项 {stat["cards"]} 条）',
              'success')
    await ws_mgr.broadcast({'type': 'card_update', 'card_id': '*', 'by': username})
    return {'ok': True, 'board_id': bid, 'board_name': name,
            'deleted_columns': stat['columns'], 'deleted_cards': stat['cards']}


class BoardBulkDeleteReq(BaseModel):
    board_ids: List[str] = []   # 待删除的看板 id 列表


@app.post('/api/boards/bulk-delete')
def bulk_delete_boards(req: BoardBulkDeleteReq, username: str = Depends(require_admin),
                       request: Request = None):
    """批量删除看板（仅管理员）—— 连同板块、事项、子事项、配置一起清掉。

    ⚠️ 与单条删除同语义：删的是**看板本身**，不是「看板配置」。
    """
    ids = []
    for b in (req.board_ids or []):
        b = (b or '').strip()
        if b and b not in ids:
            ids.append(b)
    if not ids:
        raise HTTPException(400, '未选择任何看板')
    deleted = 0
    n_cards = n_cols = 0
    for bid in ids:
        stat = _purge_board(bid)
        deleted += 1
        n_cards += stat['cards']
        n_cols += stat['columns']
    audit_log(username, client_ip(request), 'board_bulk_delete', f'{len(ids)} 个看板',
              f'删除 {deleted} 个看板（连带板块 {n_cols} 个、事项 {n_cards} 条）', 'success')
    return {'ok': True, 'deleted': deleted, 'deleted_columns': n_cols,
            'deleted_cards': n_cards}


class CopyColumnReq(BaseModel):
    col_key: str = ''          # 源板块
    board_id: str = ''         # 归属重选：目标看板
    column_id: str = ''        # 归属重选：目标板块（该看板下可见的板块）
    column_name: str = ''      # 副本名称（留空 = 原名 +（副本））
    created_at: str = ''       # 副本创建日期（留空 = 今天）
    nature: str = ''           # 性质（留空 = 沿用原板块）
    year: str = ''             # 归属年份（留空 = 沿用原板块）


@app.post('/api/columns/copy')
async def copy_column(req: CopyColumnReq, username: str = Depends(require_writer),
                      request: Request = None):
    """复制板块：复制到**指定看板**（归属重选）。

    权限三重校验：
      ① 源板块必须对当前账号可见（否则无权复制）；
      ② 目标看板必须可见且当前账号有编辑权；
      ③ 目标板块（若指定）必须对该账号可见 —— 越权板块既不可见也不可选。
    """
    if not req.col_key:
        raise HTTPException(400, '缺少源板块')
    src = dbq('SELECT * FROM board_columns WHERE col_key=?', (req.col_key,))
    if not src:
        raise HTTPException(404, '源板块不存在')
    src = dict(src[0])
    # ① 源板块可见性
    boards, columns = user_allowed(username)
    if boards is not None and src['board_id'] not in boards:
        raise HTTPException(403, '无权复制该板块')
    if columns is not None and src['column_id']:
        allowed = columns.get(src['board_id'])
        if allowed is not None and src['column_id'] not in allowed:
            raise HTTPException(403, '无权复制该板块')
    # ② 目标看板：可见 + 可编辑
    if not req.board_id:
        raise HTTPException(400, '请选择目标看板')
    check_board_access(req.board_id, username)
    if not dbq('SELECT board_id FROM boards WHERE board_id=?', (req.board_id,)):
        raise HTTPException(404, '目标看板不存在')
    # ③ 目标板块可见性
    if req.column_id:
        check_column_access(req.board_id, req.column_id, username)
    base_name = (req.column_name or '').strip() or (src['column_name'] + COPY_SUFFIX)
    name = _unique_copy_name(base_name,
                              lambda n: bool(dbq('SELECT col_key FROM board_columns WHERE col_key=?',
                                                 (col_key(req.board_id, n),))))
    key = col_key(req.board_id, name)
    created = (req.created_at or '').strip() or time.strftime('%Y-%m-%d %H:%M:%S')
    nature = (req.nature or src['nature'] or '日常').strip()
    if nature not in COLUMN_NATURES:
        raise HTTPException(400, '性质只能是「日常」或「专项」')
    year = _norm_year(req.year) or (src['year'] or '') or created[:4]
    new_cid = 'COL' + str(int(time.time() * 1000))
    dbe('INSERT INTO board_columns (col_key, column_id, board_id, column_name, created_at, creator, nature, year, pinned, copy_from)'
        ' VALUES (?,?,?,?,?,?,?,?,0,?)',
        (key, new_cid, req.board_id, name, created, username, nature, year, src['col_key']))
    log_action('__column__', username, 'copy', f'复制板块 {name}')
    audit_log(username, client_ip(request), 'column_copy', f'板块 {src["col_key"]}',
              f'复制板块「{src["column_name"]}」→「{name}」（目标看板 {req.board_id}）', 'success')
    await ws_mgr.broadcast({'type': 'card_update', 'card_id': '*', 'by': username})
    return {'ok': True, 'col_key': key, 'column_id': new_cid, 'column_name': name,
            'board_id': req.board_id, 'copy_from': src['col_key'],
            'created_at': created, 'creator': username, 'nature': nature, 'year': year}


class CopyCardReq(BaseModel):
    card_id: str = ''          # 源事项（主事项或子事项）
    board_id: str = ''         # 归属重选：目标看板
    column_id: str = ''        # 归属重选：目标板块
    column_name: str = ''      # 目标板块名（随目标板块带出）
    parent_id: str = ''        # 归属重选：目标主事项（复制**子事项**时必填）
    card_name: str = ''        # 副本标题（留空 = 原标题 +（副本））
    week_no: str = ''          # 副本周数（留空 = 按副本创建日期计算）


# 复制时随附的业务字段（运行时状态字段一律重置，不复制）
CARD_COPY_FIELDS = ['owner', 'cc', 'follower', 'begin', 'due', 'description', 'priority',
                     'label', 'entity_type', 'cover_setted', 'cover_info', 'b_sort',
                     'column_sort', 'board_status', 'board_creator', 'workspace_id']


def _deep_copy_board_content(src_board_id, new_board_id, new_board_name, username, workspace_id):
    """看板**整套复制**的正文部分（2026-11-03）：板块 + 事项 + 子事项。

    返回 (板块数, 事项数)。

    口径与既有 copy_column / copy_card 保持一致：
      · 板块：col_key = board_id::column_name → 新板块用新 board_id 前缀；
        归属年份 / 性质 / 负责人 / 参与人随附。
      · 事项：主事项与子事项都复制；**子事项的 parent_id 指向新主事项**，
        保持「主 → 子」结构；状态重置为未完成，创建人/时间重置为当前账号与当前时间。
      · copy_from 记录来源，便于溯源。
    """
    now = time.strftime('%Y-%m-%d %H:%M:%S')
    conn = get_conn()
    stamp = str(int(time.time() * 1000))
    # ── ① 板块 ──
    src_cols = [dict(r) for r in dbq(
        'SELECT * FROM board_columns WHERE board_id=? ORDER BY id', (src_board_id,))]
    col_id_map = {}          # 原 column_id → 新 column_id
    key_map = {}             # 原 col_key → 新 col_key
    for i, c in enumerate(src_cols):
        new_cid = 'COLD' + stamp + str(i)
        new_key = new_board_id + '::' + c['column_name']
        conn.execute(
            'INSERT INTO board_columns (col_key, column_id, board_id, column_name, created_at,'
            ' creator, nature, pinned, year, copy_from, owner, participants)'
            ' VALUES (?,?,?,?,?,?,?,0,?,?,?,?)',
            (new_key, new_cid, new_board_id, c['column_name'], c['created_at'],
             username, c['nature'], c['year'], c['col_key'],
             c.get('owner') or '', c.get('participants') or ''))
        col_id_map[c['column_id']] = new_cid
        key_map[c['col_key']] = new_key
    # ── ② 事项（主事项 + 子事项）──
    # ⚠️ cards 表**没有 id 列**（主键是 card_id）→ ORDER BY card_id
    src_cards = [dict(r) for r in dbq(
        'SELECT * FROM cards WHERE board_id=? AND deleted=0 ORDER BY card_id', (src_board_id,))]
    card_id_map = {}         # 原 card_id → 新 card_id
    # 先建主事项（parent_id 为空），再建子事项（parent_id 指向新主事项）
    ordered = [c for c in src_cards if not (c.get('parent_id') or '')]
    ordered += [c for c in src_cards if (c.get('parent_id') or '')]
    for i, c in enumerate(ordered):
        new_cid = 'CDP' + stamp + str(i)
        new_col_id = col_id_map.get(c['column_id'], '')
        new_col_name = c['column_name']
        # 新板块名：从 col_key 反查（原 col_key = board::name）
        src_key = src_board_id + '::' + (c['column_name'] or '')
        new_key = key_map.get(src_key, '')
        if new_key and '::' in new_key:
            new_col_name = new_key.split('::', 1)[1]
        new_parent = card_id_map.get(c.get('parent_id') or '', '')
        vals = {
            'card_id': new_cid,
            'board_id': new_board_id,
            'board_name': new_board_name,
            'column_id': new_col_id,
            'column_name': new_col_name,
            'workspace_id': workspace_id,
            'card_name': c['card_name'],
            'status': 'todo',
            'status_name': '未完成',
            'creator': username,
            'created': now,
            'modified': now,
            'completed': '',
            'b_sort': c.get('b_sort') or '',
            'entity_type': c.get('entity_type') or '',
            'cover_setted': c.get('cover_setted') or '',
            'cover_info': c.get('cover_info') or '',
            'is_filed': c.get('is_filed') or '',
            'created_from': c.get('created_from') or '',
            'date_status': c.get('date_status') or '',
            'due_time_ux': c.get('due_time_ux') or '',
            'begin_date_status': c.get('begin_date_status') or '',
            'begin_time_ux': c.get('begin_time_ux') or '',
            'comments': '',
            'column_sort': c.get('column_sort') or '',
            'board_status': c.get('board_status') or '',
            'board_creator': c.get('board_creator') or '',
            'parent_id': new_parent,
            'version': 0,
            'deleted': 0,
            'pinned': 0,
            'week_no': c.get('week_no') or '',
            'copy_from': c['card_id'],
        }
        for f in CARD_COPY_FIELDS:
            if f == 'workspace_id':
                continue
            vals[f] = c.get(f) or ''
        cols = list(vals.keys())
        marks = ','.join('?' * len(cols))
        conn.execute('INSERT INTO cards (%s) VALUES (%s)' % (','.join(cols), marks),
                     [vals[k] for k in cols])
        card_id_map[c['card_id']] = new_cid
    return len(col_id_map), len(card_id_map)


@app.post('/api/cards/copy')
async def copy_card(req: CopyCardReq, username: str = Depends(require_writer),
                    request: Request = None):
    """复制主事项 / 子事项：生成一份**全新记录**，并重新选择上级归属。

    · 副本与原记录不共享任何数据（新的 card_id，字段独立）；
    · 归属重选：目标看板 + 目标板块；**复制子事项时还必须重新选择所属主事项**；
    · 权限：源事项必须可见；目标看板 / 目标板块 / 目标主事项必须在当前账号的
      可见范围内，且当前账号具备编辑权 —— 越权数据不可见也不可选；
    · 副本的状态重置为「未完成」，创建人 / 创建时间重置为当前账号与当前时间，
      置顶、编辑锁、评论与子事项目录均不复制。
    """
    if not req.card_id:
        raise HTTPException(400, '缺少源事项')
    src = dbq('SELECT * FROM cards WHERE card_id=? AND deleted=0', (req.card_id,))
    if not src:
        raise HTTPException(404, '源事项不存在或已删除')
    src = dict(src[0])
    # ① 源事项可见性（check_card_access 内部同时校验看板可见性与存在性）
    check_card_access(req.card_id, username)
    # ② 目标看板：可见 + 可编辑
    if not req.board_id:
        raise HTTPException(400, '请选择目标看板')
    check_board_access(req.board_id, username)
    # ③ 目标板块可见性
    if req.column_id:
        check_column_access(req.board_id, req.column_id, username)
    # ④ 层级：主事项 → 主事项；子事项 → 子事项（必须重新选择所属主事项）
    is_sub = bool(src.get('parent_id'))
    parent_id = ''
    if is_sub:
        if not req.parent_id:
            raise HTTPException(400, '复制子事项必须重新选择所属主事项')
        prow = dbq('SELECT * FROM cards WHERE card_id=? AND deleted=0', (req.parent_id,))
        if not prow:
            raise HTTPException(404, '目标主事项不存在或已删除')
        prow = dict(prow[0])
        if prow.get('parent_id'):
            raise HTTPException(400, '目标主事项不能是子事项')
        boards, columns = user_allowed(username)
        if not perm_pass(prow, boards, columns):
            raise HTTPException(403, '目标主事项不可见')
        parent_id = req.parent_id
    name = (req.card_name or '').strip() or (src['card_name'] + COPY_SUFFIX)
    if not name:
        raise HTTPException(400, '事项标题不能为空')
    now = time.strftime('%Y-%m-%d %H:%M:%S')
    new_id = 'NC' + str(int(time.time() * 1000))
    vals = {k: src.get(k, '') for k in CARD_COPY_FIELDS}
    # 目标归属
    vals['board_id'] = req.board_id
    bmeta = dbq('SELECT board_name FROM boards WHERE board_id=?', (req.board_id,))
    if bmeta:
        vals['board_name'] = bmeta[0]['board_name']
    else:
        cmeta = dbq('SELECT board_name FROM cards WHERE board_id=? AND deleted=0 LIMIT 1', (req.board_id,))
        vals['board_name'] = cmeta[0]['board_name'] if cmeta else req.board_id
    vals['column_id'] = req.column_id or ''
    vals['column_name'] = req.column_name or ''
    # 运行时字段重置
    vals['card_id'] = new_id
    vals['card_name'] = name
    vals['status'] = 'open'
    vals['status_name'] = '未完成'
    vals['creator'] = username
    vals['created'] = now
    vals['modified'] = ''
    vals['completed'] = ''
    vals['parent_id'] = parent_id
    vals['version'] = 1
    vals['deleted'] = 0
    vals['pinned'] = 0
    vals['copy_from'] = src['card_id']
    # 周数：默认按**副本创建日期**所在自然周，可手动指定
    vals['week_no'] = _norm_week(req.week_no) or week_label(now)
    cols = [k for k in CARD_FIELDS if k in vals]
    dbe(f'INSERT INTO cards ({",".join(cols)}) VALUES ({",".join("?"*len(cols))})',
        [vals[k] for k in cols])
    # 目标板块的元信息登记（目标看板下该板块可能尚未登记）
    if vals['column_name'] and not parent_id:
        ensure_column(req.board_id, vals['column_name'], vals['column_id'], username, now)
    log_action(new_id, username, 'copy', f'复制自 {src["card_id"]}')
    audit_log(username, client_ip(request), 'card_copy', f'事项 {src["card_id"]}',
              f'复制事项「{src["card_name"]}」→「{name}」（目标看板 {req.board_id}'
              + (f'，目标主事项 {parent_id}' if parent_id else '') + '）', 'success')
    await ws_mgr.broadcast({'type': 'card_create', 'card_id': new_id,
        'board_id': req.board_id, 'by': username}, exclude=username)
    return {'ok': True, 'card_id': new_id, 'card_name': name, 'board_id': req.board_id,
            'column_id': vals['column_id'], 'column_name': vals['column_name'],
            'parent_id': parent_id, 'week_no': vals['week_no'], 'copy_from': src['card_id']}


@app.get('/api/boards/{board_id}/columns')
def board_columns_list(board_id: str, username: str = Depends(require_auth)):
    """某看板下**当前账号可见**的板块清单（复制弹窗选目标板块用）。

    可见性口径与 /api/cards 返回的板块列表完全一致（visible_columns），
    因此**越权板块既不会出现在选项里，也不可能被提交**。
    """
    boards, columns = user_allowed(username)
    if boards is not None and board_id not in boards:
        raise HTTPException(403, '无权访问该看板')
    counts = {}
    # ⚠️ 计数必须按**可见范围**统计 —— 否则越权板块的条数会随 counts 下发
    #    （虽然 visible_columns 会把越权板块过滤掉，但数据仍出了服务端）。
    #    口径与 /api/cards 完全一致：filter_rows 走看板级 + 板块级两级权限。
    for r in filter_rows(dbq("SELECT board_id, column_id, column_name, status FROM cards"
                             " WHERE deleted=0 AND board_id=?", (board_id,)), boards, columns):
        k = col_key(board_id, r['column_name'])
        n, dn = counts.get(k, (0, 0))
        counts[k] = (n + 1, dn + (1 if r['status'] == 'done' else 0))
    out = visible_columns(username, boards, columns, board_id, counts)
    return {'columns': out}


@app.delete('/api/cards/{card_id}')
async def delete_card(card_id: str, username: str = Depends(require_writer), request: Request = None):
    holder = lock_mgr.who(card_id)
    if holder and holder != username:
        raise HTTPException(409, f'卡片已被 {holder} 编辑中，无法删除')
    cur_row = dbq('SELECT board_id FROM cards WHERE card_id=? AND deleted=0', (card_id,))
    if not cur_row:
        raise HTTPException(404, '卡片不存在或已删除')
    # 分级权限（2026-11-02）：删除事项 = 事项负责人及以上
    # ⚠️ 权限内核先于可见性校验（见 update_card 的同款说明）
    perm_check(username, perm_chain(card_id=card_id),
               OP_DELETE, LV_CARD_OWNER, 'card:' + card_id)
    check_board_access(cur_row[0]['board_id'], username)
    res = dbe('UPDATE cards SET deleted=1 WHERE card_id=? AND deleted=0', (card_id,))
    if res.rowcount == 0:
        raise HTTPException(404, '卡片不存在或已删除')
    # 级联：删除子事项（递归，含孙级）及其代办任务
    allsubs = dbq('SELECT card_id, parent_id FROM cards WHERE deleted=0 AND parent_id!=?', (card_id,))
    byid = {r['card_id']: (r['parent_id'] or 0) for r in allsubs}
    victims = {card_id}
    changed = True
    while changed:
        changed = False
        for cid, pid in byid.items():
            if pid in victims and cid not in victims:
                victims.add(cid)
                changed = True
    victims.discard(card_id)
    for sid in victims:
        dbe('UPDATE cards SET deleted=1 WHERE card_id=?', (sid,))
        dbe('DELETE FROM card_subtasks WHERE card_id=?', (sid,))
    dbe('DELETE FROM card_subtasks WHERE card_id=?', (card_id,))
    # 数据不变量：板块至少留一个事项；空板块与空看板一并清理
    cleanup_empty_columns_and_boards()
    log_action(card_id, username, 'delete', f'subitems={len(victims)}')
    audit_log(username, client_ip(request), 'delete', f'卡片 {card_id}', f'删除卡片（含 {len(victims)} 个子事项）', 'success')
    lock_mgr.release(card_id, username)
    await ws_mgr.broadcast({'type': 'card_delete', 'card_id': card_id,
        'by': username}, exclude=username)
    return {'ok': True}

# ---------------- API：锁 ----------------
@app.post('/api/cards/{card_id}/lock')
async def lock_card(card_id: str, username: str = Depends(require_writer), request: Request = None):
    ok, holder = lock_mgr.acquire(card_id, username)
    if not ok:
        raise HTTPException(409, f'卡片已被 {holder} 编辑中')
    audit_log(username, client_ip(request), 'lock', f'卡片 {card_id}', '锁定编辑', 'success')
    await ws_mgr.broadcast({'type': 'lock', 'card_id': card_id, 'by': username})
    return {'ok': True}

@app.post('/api/cards/{card_id}/unlock')
async def unlock_card(card_id: str, username: str = Depends(require_writer), request: Request = None):
    if lock_mgr.release(card_id, username):
        audit_log(username, client_ip(request), 'unlock', f'卡片 {card_id}', '解锁编辑', 'success')
        await ws_mgr.broadcast({'type': 'unlock', 'card_id': card_id, 'by': username})
    return {'ok': True}

@app.post('/api/cards/{card_id}/heartbeat')
def heartbeat(card_id: str, username: str = Depends(require_writer)):
    lock_mgr.heartbeat(card_id, username)
    return {'ok': True}

# ---------------- API：评论 / 日志 ----------------
@app.get('/api/cards/{card_id}/comments')
def get_comments(card_id: str, username: str = Depends(require_auth)):
    # 可见性校验：该卡片所属看板对当前账号不可见 → 403（此前只做登录校验，
    # 不可见看板的评论可被直接调 API 读取 → 越权读）
    check_card_access(card_id, username)
    rows = dbq('SELECT id, card_id, username, content, mentions, created_at FROM comments WHERE card_id=? ORDER BY id', (card_id,))
    return {'comments': [dict(r) for r in rows]}

@app.post('/api/cards/{card_id}/comments')
async def add_comment(card_id: str, req: CommentReq, username: str = Depends(require_auth), request: Request = None):
    check_card_access(card_id, username)
    if not req.content or not req.content.strip():
        raise HTTPException(400, '评论不能为空')
    # @ 提及：mentions 是被提及的成员姓名列表（与 owner 字段同口径）
    mentions = [m.strip() for m in (req.mentions or []) if m and m.strip()]
    # 去重且保序
    seen = set(); ms = []
    for m in mentions:
        if m not in seen:
            seen.add(m); ms.append(m)
    dbe('INSERT INTO comments (card_id, username, content, mentions) VALUES (?,?,?,?)',
        (card_id, username, req.content.strip(), ';'.join(ms)))
    log_action(card_id, username, 'comment', req.content.strip()[:200])
    audit_log(username, client_ip(request), 'comment', f'卡片 {card_id}', '发表评论', 'success')
    # 为每个被提及的成员投递一条消息（收件人 = 成员对应的登录账号；没有账号的成员按姓名记录）
    if ms:
        card_name = ''
        crow = dbq('SELECT card_name FROM cards WHERE card_id=? AND deleted=0', (card_id,))
        if crow:
            card_name = crow[0]['card_name'] or ''
        for m in ms:
            recv = _mention_receiver(m)
            if not recv or recv == username:
                continue   # 不给自己发消息
            dbe('INSERT INTO messages (receiver, sender, card_id, kind, content) VALUES (?,?,?,?,?)',
                (recv, username, card_id, 'mention',
                 (req.content.strip()[:200] if req.content.strip() else '提及了你')))
    await ws_mgr.broadcast({'type': 'comment', 'card_id': card_id,
        'by': username}, exclude=username)
    return {'ok': True}

# ---------------- API：消息中心 ----------------
def _mention_receiver(member_name):
    """把被提及的成员姓名映射到收件人标识。
    优先用该成员绑定的登录账号（team_members.account）；
    没有绑定账号时退回姓名本身（前端匹配当前用户名）。
    返回空串表示无法投递。"""
    name = (member_name or '').strip()
    if not name:
        return ''
    rows = dbq('SELECT account FROM team_members WHERE name=?', (name,))
    if rows and (rows[0]['account'] or '').strip():
        return rows[0]['account'].strip()
    return name

@app.get('/api/messages')
def get_messages(username: str = Depends(require_auth)):
    """当前用户的消息列表 + 未读数。
    收件人匹配：账号本身、以及该账号绑定的成员姓名（两种都收，避免绑定遗漏）。"""
    names = [username]
    rows = dbq('SELECT name FROM team_members WHERE account=?', (username,))
    for r in rows:
        if r['name'] and r['name'] not in names:
            names.append(r['name'])
    marks = ','.join('?' * len(names))
    msgs = dbq(f'''SELECT id, receiver, sender, card_id, kind, content, read_at, created_at
                    FROM messages WHERE receiver IN ({marks}) ORDER BY id DESC LIMIT 200''', tuple(names))
    unread = dbq(f'SELECT COUNT(*) c FROM messages WHERE receiver IN ({marks}) AND read_at=\'\'', tuple(names))
    return {'messages': [dict(r) for r in msgs], 'unread': unread[0]['c'] if unread else 0}

@app.post('/api/messages/{mid}/read')
def read_message(mid: int, username: str = Depends(require_auth)):
    names = [username]
    rows = dbq('SELECT name FROM team_members WHERE account=?', (username,))
    for r in rows:
        if r['name'] and r['name'] not in names:
            names.append(r['name'])
    marks = ','.join('?' * len(names))
    cur = dbq(f'SELECT id, read_at FROM messages WHERE id=? AND receiver IN ({marks})', (mid,) + tuple(names))
    if not cur:
        raise HTTPException(404, '消息不存在或不属于当前用户')
    if not cur[0]['read_at']:
        dbe("UPDATE messages SET read_at=datetime('now','localtime') WHERE id=?", (mid,))
    return {'ok': True}

@app.post('/api/messages/read-all')
def read_all_messages(username: str = Depends(require_auth)):
    """一键标记当前用户的全部消息为已读。"""
    names = [username]
    rows = dbq('SELECT name FROM team_members WHERE account=?', (username,))
    for r in rows:
        if r['name'] and r['name'] not in names:
            names.append(r['name'])
    marks = ','.join('?' * len(names))
    dbe(f"UPDATE messages SET read_at=datetime('now','localtime') WHERE receiver IN ({marks}) AND read_at=''",
        tuple(names))
    return {'ok': True}

@app.get('/api/cards/{card_id}/actions')
def get_actions(card_id: str, username: str = Depends(require_auth)):
    check_card_access(card_id, username)
    rows = dbq('SELECT username, action, detail, created_at FROM actions WHERE card_id=? ORDER BY id DESC LIMIT 30',
               (card_id,))
    return {'actions': [dict(r) for r in rows]}

# ---------------- API：子事项 ----------------
class SubtaskReq(BaseModel):
    title: Optional[str] = None
    done: Optional[int] = None
    sort: Optional[int] = None
    parent_id: Optional[int] = None   # 上级子事项 id（0/None = 顶层）


def build_subtask_tree(rows):
    """把平铺的子事项列表组装成树（children 嵌套）。

    孤儿节点（parent_id 指向不存在的行）会被提到顶层，避免子事项「消失」。
    """
    items = []
    index = {}
    for r in rows:
        d = dict(r)
        d['children'] = []
        items.append(d)
        index[d['id']] = d
    roots = []
    for d in items:
        pid = d.get('parent_id') or 0
        if pid and pid in index and pid != d['id']:
            index[pid]['children'].append(d)
        else:
            roots.append(d)
    # 防御环路：若因数据异常形成环，按原顺序提为顶层
    def depth_of(d, seen=None):
        seen = seen or set()
        n = 0
        cur = d
        while cur.get('children'):
            cur = cur['children'][0]
            if cur['id'] in seen:
                break
            seen.add(cur['id'])
            n += 1
            if n > 32:
                break
        return n
    for d in items:
        d['depth'] = depth_of(d)
    return roots, items


@app.get('/api/cards/{card_id}/subtasks')
def get_subtasks(card_id: str, username: str = Depends(require_auth)):
    """返回子事项**树形**结构：顶层子事项在 subtasks，每项带 children 子树"""
    check_card_access(card_id, username)
    rows = dbq('SELECT id, card_id, title, done, sort, done_by, done_at, created_by, parent_id, created_at '
               'FROM card_subtasks WHERE card_id=? ORDER BY sort, id', (card_id,))
    roots, flat = build_subtask_tree(rows)
    return {'subtasks': roots, 'flat': flat,
            'total': len(flat), 'done': sum(1 for x in flat if x.get('done'))}

@app.get('/api/cards/{card_id}/children')
def get_card_children(card_id: str, username: str = Depends(require_auth)):
    """返回该事项的**子事项树**（子卡片递归嵌套），供列表与弹窗按目录展示"""
    check_card_access(card_id, username)
    boards, columns = user_allowed(username)
    all_rows = [dict(r) for r in dbq('SELECT * FROM cards WHERE deleted=0')]
    mine = filter_rows(all_rows, boards, columns)
    by_parent = defaultdict(list)
    for r in mine:
        if r.get('parent_id'):
            by_parent[r['parent_id']].append(r)

    def build(pid, depth=0):
        out = []
        # 子事项排序与主事项列表保持一致：置顶优先，其余按创建时间降序（新的在前）
        for r in sorted(by_parent.get(pid, []),
                        key=lambda x: (0 if x.get('pinned') else 1,
                                       -_ts(x.get('created')), x['card_id'])):
            d = dict(r)
            d['children'] = build(r['card_id'], depth + 1) if depth < 6 else []
            d['child_count'] = len(by_parent.get(r['card_id'], []))
            d['locked_by'] = lock_mgr.who(r['card_id'])
            out.append(d)
        return out

    tree = build(card_id)
    stack = list(tree)
    total = 0
    while stack:
        n = stack.pop()
        total += 1
        stack.extend(n.get('children') or [])
    return {'children': tree, 'total': total}


@app.post('/api/cards/{card_id}/subtasks')
async def add_subtask(card_id: str, req: SubtaskReq, username: str = Depends(require_writer), request: Request = None):
    holder = lock_mgr.who(card_id)
    if holder and holder != username:
        raise HTTPException(409, f'卡片已被 {holder} 编辑中，无法修改子事项')
    title = (req.title or '').strip()
    if not title:
        raise HTTPException(400, '子事项标题不能为空')
    card_row = dbq('SELECT board_id FROM cards WHERE card_id=? AND deleted=0', (card_id,))
    if not card_row:
        raise HTTPException(404, '卡片不存在或已删除')
    check_board_access(card_row[0]['board_id'], username)
    if not dbq('SELECT 1 FROM cards WHERE card_id=? AND deleted=0', (card_id,)):
        raise HTTPException(404, '卡片不存在或已删除')
    mx = dbq('SELECT COALESCE(MAX(sort),0) m FROM card_subtasks WHERE card_id=?', (card_id,))[0]['m']
    # 层级：parent_id 必须是同一卡片下的既有子事项（0/None = 顶层）
    pid = int(req.parent_id or 0)
    if pid:
        if not dbq('SELECT 1 FROM card_subtasks WHERE id=? AND card_id=?', (pid, card_id)):
            raise HTTPException(400, '上级子事项不存在')
        # 防止成环：父级不能是自己的后代
        anc = dbq('SELECT id, parent_id FROM card_subtasks WHERE card_id=?', (card_id,))
        byid = {r['id']: (r['parent_id'] or 0) for r in anc}
        cur, guard = pid, 0
        while cur and guard < 64:
            cur = byid.get(cur, 0)
            guard += 1
            if cur == pid:
                raise HTTPException(400, '不能把子事项挂到它自己的下级')
    dbe('INSERT INTO card_subtasks (card_id, title, done, sort, created_by, parent_id) VALUES (?,?,?,?,?,?)',
        (card_id, title, 0, mx + 10, username, pid))
    log_action(card_id, username, 'subtask_add', title)
    audit_log(username, client_ip(request), 'subtask_add', f'卡片 {card_id}',
              ('新增子事项：%s' % title) + (f'（上级 #{pid}）' if pid else ''), 'success')
    await ws_mgr.broadcast({'type': 'card_update', 'card_id': card_id,
        'by': username}, exclude=username)
    return {'ok': True}

@app.put('/api/cards/{card_id}/subtasks/{sid}')
async def update_subtask(card_id: str, sid: int, req: SubtaskReq,
                         username: str = Depends(require_writer), request: Request = None):
    holder = lock_mgr.who(card_id)
    if holder and holder != username:
        raise HTTPException(409, f'卡片已被 {holder} 编辑中，无法修改子事项')
    _cr = dbq('SELECT board_id FROM cards WHERE card_id=? AND deleted=0', (card_id,))
    if _cr:
        check_board_access(_cr[0]['board_id'], username)
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
async def delete_subtask(card_id: str, sid: int, username: str = Depends(require_writer), request: Request = None):
    holder = lock_mgr.who(card_id)
    if holder and holder != username:
        raise HTTPException(409, f'卡片已被 {holder} 编辑中，无法修改子事项')
    _cr2 = dbq('SELECT board_id FROM cards WHERE card_id=? AND deleted=0', (card_id,))
    if _cr2:
        check_board_access(_cr2[0]['board_id'], username)
    # 删除父级时一并删除其所有后代，避免留下孤儿节点
    allrows = dbq('SELECT id, parent_id FROM card_subtasks WHERE card_id=?', (card_id,))
    byid = {r['id']: (r['parent_id'] or 0) for r in allrows}
    victims = {sid}
    changed = True
    while changed:
        changed = False
        for cid, pid in byid.items():
            if pid in victims and cid not in victims:
                victims.add(cid)
                changed = True
    marks = ','.join('?' * len(victims))
    res = dbe(f'DELETE FROM card_subtasks WHERE card_id=? AND id IN ({marks})',
              [card_id] + sorted(victims))
    if res.rowcount == 0:
        raise HTTPException(404, '子事项不存在')
    extra = len(victims) - 1
    log_action(card_id, username, 'subtask_del', f'#{sid}' + (f' (+{extra} 下级)' if extra else ''))
    audit_log(username, client_ip(request), 'subtask_delete', f'卡片 {card_id} 子事项#{sid}',
              ('删除子事项：%s' % ('含 %d 个下级' % extra if extra else '单条')), 'success')
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
    # 组织归属来源（架构管理优先）——供前端标注「以架构管理为准 / 与架构管理冲突」
    appt_nodes = defaultdict(set)
    for r in dbq('SELECT a.member_id, n.name FROM org_appointments a '
                 'JOIN org_nodes n ON n.id=a.node_id'):
        appt_nodes[r['member_id']].add(r['name'])
    for m in out:
        names = set(x.strip() for x in (m.get('workgroups') or '').split(';') if x.strip())
        org_names = appt_nodes.get(m['id'], set())
        if org_names:
            m['org_source'] = 'org'
            # 冲突：workgroups 里有架构管理未覆盖的组
            m['org_conflict'] = sorted(names - org_names)
            m['org_nodes'] = sorted(org_names)
        elif names:
            m['org_source'] = 'legacy'
            m['org_conflict'] = []
            m['org_nodes'] = []
        else:
            m['org_source'] = 'none'
            m['org_conflict'] = []
            m['org_nodes'] = []
    if not is_admin(username):
        # 非管理员：脱敏角色/密码状态（成员管理是管理员页面用不到）。
        # ⚠️ account **不能清**（2026-11-04 用户反馈）——
        #   「姓名 → 账号」映射是选人选人的必需依赖：树选负责人/参与人的
        #   requireAccount 判定与 bcAccountByName 转换都靠它。
        #   清空 → 所有人被判「未开通账号」不可选 + 负责人筛选降级成账号下拉。
        for m in out:
            m['role'] = ''
            m['password_set'] = False
            m.pop('org_conflict', None)
            m.pop('org_nodes', None)
    return {'members': out}

class TeamReq(BaseModel):
    name: str
    # workgroups 已下线：成员的组织归属统一由【架构管理】的任命维护，
    # 成员页面不再提交该字段（后端也不写 team_members.workgroups）。
    account: Optional[str] = None   # 配套登录账号（username），可空=不开通
    password: Optional[str] = None  # 开通账号时的密码
    role: str = 'editor'

class TeamUpdateReq(BaseModel):
    name: str
    account: Optional[str] = None   # 变更账号关联：空串=关闭，非空前=开通/绑定
    password: Optional[str] = None
    role: Optional[str] = None

def _norm_workgroups(workgroups):
    """（兼容保留）工作组名归一化。
    成员页面已下线工作组选择入口，workgroups 只由【架构管理】同步写入，
    此函数暂留供旧数据清理/迁移脚本使用。"""
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
        # workgroups 不再由本接口写入 —— 归属统一由【架构管理】的任命同步维护
        dbe('INSERT INTO team_members (name, workgroups) VALUES (?,?)', (name, ''))
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
    # 只改姓名；workgroups 归【架构管理】独占维护，本接口不触碰
    dbe('UPDATE team_members SET name=? WHERE id=?', (name, mid))
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
    # 清理该成员在【架构管理】中的任职记录。
    # org_appointments 虽声明了 ON DELETE CASCADE，但本库未开启
    # PRAGMA foreign_keys（SQLite 默认关闭），级联不会生效 → 必须显式清理，
    # 否则会残留孤儿任职数据。
    dbe('DELETE FROM org_appointments WHERE member_id=?', (mid,))
    dbe('DELETE FROM team_members WHERE id=?', (mid,))
    audit_log(username, client_ip(request), 'member_delete', f'成员 {mname} (id={mid})', f'删除成员' + (f'及关联账号 {acc}' if acc else '') + '，并清理架构管理中的任职记录', 'success')
    return {'ok': True}

# ---------------- API：工作组管理（工作组树形架构） ----------------
def _wg_rows():
    rows = [dict(r) for r in dbq('SELECT id, name, parent_id, leader, function, boards FROM workgroups ORDER BY id')]
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
    """工作组管理：返回树形工作组架构 + 全部看板列表（供板块绑定配置）

    · 普通用户返回其可见看板（与 /api/me 口径一致）；
    · **架构负责人额外能看到「本部门架构下所有看板」**（2026-11-03 用户反馈）：
      部门长/组长需要能给子组绑定本部门架构下的看板，只给「可见的」不够用。
      这里的看板列表**仅用于【架构管理】的绑定勾选池**，
      不改变 /api/me 的 boards，也不改变任何读接口的可见性口径。
    """
    all_boards = _all_boards()
    visible, _cols = user_allowed(username)
    if visible is not None:
        all_boards = [b for b in all_boards if b['board_id'] in visible]
    # 架构负责人：补上「管辖范围内」的看板（自己负责的节点 + 其后代所绑定的看板）
    if not is_admin(username):
        scope = _arch_scope_nodes(dbq, username)
        if scope:
            owned = _dept_owned_boards()
            wg_by_id = {r['id']: dict(r) for r in dbq('SELECT id, boards FROM workgroups')}
            nmap = _org_node_map()
            extra = set()
            for nid in scope:
                node = nmap.get(nid)
                if node:
                    extra |= _node_arch_boards(node, owned=owned, wg_by_id=wg_by_id, nmap=nmap)
            if extra:
                _known = {b['board_id'] for b in all_boards}
                all_boards = all_boards + [b for b in _all_boards()
                                           if b['board_id'] in extra and b['board_id'] not in _known]
    # 绑定候选口径（2026-11-04）：非管理员在绑定勾选池里只能看到/选择
    # **自己是负责人或参与人**的看板（加上各节点已绑定的，见前端保底）。
    # 这里把「我的可绑看板」并进 all_boards（负责人不放大可见性 → 可能不在可见集里，
    # 但绑定操作需要能选到它）；bindable_board_ids 供前端过滤勾选池。
    bindable_ids = None
    binding_scope = 'admin'
    if not is_admin(username):
        base = _my_bindable_boards(username)
        binding_scope = 'own'
        # 架构负责人（中心负责人/总经理）：候选池并入**管辖架构下全部看板**（宽池）
        arows = dbq("SELECT a.node_id FROM org_appointments a"
                    " JOIN team_members m ON m.id=a.member_id"
                    " WHERE m.account=? AND a.role_key IN ('center_head','gm')",
                    (username,))
        if arows:
            binding_scope = 'arch'
            owned = _dept_owned_boards()
            wg_by_id = {r['id']: dict(r) for r in dbq('SELECT id, boards FROM workgroups')}
            nmap = _org_node_map()
            kids = defaultdict(list)
            for r in dbq('SELECT id, parent_id FROM org_nodes'):
                kids[r['parent_id']].append(r['id'])
            aroots, stack = set(), [r['node_id'] for r in arows]
            while stack:
                nid = stack.pop()
                if nid in aroots:
                    continue
                aroots.add(nid)
                stack.extend(kids.get(nid, []))
            for nid in aroots:
                node = nmap.get(nid)
                if node:
                    base |= _node_arch_boards(node, owned=owned, wg_by_id=wg_by_id, nmap=nmap)
        bindable_ids = sorted(base)
        _known = {b['board_id'] for b in all_boards}
        all_boards = all_boards + [b for b in _all_boards()
                                   if b['board_id'] in set(bindable_ids)
                                   and b['board_id'] not in _known]
    return {'groups': _wg_tree(_wg_rows()), 'all_boards': all_boards,
            'bindable_board_ids': bindable_ids, 'binding_scope': binding_scope}

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
        dbe('INSERT INTO workgroups (name, parent_id, leader, function, boards) VALUES (?,?,?,?,?)',
            (name, req.parent_id, req.leader.strip(), req.function.strip(), boards))
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
    dbe('UPDATE workgroups SET name=?, parent_id=?, leader=?, function=?, boards=? WHERE id=?',
        (name, req.parent_id, req.leader.strip(), req.function.strip(), boards, gid))
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


# ================================================================
# ---------------- API：组织架构（新模型） ----------------
#
# 三层实体：
#   org_nodes        架构节点（中心 / 部门 / 常规小组 / 专项小组）
#   org_roles        岗位定义（节点类型 → 可设岗位，唯一槽位 vs 可多人）
#   org_appointments 任职关系（人 × 节点 × 岗位，支持一人多岗、多组织任职）
#
# 层级规则（_check_parent_ok）：
#   center  → parent_id 必须为 0，且全局唯一
#   dept    → parent 必须是 center
#   group   → parent 必须是 dept
#   special → parent 可以是 center 或 dept（跨部门专项组）
#
# 角色唯一性：
#   unique_slot=1 的岗位（中心负责人/总经理/部门长/组长）在节点内至多一人，
#   由 DB 的 partial unique index ux_org_unique_slot 强制兜底，
#   应用层再校验一次给出友好错误（DB 报错是英文）。
#
# 多重归属：
#   org_appointments 是 (node_id, member_id, role_key) 的组合，
#   同一人可在多个节点任职（多组织），也可在同一节点兼任多个岗位（一人多岗）。
# ================================================================
ORG_TYPES = ('center', 'dept', 'group', 'special')
ORG_TYPE_NAMES = {'center': '中心', 'dept': '部门', 'group': '常规小组', 'special': '专项小组'}
# 各节点类型允许的**父节点类型**
#   center  → 无父（parent_id=0）
#   dept    → center
#   group   → dept
#   special → center / dept（专项组可挂中心或部门，跨部门协作）
ORG_PARENT_RULES = {
    'center':  set(),
    'dept':    {'center'},
    'group':   {'dept'},
    'special': {'center', 'dept'},
}
# 父节点类型 → 该父节点下允许挂的子节点类型（用于「父级视角」的提示与校验）
ORG_CHILD_RULES = {
    'center':  {'dept', 'special'},
    'dept':    {'group', 'special'},
    'group':   set(),
    'special': set(),
}

def _binding_manager_nodes(username: str) -> set:
    """绑定管理员节点集（2026-11-04 用户需求）：

    看板绑定操作的执行角色 = **部门长 或 小组组长**（管理员另行放行）。
    判定 = 担任 dept_head / group_leader 的节点**及其全部后代**
    （部门长管理本部门架构下 —— 与 2026-11-03「本部门架构下所有看板」口径一致；
    小组组长只管自己那一级）。中心负责人/总经理等其它岗位**不含**在内。
    """
    rows = dbq("""SELECT a.node_id FROM org_appointments a
                  JOIN team_members m ON m.id=a.member_id
                  WHERE m.account=? AND a.role_key IN ('dept_head','group_leader')""",
               (username,))
    if not rows:
        return set()
    kids = defaultdict(list)
    for r in dbq('SELECT id, parent_id FROM org_nodes'):
        kids[r['parent_id']].append(r['id'])
    out, stack = set(), [r['node_id'] for r in rows]
    while stack:
        nid = stack.pop()
        if nid in out:
            continue
        out.add(nid)
        stack.extend(kids.get(nid, []))
    return out


def _my_bindable_boards(username: str) -> set:
    """我可作为绑定候选的看板（2026-11-04 用户需求）：

    = 我是**负责人**（boards.owner）或**参与人**（该看板下任一板块的
    board_columns.participants 含我的账号）。看板级参与人机制已下线（2026-11-02），
    此处「参与人」取板块参与人 —— 与板块编辑弹窗里的负责人/参与人配置同源。
    ⚠️ 只约束「绑定看板」这一操作，不影响看板展示/编辑权限体系（二者独立）。
    """
    out = {r['board_id'] for r in
           dbq('SELECT board_id FROM boards WHERE owner=? AND owner<>?', (username, ''))}
    for r in dbq("SELECT board_id, participants FROM board_columns"
                 " WHERE participants IS NOT NULL AND participants<>''"):
        if username in [x.strip() for x in (r['participants'] or '').split(',')]:
            out.add(r['board_id'])
    return out


def _arch_owner_nodes(username: str) -> set:
    """架构负责人节点集（2026-11-04 用户修订）：

    担任 **中心负责人(center_head) / 总经理(gm)** 的节点及其全部后代。
    架构负责人对**管辖架构下的全部看板**拥有绑定权（不受「负责人/参与人」
    候选池限制）。部门长/组长的窄口径（只能绑自己是负责人/参与人的看板）
    见 _binding_manager_nodes —— 两者互不覆盖，一人兼多岗时取并集。
    """
    rows = dbq("""SELECT a.node_id FROM org_appointments a
                  JOIN team_members m ON m.id=a.member_id
                  WHERE m.account=? AND a.role_key IN ('center_head','gm')""",
               (username,))
    if not rows:
        return set()
    kids = defaultdict(list)
    for r in dbq('SELECT id, parent_id FROM org_nodes'):
        kids[r['parent_id']].append(r['id'])
    out, stack = set(), [r['node_id'] for r in rows]
    while stack:
        nid = stack.pop()
        if nid in out:
            continue
        out.add(nid)
        stack.extend(kids.get(nid, []))
    return out


def _org_node(node_id: int):
    rows = dbq('SELECT id, name, node_type, parent_id, wg_id, is_anchor, function'
               ' FROM org_nodes WHERE id=?', (node_id,))
    return dict(rows[0]) if rows else None

def _org_role_defs(node_type: str):
    """该节点类型可设的岗位清单 [{role_key, role_name, unique_slot}]"""
    return [dict(r) for r in dbq(
        'SELECT role_key, role_name, unique_slot FROM org_roles WHERE node_type=? ORDER BY sort, id',
        (node_type,))]

def _org_appointments_of(node_id: int):
    """节点的任职明细（含成员姓名与岗位显示名）"""
    rows = dbq('''SELECT a.id, a.node_id, a.member_id, a.role_key, a.is_primary,
                         m.name AS member_name, m.account,
                         COALESCE(r.role_name, a.role_key) AS role_name
                  FROM org_appointments a
                  JOIN team_members m ON m.id = a.member_id
                  LEFT JOIN org_nodes n ON n.id = a.node_id
                  LEFT JOIN org_roles r ON r.node_type = n.node_type AND r.role_key = a.role_key
                  WHERE a.node_id=? ORDER BY a.role_key, m.name''', (node_id,))
    out = []
    for r in rows:
        d = dict(r)
        d['is_primary'] = 1 if d.get('is_primary') else 0
        out.append(d)
    return out

def _org_node_descendants(node_id: int, rows=None):
    """返回 node_id 的全部后代 id 集合（不含自身）"""
    if rows is None:
        rows = [dict(r) for r in dbq('SELECT id, parent_id FROM org_nodes')]
    children = defaultdict(list)
    for r in rows:
        children[r['parent_id']].append(r['id'])
    out = set()
    stack = list(children.get(node_id, []))
    while stack:
        cur = stack.pop()
        if cur in out:
            continue
        out.add(cur)
        stack.extend(children.get(cur, []))
    return out

def _check_parent_ok(node_type: str, parent_id: int, self_id: int = 0):
    """层级完整性校验：
       1) 父节点类型必须在该节点类型的允许集合内（ORG_PARENT_RULES）
       2) 父节点必须存在
       3) 不能挂到自己的后代下（防环）
       4) center 全局唯一
    """
    if node_type not in ORG_TYPES:
        raise HTTPException(400, f'节点类型必须是 {"/".join(ORG_TYPES)} 之一')
    allowed = ORG_PARENT_RULES[node_type]
    # center 是顶级节点：parent_id 必须为 0
    if node_type == 'center':
        if parent_id:
            raise HTTPException(400, '中心是顶级节点，不能有上级')
    else:
        if not parent_id:
            hint = '、'.join(ORG_TYPE_NAMES[t] for t in sorted(allowed))
            raise HTTPException(400, f'{ORG_TYPE_NAMES[node_type]}必须挂在「{hint}」下')
        p = _org_node(parent_id)
        if not p:
            raise HTTPException(404, '上级节点不存在')
        if p['node_type'] not in allowed:
            can = '、'.join(ORG_TYPE_NAMES[t] for t in sorted(allowed))
            raise HTTPException(400, f'{ORG_TYPE_NAMES[node_type]}只能挂在「{can}」下，'
                                    f'「{p["name"]}」是{ORG_TYPE_NAMES.get(p["node_type"], p["node_type"])}')
        if self_id and parent_id == self_id:
            raise HTTPException(400, '上级节点不能是自身')
        if self_id:
            rows = [dict(r) for r in dbq('SELECT id, parent_id FROM org_nodes')]
            if parent_id in _org_node_descendants(self_id, rows):
                raise HTTPException(400, '上级节点不能是自己的下级（会造成层级环）')
    # center 全局唯一
    if node_type == 'center':
        others = dbq('SELECT id FROM org_nodes WHERE node_type=? AND id!=?', ('center', self_id or 0))
        if others:
            raise HTTPException(409, '中心节点全局只能有一个')

def _check_role_allowed(node_type: str, role_key: str):
    """岗位必须在该节点类型的岗位清单内"""
    defs = _org_role_defs(node_type)
    if not any(d['role_key'] == role_key for d in defs):
        names = '、'.join(d['role_name'] for d in defs) or '（未配置）'
        raise HTTPException(400, f'「{ORG_TYPE_NAMES.get(node_type, node_type)}」不可设置该岗位；'
                                f'可用岗位：{names}')

def _check_unique_slot(node_id: int, role_key: str, member_id: int, exclude_id: int = 0):
    """唯一槽位岗位校验（节点内至多一人），给出友好错误"""
    defs = _org_role_defs(_org_node(node_id)['node_type'])
    d = next((x for x in defs if x['role_key'] == role_key), None)
    if not d or not d['unique_slot']:
        return
    rows = dbq('SELECT a.id, m.name FROM org_appointments a JOIN team_members m ON m.id=a.member_id'
               ' WHERE a.node_id=? AND a.role_key=? AND a.member_id!=? AND a.id!=?',
               (node_id, role_key, member_id, exclude_id))
    if rows:
        raise HTTPException(409, f'「{d["role_name"]}」在一个节点内只能有一人，'
                                f'当前已由 {rows[0]["name"]} 担任')

def _org_sync_legacy(node_id: int):
    """把新模型的任职关系回写到旧表 workgroups.leader 与 team_members.workgroups。
    旧权限逻辑（_leader_boards / _group_boards）读的是这两个字段，
    回写保证新旧模型在权限判定上完全一致。"""
    node = _org_node(node_id)
    if not node:
        return
    # 1) leader：取该节点的唯一槽位岗位任职人（组长/部门长/中心负责人）
    leader = ''
    rows = dbq('''SELECT m.name FROM org_appointments a
                  JOIN team_members m ON m.id=a.member_id
                  WHERE a.node_id=? AND a.role_key IN ('group_leader','dept_head','center_head','gm')
                  ORDER BY CASE a.role_key WHEN 'center_head' THEN 0 WHEN 'dept_head' THEN 1
                                           WHEN 'gm' THEN 2 ELSE 3 END LIMIT 1''', (node_id,))
    if rows:
        leader = rows[0]['name']
    wg_id = node.get('wg_id') or 0
    if wg_id:
        dbe('UPDATE workgroups SET leader=? WHERE id=?', (leader, wg_id))
    # 2) team_members.workgroups：把「组员/骨干」任职回写成分号串
    #    仅回写常规小组/专项小组节点（与旧语义一致：成员归属到组，部门靠父链传导）
    if node['node_type'] in ('group', 'special'):
        for m in dbq('''SELECT a.member_id, t.name FROM org_appointments a
                        JOIN team_members t ON t.id=a.member_id
                        WHERE a.node_id=? AND a.role_key IN ('member','dept_backbone','center_backbone')''',
                     (node_id,)):
            row = dbq('SELECT workgroups FROM team_members WHERE id=?', (m['member_id'],))
            if not row:
                continue
            gs = [x.strip() for x in (row[0]['workgroups'] or '').split(';') if x.strip()]
            if node['name'] not in gs:
                gs.append(node['name'])
                dbe('UPDATE team_members SET workgroups=? WHERE id=?', (';'.join(gs), m['member_id']))

def _org_sync_member_legacy(member_id: int):
    """成员侧回写：移除某成员在指定节点的全部任职时，同步清理 workgroups 串"""
    rows = dbq('''SELECT n.name FROM org_appointments a JOIN org_nodes n ON n.id=a.node_id
                  WHERE a.member_id=? AND n.node_type IN ('group','special')''', (member_id,))
    names = set(r['name'] for r in rows)
    row = dbq('SELECT workgroups FROM team_members WHERE id=?', (member_id,))
    if not row:
        return
    gs = [x.strip() for x in (row[0]['workgroups'] or '').split(';') if x.strip()]
    keep = [g for g in gs if g not in names]
    if keep != gs:
        dbe('UPDATE team_members SET workgroups=? WHERE id=?', (';'.join(keep), member_id))

class OrgNodeReq(BaseModel):
    name: str
    node_type: str = 'group'
    parent_id: int = 0
    function: str = ''

class OrgAppointmentReq(BaseModel):
    node_id: int
    member_id: int
    role_key: str
    is_primary: int = 0

def _collect_node_members(node_id: int, nodes, appts):
    """节点（含全部后代）的末级人员名单。

    返回 [{name, role_name, node_name, node_id}]，按姓名去重（同名人员在不同节点各占一项）。
    「末级人员」= 该节点及其后代节点上所有任职人 —— 树形组件在节点下追加人员层时使用。

    ⚠️ `node_id` = 该人员**实际任职所在**的节点 id。
    前端树形组件据此把人员挂到「真正所属的那个节点」下，
    否则父节点的成员表（含全部后代）会与子节点的成员表重复 —— 同一批人
    在树上出现两次（父节点一份、子节点一份），看起来就是「树状展开异常」。
    """
    by_parent = defaultdict(list)
    for n in nodes:
        by_parent[n['parent_id']].append(n)
    name_by_id = {n['id']: n['name'] for n in nodes}
    out = []
    seen = set()
    stack = [node_id]
    while stack:
        cur = stack.pop()
        for a in appts.get(cur, []):
            nm = a.get('member_name') or ''
            if not nm or nm in seen:
                continue          # 同一人只在最靠近的节点出现一次，避免父节点重复列出
            seen.add(nm)
            out.append({'name': nm,
                        'role_name': a.get('role_name') or '',
                        'node_name': name_by_id.get(cur, ''),
                        'node_id': cur})
        # by_parent 的 value 是节点 dict 列表，这里要的是**节点 id**
        stack.extend(child['id'] for child in by_parent.get(cur, []))
    out.sort(key=lambda x: (x['node_name'], x['name']))
    return out


@app.get('/api/org/tree')
def get_org_tree(username: str = Depends(require_auth)):
    """组织架构树：节点 + 类型 + 岗位定义 + 任职明细（含多归属标记）"""
    nodes = [dict(r) for r in dbq(
        'SELECT id, name, node_type, parent_id, wg_id, is_anchor, function'
        ' FROM org_nodes ORDER BY sort, id')]
    node_type_of = {n['id']: n['node_type'] for n in nodes}
    # 每节点的岗位清单
    roles_by_type = {}
    for r in dbq('SELECT node_type, role_key, role_name, unique_slot, sort FROM org_roles ORDER BY sort, id'):
        roles_by_type.setdefault(r['node_type'], []).append(
            {'role_key': r['role_key'], 'role_name': r['role_name'], 'unique_slot': r['unique_slot']})
    # 全部任职（按节点分组）
    appts = {}
    role_names = {}
    for r in dbq('SELECT node_type, role_key, role_name FROM org_roles'):
        role_names[(r['node_type'], r['role_key'])] = r['role_name']
    for r in dbq('''SELECT a.id, a.node_id, a.member_id, a.role_key, a.is_primary,
                           m.name AS member_name, m.account
                    FROM org_appointments a JOIN team_members m ON m.id=a.member_id
                    ORDER BY m.name'''):
        d = dict(r)
        d['is_primary'] = 1 if d.get('is_primary') else 0
        d['role_name'] = role_names.get((node_type_of.get(d['node_id'], ''), d['role_key']), d['role_key'])
        appts.setdefault(d['node_id'], []).append(d)
    # 成员的任职总数（用于「多归属」提示）
    member_nodes = defaultdict(set)
    for nid, lst in appts.items():
        for a in lst:
            member_nodes[a['member_id']].add(nid)
    for nid, lst in appts.items():
        for a in lst:
            a['other_org_count'] = len(member_nodes[a['member_id']]) - 1
    by_parent = defaultdict(list)
    for n in nodes:
        by_parent[n['parent_id']].append(n)
    # 归属部门拥有的板块（看板管理 → 架构管理的联动）
    owned = _dept_owned_boards()
    # 预取工作组绑定与节点映射（算「架构下所有看板」用，避免逐节点查库）
    wg_by_id = {r['id']: dict(r) for r in dbq('SELECT id, boards FROM workgroups')}
    nmap = _org_node_map()
    # 普通用户只看到自己可见的看板（与 /api/me 口径一致）
    visible, _cols = user_allowed(username)
    if visible is not None:
        owned = {nid: {b for b in bs if b in visible} for nid, bs in owned.items()}

    # 逐节点能力位（2026-11-03，2026-11-04 修订绑定口径）：
    #   can_config_bind → 能否在本节点**执行看板绑定**：
    #     管理员，或 部门长/小组组长（在本节点或其祖先任职 → 管辖本节点）。
    #     ⚠️ 架构负责人若非部门长/组长 → 不可绑定（只能查看）。
    #   can_manage_node → 能否增删改本节点（仅管理员）
    scope = set() if is_admin(username) else _arch_scope_nodes(dbq, username)
    leader_ids = set() if is_admin(username) else _arch_leader_nodes(dbq, username)
    bind_mgr = set() if is_admin(username) else _binding_manager_nodes(username)
    # 架构负责人（中心负责人/总经理）：管辖架构下全部节点可绑（2026-11-04 用户修订）
    arch_owner = set() if is_admin(username) else _arch_owner_nodes(username)

    def build(pid):
        out = []
        for n in by_parent.get(pid, []):
            node = dict(n)
            node['type_name'] = ORG_TYPE_NAMES.get(n['node_type'], n['node_type'])
            node['roles'] = roles_by_type.get(n['node_type'], [])
            node['appointments'] = appts.get(n['id'], [])
            node['owned_boards'] = sorted(owned.get(n['id'], set()))
            # 能力位
            in_scope = n['id'] in scope
            node['can_config_bind'] = bool(is_admin(username) or n['id'] in bind_mgr
                                           or n['id'] in arch_owner)
            node['can_manage_node'] = bool(is_admin(username))
            node['is_leader'] = (n['id'] in leader_ids)
            node['in_my_scope'] = bool(in_scope)
            # 「架构下所有看板」（2026-11-03）：本节点归属的 + 全部后代小组已绑定的。
            # → 部门长/组长在板块绑定里能看到本部门架构下的全部看板。
            _arch_boards = sorted(_node_arch_boards(n, owned=owned, wg_by_id=wg_by_id, nmap=nmap))
            node['arch_boards'] = _arch_boards
            # 可勾选池：架构下所有看板 ∪ 自身已绑定（小组节点自身绑定不在 arch_boards 时也保底）
            node['bindable_boards'] = sorted(set(_arch_boards) | set(_node_bound_boards(
                n, owned=owned, wg_by_id=wg_by_id)))
            # 该节点的末级人员名单（姓名 + 岗位），供前端树形组件渲染「人员」层。
            # 取该节点的任职人 + 其所有后代节点的任职人（末级=最深层的实际人员）。
            node['members'] = _collect_node_members(n['id'], nodes, appts)
            node['children'] = build(n['id'])
            out.append(node)
        return out

    return {'tree': build(0), 'roles_by_type': roles_by_type,
            'type_names': ORG_TYPE_NAMES}

@app.post('/api/org/nodes')
def create_org_node(req: OrgNodeReq, username: str = Depends(require_admin), request: Request = None):
    """新增架构节点（中心/部门/常规小组/专项小组）"""
    name = (req.name or '').strip()
    if not name:
        raise HTTPException(400, '节点名称不能为空')
    node_type = (req.node_type or '').strip()
    _check_parent_ok(node_type, req.parent_id)
    if dbq('SELECT 1 FROM org_nodes WHERE parent_id=? AND name=?', (req.parent_id, name)):
        raise HTTPException(409, f'同级下已存在同名节点「{name}」')
    cur = dbe('INSERT INTO org_nodes (name, node_type, parent_id, function)'
              ' VALUES (?,?,?,?)',
              (name, node_type, req.parent_id, (req.function or '').strip()))
    nid = cur.lastrowid
    # 同步旧表 workgroups（保持旧权限逻辑可见）
    pid = req.parent_id
    pwg = dbq('SELECT wg_id FROM org_nodes WHERE id=?', (pid,)) if pid else []
    parent_wg = pwg[0]['wg_id'] if pwg and pwg[0]['wg_id'] else 0
    if node_type == 'center':
        w = dbe('INSERT INTO workgroups (name, parent_id) VALUES (?,0)', (name,))
    else:
        w = dbe('INSERT INTO workgroups (name, parent_id) VALUES (?,?)', (name, parent_wg))
    dbe('UPDATE org_nodes SET wg_id=? WHERE id=?', (w.lastrowid, nid))
    audit_log(username, client_ip(request), 'org_node_create',
              f'节点 {name}（{ORG_TYPE_NAMES.get(node_type, node_type)}）',
              f'新增架构节点，id={nid}，上级 id={req.parent_id}', 'success')
    return {'ok': True, 'id': nid}

@app.put('/api/org/nodes/{nid}')
def update_org_node(nid: int, req: OrgNodeReq, username: str = Depends(require_admin), request: Request = None):
    """修改节点：名称 / 类型 / 上级。
       改类型或上级时会校验子节点是否仍满足层级规则（层级完整性）。"""
    node = _org_node(nid)
    if not node:
        raise HTTPException(404, '节点不存在')
    name = (req.name or '').strip()
    if not name:
        raise HTTPException(400, '节点名称不能为空')
    node_type = (req.node_type or node['node_type']).strip()
    parent_id = req.parent_id
    _check_parent_ok(node_type, parent_id, self_id=nid)
    if dbq('SELECT 1 FROM org_nodes WHERE parent_id=? AND name=? AND id!=?', (parent_id, name, nid)):
        raise HTTPException(409, f'同级下已存在同名节点「{name}」')
    # 子节点类型约束：改类型后，子节点的上级类型必须仍被允许
    kids = dbq('SELECT id, name, node_type FROM org_nodes WHERE parent_id=?', (nid,))
    for k in kids:
        if node_type not in ORG_PARENT_RULES.get(k['node_type'], set()):
            raise HTTPException(400, f'子节点「{k["name"]}」的类型（{ORG_TYPE_NAMES.get(k["node_type"], k["node_type"])}）'
                                    f'不允许挂在「{ORG_TYPE_NAMES.get(node_type, node_type)}」下，'
                                    f'请先调整子节点')
    dbe('UPDATE org_nodes SET name=?, node_type=?, parent_id=?, function=? WHERE id=?',
        (name, node_type, parent_id, (req.function or '').strip(), nid))
    # 同步旧表
    if node.get('wg_id'):
        pwg = dbq('SELECT wg_id FROM org_nodes WHERE id=?', (parent_id,)) if parent_id else []
        parent_wg = pwg[0]['wg_id'] if pwg and pwg[0]['wg_id'] else 0
        dbe('UPDATE workgroups SET name=?, parent_id=? WHERE id=?', (name, parent_wg, node['wg_id']))
    audit_log(username, client_ip(request), 'org_node_update',
              f'节点 {name} (id={nid})', '更新架构节点', 'success')
    return {'ok': True}

class NodeBoardsReq(BaseModel):
    """看板绑定专项请求（2026-11-04）：boards = 逗号分隔看板 id；空串 = 清空绑定。"""
    boards: str = ''


@app.put('/api/org/nodes/{nid}/boards')
def update_node_boards(nid: int, req: NodeBoardsReq, username: str = Depends(require_writer),
                       request: Request = None):
    """看板绑定（专项接口，2026-11-04 用户需求）：

    · 权限：管理员，或 **部门长/小组组长**（在本节点或其祖先任职 → 管辖本节点）。
      架构负责人若非部门长/组长 → 403。
    · 非管理员的**新增绑定**只能选自己是负责人（boards.owner）或参与人
      （板块参与人）的看板；已有绑定保持不变（可解除，解除也是绑定操作）。
    · 仅约束「绑定看板」这一操作，**不影响**看板展示/编辑权限体系。
    · 结构（名称/类型/上级）仍走 PUT /api/org/nodes/{nid}（require_admin）。
    """
    node = _org_node(nid)
    if not node:
        raise HTTPException(404, '节点不存在')
    if node['node_type'] == 'center':
        raise HTTPException(403, '中心节点锁定全部看板，不可在此调整绑定')
    if not node.get('wg_id'):
        raise HTTPException(400, '该节点没有可存储绑定的载体（缺少工作组映射）')
    arch_owner = set() if is_admin(username) else _arch_owner_nodes(username)
    if not is_admin(username):
        if nid not in _binding_manager_nodes(username) and nid not in arch_owner:
            raise HTTPException(403, '仅管理员、架构负责人或该节点的部门长/小组组长可修改看板绑定')
    wg_row = dbq('SELECT boards FROM workgroups WHERE id=?', (node['wg_id'],))
    existing = set(x for x in ((wg_row[0]['boards'] if wg_row else '') or '').split(',') if x)
    boards = _norm_boards(req.boards)
    newset = set(x for x in boards.split(',') if x)
    # 「负责人/参与人」候选池限制只约束**部门长/组长**（2026-11-04 用户修订）：
    # 架构负责人可绑管辖架构下全部看板（宽池豁免）。
    if not is_admin(username) and nid not in arch_owner:
        added = newset - existing
        if added:
            illegal = sorted(added - _my_bindable_boards(username))
            if illegal:
                raise HTTPException(403, '只能绑定你是负责人或参与人的看板：' + '、'.join(illegal))
    # ⚠️ _check_child_boards 收的是 **workgroups.id**（旧表键空间）——
    #    org_nodes.parent_id 必须先映射到父节点的 wg_id（与 update_org_node 同款）。
    _prow = dbq('SELECT wg_id FROM org_nodes WHERE id=?', (node['parent_id'],))
    _pwg = _prow[0]['wg_id'] if _prow and _prow[0]['wg_id'] else 0
    _check_child_boards(_pwg, boards)
    dbe('UPDATE workgroups SET boards=? WHERE id=?', (boards, node['wg_id']))
    cascade = _cascade_boards(node['wg_id'], boards)
    audit_log(username, client_ip(request), 'org_node_bind', f'节点 {node["name"]} (id={nid})',
              '修改看板绑定 → [' + boards + ']' + (f'；级联调整 {len(cascade)} 个子级' if cascade else ''),
              'success')
    return {'ok': True, 'boards': boards, 'cascade': cascade}


@app.delete('/api/org/nodes/{nid}')
def delete_org_node(nid: int, username: str = Depends(require_admin), request: Request = None):
    """删除节点：级联删除其任职关系与子节点；节点有关联看板时拒绝。"""
    node = _org_node(nid)
    if not node:
        raise HTTPException(404, '节点不存在')
    if node['node_type'] == 'center':
        raise HTTPException(403, '中心节点不可删除')
    # 有看板绑定时拒绝（避免成员突然失去访问权限）
    if node.get('wg_id'):
        w = dbq('SELECT boards FROM workgroups WHERE id=?', (node['wg_id'],))
        if w and (w[0]['boards'] or '').strip():
            raise HTTPException(409, '该节点仍绑定着板块，请先解除板块绑定再删除')
    desc = _org_node_descendants(nid)
    # 先收集受影响成员（删除前），删除后再回写清理
    affected = set()
    for dn in list(desc) + [nid]:
        for r in dbq('SELECT DISTINCT member_id FROM org_appointments WHERE node_id=?', (dn,)):
            affected.add(r['member_id'])
    appt_cnt = 0
    for dn in list(desc) + [nid]:
        appt_cnt += dbq('SELECT COUNT(*) AS c FROM org_appointments WHERE node_id=?', (dn,))[0]['c']
    # 删除子节点（自底向上）与任职关系
    for dn in sorted(desc, reverse=True):
        dbe('DELETE FROM org_appointments WHERE node_id=?', (dn,))
        sub = dbq('SELECT wg_id FROM org_nodes WHERE id=?', (dn,))
        if sub and sub[0]['wg_id']:
            dbe('DELETE FROM workgroups WHERE id=?', (sub[0]['wg_id'],))
        dbe('DELETE FROM org_nodes WHERE id=?', (dn,))
    dbe('DELETE FROM org_appointments WHERE node_id=?', (nid,))
    if node.get('wg_id'):
        dbe('DELETE FROM workgroups WHERE id=?', (node['wg_id'],))
    dbe('DELETE FROM org_nodes WHERE id=?', (nid,))
    # 清理成员侧的旧引用（该成员若已无任何小组任职，其 workgroups 串里对应名称要移除）
    for mid in affected:
        _org_sync_member_legacy(mid)
    audit_log(username, client_ip(request), 'org_node_delete',
              f'节点 {node["name"]} (id={nid})',
              f'删除架构节点，级联清理 {len(desc)} 个子节点、{appt_cnt} 条任职关系', 'success')
    return {'ok': True, 'removed_children': len(desc), 'removed_appointments': appt_cnt}

class OrgMoveNodeReq(BaseModel):
    """移动节点只需目标上级；名称/类型不变"""
    parent_id: int

@app.post('/api/org/nodes/{nid}/move')
def move_org_node(nid: int, req: OrgMoveNodeReq, username: str = Depends(require_admin), request: Request = None):
    """移动节点（换上级）：跨部门组 / 调整层级。
       校验：目标上级类型合法、不成环、子节点类型仍兼容。"""
    node = _org_node(nid)
    if not node:
        raise HTTPException(404, '节点不存在')
    if node['node_type'] == 'center':
        raise HTTPException(403, '中心节点不可移动')
    new_parent = req.parent_id
    _check_parent_ok(node['node_type'], new_parent, self_id=nid)
    kids = dbq('SELECT id, name, node_type FROM org_nodes WHERE parent_id=?', (nid,))
    for k in kids:
        if node['node_type'] not in ORG_PARENT_RULES.get(k['node_type'], set()):
            raise HTTPException(400, f'子节点「{k["name"]}」的类型不允许挂在目标上级下，'
                                    f'请先调整子节点')
    dbe('UPDATE org_nodes SET parent_id=? WHERE id=?', (new_parent, nid))
    if node.get('wg_id'):
        pwg = dbq('SELECT wg_id FROM org_nodes WHERE id=?', (new_parent,)) if new_parent else []
        parent_wg = pwg[0]['wg_id'] if pwg and pwg[0]['wg_id'] else 0
        dbe('UPDATE workgroups SET parent_id=? WHERE id=?', (parent_wg, node['wg_id']))
    audit_log(username, client_ip(request), 'org_node_move',
              f'节点 {node["name"]} (id={nid})', f'移动到上级 id={new_parent}', 'success')
    return {'ok': True}

@app.post('/api/org/appointments')
def create_org_appointment(req: OrgAppointmentReq, username: str = Depends(require_admin), request: Request = None):
    """新增任职关系：一人多岗 / 一人多组织。
       校验：节点存在、成员存在、岗位属于该节点类型、唯一槽位不被占。"""
    node = _org_node(req.node_id)
    if not node:
        raise HTTPException(404, '节点不存在')
    m = dbq('SELECT id, name FROM team_members WHERE id=?', (req.member_id,))
    if not m:
        raise HTTPException(404, '成员不存在')
    role_key = (req.role_key or '').strip()
    _check_role_allowed(node['node_type'], role_key)
    _check_unique_slot(req.node_id, role_key, req.member_id)
    try:
        dbe('INSERT INTO org_appointments (node_id, member_id, role_key, is_primary) VALUES (?,?,?,?)',
            (req.node_id, req.member_id, role_key, 1 if req.is_primary else 0))
    except sqlite3.IntegrityError:
        raise HTTPException(409, '该成员在此节点已有该岗位')
    _org_sync_legacy(req.node_id)
    audit_log(username, client_ip(request), 'org_appointment_create',
              f'{m[0]["name"]} @ {node["name"]}',
              f'新增任职，岗位 {role_key}', 'success')
    return {'ok': True}

@app.delete('/api/org/appointments/{aid}')
def delete_org_appointment(aid: int, username: str = Depends(require_admin), request: Request = None):
    """删除任职关系"""
    row = dbq('''SELECT a.id, a.node_id, a.member_id, a.role_key, m.name AS member_name
                 FROM org_appointments a JOIN team_members m ON m.id=a.member_id WHERE a.id=?''', (aid,))
    if not row:
        raise HTTPException(404, '任职关系不存在')
    dbe('DELETE FROM org_appointments WHERE id=?', (aid,))
    _org_sync_legacy(row[0]['node_id'])
    _org_sync_member_legacy(row[0]['member_id'])
    audit_log(username, client_ip(request), 'org_appointment_delete',
              f'{row[0]["member_name"]}', '删除任职关系', 'success')
    return {'ok': True}

@app.get('/api/org/members/{member_id}/appointments')
def get_member_appointments(member_id: int, username: str = Depends(require_auth)):
    """某人的全部任职（多归属视图）：横跨哪些节点、担任什么岗位"""
    rows = dbq('''SELECT a.id, a.node_id, a.role_key, a.is_primary, r.role_name, r.unique_slot,
                         n.name AS node_name, n.node_type
                  FROM org_appointments a
                  JOIN org_nodes n ON n.id=a.node_id
                  LEFT JOIN org_roles r ON r.node_type=n.node_type AND r.role_key=a.role_key
                  WHERE a.member_id=? ORDER BY n.id, a.role_key''', (member_id,))
    out = []
    for r in rows:
        d = dict(r)
        d['is_primary'] = 1 if d.get('is_primary') else 0
        d['type_name'] = ORG_TYPE_NAMES.get(d['node_type'], d['node_type'])
        out.append(d)
    return {'appointments': out}

class OrgMoveApptReq(BaseModel):
    appt_id: int
    node_id: int = 0        # 0=不换节点
    role_key: str = ''      # 空=不换岗位

@app.post('/api/org/appointments/move')
def move_org_appointment(req: OrgMoveApptReq, username: str = Depends(require_admin), request: Request = None):
    """调整任职：换节点（一人多组织的维护入口）或换岗位。
       校验与新增一致：目标节点类型允许该岗位、唯一槽位未被他人占用。"""
    row = dbq('''SELECT a.id, a.node_id, a.member_id, a.role_key, m.name AS member_name
                 FROM org_appointments a JOIN team_members m ON m.id=a.member_id WHERE a.id=?''',
               (req.appt_id,))
    if not row:
        raise HTTPException(404, '任职关系不存在')
    old_node = row[0]['node_id']
    new_node = req.node_id or old_node
    new_role = (req.role_key or '').strip() or row[0]['role_key']
    node = _org_node(new_node)
    if not node:
        raise HTTPException(404, '目标节点不存在')
    _check_role_allowed(node['node_type'], new_role)
    _check_unique_slot(new_node, new_role, row[0]['member_id'], exclude_id=req.appt_id)
    try:
        dbe('UPDATE org_appointments SET node_id=?, role_key=? WHERE id=?',
            (new_node, new_role, req.appt_id))
    except sqlite3.IntegrityError:
        raise HTTPException(409, '该成员在目标节点已有该岗位')
    _org_sync_legacy(old_node)
    _org_sync_legacy(new_node)
    _org_sync_member_legacy(row[0]['member_id'])
    audit_log(username, client_ip(request), 'org_appointment_move',
              f'{row[0]["member_name"]}',
              f'任职调整：节点 {old_node} → {new_node}，岗位 {row[0]["role_key"]} → {new_role}', 'success')
    return {'ok': True}


# ---------------- API：看板管理（配置板块：年份/归属部门/属性/状态） ----------------
# 枚举可选值（与 DB CHECK 约束保持一致，应用层二次校验，越界即 400）
# 部门的**有序**列表：目录树按此顺序渲染顶层部门节点（空部门同样占位）。
# 实际可选部门以【架构管理】的部门层级为准（_dept_names()/_dept_order()），
# 这里的固定清单仅作为架构为空时的历史回退。
DEPT_ORDER = ['财务中心', '核算部', '总账部', '管理部', '资金部', '商务部']
ALLOWED_DEPTS = set(DEPT_ORDER)
ALLOWED_ATTRS = {'日常', '专项'}
ALLOWED_STATUSES = {'启用', '封存'}

class BoardConfigReq(BaseModel):
    """看板配置：**不再含归属年份** —— 年份已下沉到【板块】层（board_columns.year）。

    每个板块绑定唯一归属年份；看板只是板块的容器，
    一个看板下的不同板块可以属于不同年份。
    """
    board_id: str = ''      # 关联的真实看板 id（boards ∪ cards 派生的 board_id）
    dept: str              # 归属部门名称（须是架构中的中心/部门）
    dept_node_id: int = 0  # 归属部门对应的 org_nodes.id（0=未指定，按名称解析）
    attr: str
    status: str = '启用'
    remark: str = ''

def _resolve_dept_node(dept, dept_node_id=0):
    """归属部门 → 架构节点。优先按 dept_node_id 解析，其次按名称解析。

    返回 (node_id, name, is_center)。找不到对应部门节点时返回 (0, dept, 0)，
    由调用方决定是否放行（历史数据里可能存在已删除的部门名）。
    """
    kinds = ('center', 'dept')
    if dept_node_id:
        row = dbq('SELECT id, name, node_type FROM org_nodes WHERE id=? AND node_type IN (?,?)',
                  (dept_node_id,) + kinds)
        if row:
            return row[0]['id'], row[0]['name'], 1 if row[0]['node_type'] == 'center' else 0
    name = (dept or '').strip()
    if name:
        row = dbq('SELECT id, name, node_type FROM org_nodes WHERE name=? AND node_type IN (?,?)'
                  ' ORDER BY id LIMIT 1', (name,) + kinds)
        if row:
            return row[0]['id'], row[0]['name'], 1 if row[0]['node_type'] == 'center' else 0
    return 0, name, 0

def _validate_board_config(dept, attr, status):
    if dept not in _dept_names():
        raise HTTPException(400, '归属部门必须是架构中的中心或部门，当前可选：'
                            + '/'.join(sorted(_dept_names())))
    if attr not in ALLOWED_ATTRS:
        raise HTTPException(400, '属性必须是 ' + '/'.join(ALLOWED_ATTRS) + ' 之一')
    if status not in ALLOWED_STATUSES:
        raise HTTPException(400, '状态必须是 ' + '/'.join(ALLOWED_STATUSES) + ' 之一')

@app.get('/api/boards')
def list_boards(username: str = Depends(require_auth)):
    """看板管理列表：真实看板（boards ∪ cards 派生）+ 卡片数 + 关联配置。
    看板管理功能直接作用于当前在用的真实看板，通过 board_id 与 board_config 关联。

    可见性：管理员返回全部看板；普通用户只返回其架构授权范围内的看板
    （与 /api/me 的看板集合一致，避免「前端只隐藏、后端仍全量下发」）。

    ⚠️ 看板**不再有归属年份** —— 年份下沉到板块层：
       `col_years` = 该看板下各板块的归属年份集合（去重、倒序），供列表展示
       「所属板块年份」。
    """
    boards = _all_boards()
    visible, cols_perm = user_allowed(username)
    if visible is not None:
        boards = [b for b in boards if b['board_id'] in visible]
    # 【看板管理】列表 = 可见看板 ∪ **可管理看板**（2026-11-03）
    # ⚠️ 原因：负责人 = 管理权，但**不放大可见性** →
    #    若某人只靠「负责人」身份拿到管理权，他负责的看板可能不在可见集里，
    #    列表里就没有它 → 无法配置自己负责的看板。
    #    这里补上**管理范围内**的看板，不改变任何读接口的可见性口径。
    _managed_extra = set()
    if not is_admin(username):
        _managed_extra = {b['board_id'] for b in boards
                          if board_owner(b['board_id']) == username}
        for _b in _all_boards():
            _bid = _b['board_id']
            if _bid in _managed_extra:
                continue
            if perm_check_pass(username, perm_chain(board_id=_bid),
                               OP_UPDATE, LV_BOARD_OWNER):
                _managed_extra.add(_bid)
        if _managed_extra:
            _known = {b['board_id'] for b in boards}
            boards = boards + [b for b in _all_boards() if b['board_id'] in _managed_extra
                               and b['board_id'] not in _known]
    # 卡片数：**必须按当前账号的可见范围统计**（看板级 + 板块级两级权限）。
    # ⚠️ 此前直接对 cards 表 GROUP BY 统计 → 只做了看板级过滤，
    #    板块级白名单（allowed_columns）收窄后的板块，其事项仍被计入
    #    → 「看板管理」里显示的卡片数与用户实际能看到的条数对不上（实测 6 vs 2）。
    #    口径统一：与 /api/cards 的可见集合完全一致。
    counts = defaultdict(int)
    for r in filter_rows(dbq('SELECT board_id, column_id FROM cards WHERE deleted=0'),
                          visible, cols_perm):
        counts[r['board_id']] += 1
    # 所属板块年份（年份在板块层，看板只是容器）
    # ⚠️ 同样要按**可见板块**算 —— 越权板块的年份不该出现在列表里。
    col_years = defaultdict(set)
    for r in visible_columns(username, visible, cols_perm):
        if r.get('year'):
            col_years[r['board_id']].add(r['year'])
    cfgs = {}
    for r in dbq('SELECT id, board_id, dept, dept_node_id, attr, status, remark, created_at'
                 ' FROM board_config'):
        cfgs[r['board_id']] = dict(r)
    # 看板负责人与参与人 —— 供【看板管理】配置与展示。
    # ⚠️ 2026-11-04 恢复参与人下发：人员选择层级约束要求「板块的负责人与参与人
    #    从所属看板的负责人与参与人中选」，前端需要读到看板的参与人名单。
    acl = {}
    for r in dbq('SELECT board_id, owner, participants FROM boards'):
        d = dict(r)
        acl[d['board_id']] = {'owner': d.get('owner', ''),
                              'participants': d.get('participants', '') or ''}
    out = []
    for b in boards:
        bid = b['board_id']
        c = cfgs.get(bid, {})
        a = acl.get(bid, {'owner': ''})
        out.append({
            'board_id': bid,
            'board_name': b['board_name'],
            'workspace_id': b.get('workspace_id', ''),
            'card_count': counts.get(bid, 0),
            'config_id': c.get('id'),
            'col_years': sorted(col_years.get(bid, set()), reverse=True),
            'dept': c.get('dept', ''),
            'dept_node_id': c.get('dept_node_id', 0) or 0,
            'attr': c.get('attr', ''),
            'status': c.get('status', ''),
            'remark': c.get('remark', ''),
            'owner': a.get('owner', ''),
            'participants': a.get('participants', ''),
            # 该账号是否为该看板的负责人（决定能否修改该看板基本信息）
            'is_owner': a.get('owner', '') == username,
        })
    # 逐看板给出「可配置能力」（2026-11-03）
    # ⚠️ 前端按这个渲染：能改基本信息 / 能改负责人 / 完全不可动。
    #    判定走 perm.py 的 can_do，与后端写接口的门槛**完全一致**。
    for item in out:
        bid = item['board_id']
        chain = perm_chain(board_id=bid)
        lv = perm_level_of(username, chain)
        item['perm_level'] = lv
        item['perm_role'] = ROLE_NAMES.get(lv, '无权限')
        can_update = perm_check_pass(username, chain, OP_UPDATE, LV_BOARD_OWNER)
        can_assign = perm_check_pass(username, chain, OP_ASSIGN_OWNER, LV_BOARD_OWNER,
                                      min_level=LV_ARCH_OWNER)
        item['can_edit'] = can_update          # 能否改基本信息（归属部门/属性/状态/备注）
        item['can_assign_owner'] = can_assign  # 能否指定/变更看板负责人（架构负责人及以上）
        # can_delete = 能否**删除看板本身**（2026-11-04：删除配置已下线）
        #   min_level 显式给 LV_BOARD_OWNER → 与 DELETE /api/boards/{id} 的后端校验完全同口径。
        item['can_delete'] = perm_check_pass(username, chain, OP_DELETE, LV_BOARD_OWNER,
                                             min_level=LV_BOARD_OWNER)
    return {'boards': out, 'depts': _dept_options()}

@app.get('/api/board-config')
def list_board_config(username: str = Depends(require_auth)):
    """看板配置列表（含关联看板名称），按部门、属性排序。
    普通用户只返回其可见看板的配置（与看板列表口径一致）。
    ⚠️ 配置里**没有年份** —— 归属年份在板块层（board_columns.year）。"""
    rows = dbq('''SELECT c.id, c.board_id, c.dept, c.attr, c.status, c.remark, c.created_at,
                        COALESCE(b.board_name, '') AS board_name
                 FROM board_config c
                 LEFT JOIN boards b ON b.board_id = c.board_id
                 ORDER BY c.dept, c.attr''')
    visible, _cols = user_allowed(username)
    if visible is not None:
        rows = [r for r in rows if r['board_id'] in visible]
    return {'items': [dict(r) for r in rows]}

@app.post('/api/board-config')
def create_board_config(req: BoardConfigReq, username: str = Depends(require_auth), request: Request = None):
    """为真实看板登记配置。每个看板仅一条配置。
    归属年份不在这里配置 —— 请在板块层设置（每个板块绑定唯一归属年份）。

    权限（2026-11-02）：**管理员，或该看板的负责人**。
    负责人 = 看板管理权（可改本看板的基本信息），见 is_board_manager()。
    """
    bid = (req.board_id or '').strip()
    if not bid:
        raise HTTPException(400, '必须选择关联看板')
    if not dbq('SELECT 1 FROM boards WHERE board_id=?', (bid,)) and \
       not dbq('SELECT 1 FROM cards WHERE board_id=? AND deleted=0', (bid,)):
        raise HTTPException(404, '关联看板不存在')
    # 分级权限（2026-11-02）：修改看板基本信息 = 看板负责人及以上
    perm_check(username, perm_chain(board_id=bid), OP_UPDATE, LV_BOARD_OWNER, 'board:' + bid)
    attr = req.attr.strip()
    status = (req.status or '启用').strip(); remark = (req.remark or '').strip()
    dept_node_id, dept, _is_center = _resolve_dept_node(req.dept, req.dept_node_id)
    if not (dept and attr):
        raise HTTPException(400, '归属部门 / 属性 均必填')
    _validate_board_config(dept, attr, status)
    if dbq('SELECT 1 FROM board_config WHERE board_id=?', (bid,)):
        raise HTTPException(409, '该看板已存在配置，请勿重复添加')
    try:
        dbe('INSERT INTO board_config (board_id, dept, dept_node_id, attr, status, remark)'
            ' VALUES (?,?,?,?,?,?)',
            (bid, dept, dept_node_id, attr, status, remark))
    except sqlite3.IntegrityError:
        raise HTTPException(409, '该看板已存在配置')
    audit_log(username, client_ip(request), 'board_config_create', f'{bid}/{dept}/{attr}',
              f'状态={status}', 'success')
    return {'ok': True}

# ---------------- API：ACL 配置（负责人 / 参与人）----------------
class AclReq(BaseModel):
    """负责人配置请求：owner = 负责人账号（单选）。

    2026-11-04：participants（参与人）**恢复使用** —— 人员选择层级约束要求
       「板块的负责人与参与人从所属看板的负责人与参与人中选」，看板需要
       维护自己的参与人名单作为板块的选人池。负责人与参与人**互斥**。
    """
    owner: str = ''
    # 参与人兼容两种入参：逗号串（前端 saveBoardAcl）或列表（旧客户端）——
    # _norm_acl_participants 内部都会归一（2026-11-04：此前写死 List[str]，
    # 前端传逗号串直接 422）
    participants: Union[str, List[str]] = []


def _norm_acl_owner(v: str) -> str:
    """负责人归一：必须是**已存在的登录账号**，否则拒绝（避免写了永远匹配不上的值）"""
    o = (v or '').strip()
    if not o:
        return ''
    if not dbq('SELECT 1 FROM users WHERE username=? LIMIT 1', (o,)):
        raise HTTPException(400, f'负责人账号「{o}」不存在')
    return o


def _norm_acl_participants(items) -> str:
    """参与人归一：去空白、去重、剔除不存在的账号 → 逗号分隔串

    ⚠️ 参与人存**账号**（与 boards.owner 同口径）；
       事项层的历史存量是**姓名**（cards.cc）—— 判定内核按双口径匹配，
       写入时统一用账号。
    """
    # ⚠️ 入参可能是**列表**（AclReq.participants）或**逗号分隔字符串**
    #   （ColumnUpdate.participants）→ 先统一拆成列表，避免逐字符迭代。
    if isinstance(items, str):
        items = [x for x in re.split(r'[,;、]', items)]
    out, seen = [], set()
    for x in (items or []):
        x = (str(x or '')).strip()
        if not x or x in seen:
            continue
        if not dbq('SELECT 1 FROM users WHERE username=? LIMIT 1', (x,)):
            raise HTTPException(400, f'参与人账号「{x}」不存在')
        seen.add(x)
        out.append(x)
    return ','.join(out)


@app.put('/api/boards/{board_id}/acl')
async def set_board_acl(board_id: str, req: AclReq, username: str = Depends(require_writer),
                        request: Request = None):
    """设置看板负责人（仅管理员）。

    语义（2026-11-02 修订）：负责人 = **该看板的管理权** —— 负责人有权修改
    该看板的基本信息（归属部门 / 属性 / 状态 / 备注），**不影响谁能看到这个看板**
    （可见性统一由【架构管理】的看板绑定决定）。
    传空 owner = 撤销负责人。
    """
    bid = (board_id or '').strip()
    if not dbq('SELECT 1 FROM boards WHERE board_id=? LIMIT 1', (bid,)):
        raise HTTPException(404, '看板不存在')
    # 分级权限（2026-11-02）：指派看板负责人 = 架构负责人及以上
    perm_check(username, perm_chain(board_id=bid), OP_ASSIGN_OWNER, LV_BOARD_OWNER,
               'board:' + bid, min_level=LV_ARCH_OWNER)
    owner = _norm_acl_owner(req.owner)
    # 2026-11-04 恢复：参与人字段重新启用（人员选择层级约束 —— 板块的选人池
    # 来自所属看板的负责人与参与人），不再随负责人保存清空。
    # 负责人/参与人**互斥**：设为负责人时自动从参与人中移除。
    _row = dbq('SELECT participants FROM boards WHERE board_id=?', (bid,))
    parts = ((_row[0]['participants'] if _row else '') or '')
    if owner:
        parts = ','.join([p for p in parts.split(',') if p and p != owner])
    dbe('UPDATE boards SET owner=?, participants=? WHERE board_id=?', (owner, parts, bid))
    audit_log(username, client_ip(request), 'board_acl', f'看板 {bid}',
              f'设置看板负责人：{owner or "(无)"}', 'success')
    await ws_mgr.broadcast({'type': 'card_update', 'card_id': '*', 'by': username})
    return {'ok': True, 'board_id': bid, 'owner': owner, 'participants': parts}


@app.put('/api/boards/{board_id}/participants')
async def set_board_participants(board_id: str, req: AclReq, username: str = Depends(require_writer),
                                 request: Request = None):
    # 指派看板参与人（仅管理员）。
    # ⚠️ 看板参与人 = 该看板的**协作者**：可修改自己参与的事项与板块的可见内容，
    #    但**无增删与指派权限**（见 perm.py 的 OP_MIN_LEVEL）。
    bid = (board_id or '').strip()
    if not dbq('SELECT 1 FROM boards WHERE board_id=? LIMIT 1', (bid,)):
        raise HTTPException(404, '看板不存在')
    perm_check(username, perm_chain(board_id=bid), OP_ASSIGN_PARTICIPANT,
               LV_BOARD_OWNER, 'board:' + bid, min_level=LV_BOARD_OWNER)
    parts = _norm_acl_participants(req.participants)
    # 负责人/参与人互斥（2026-11-04）：参与人名单里剔除当前负责人
    _row = dbq('SELECT owner FROM boards WHERE board_id=?', (bid,))
    _own = ((_row[0]['owner'] if _row else '') or '')
    if _own:
        parts = ','.join([p for p in parts.split(',') if p and p != _own])
    dbe('UPDATE boards SET participants=? WHERE board_id=?', (parts, bid))
    audit_log(username, client_ip(request), 'board_participants', f'看板 {bid}',
              f'设置看板参与人：{parts or "(无)"}', 'success')
    return {'ok': True, 'board_id': bid, 'participants': parts}


@app.put('/api/columns/{col_key}/participants')
async def set_column_participants(col_key: str, req: AclReq, username: str = Depends(require_writer),
                                  request: Request = None):
    # 指派板块参与人（仅管理员 / 板块负责人）。
    key = col_key or ''
    row = dbq('SELECT board_id, column_id FROM board_columns WHERE col_key=? LIMIT 1', (key,))
    if not row:
        raise HTTPException(404, '板块不存在')
    perm_check(username, perm_chain(board_id=row[0]['board_id'], column_id=row[0]['column_id']),
               OP_ASSIGN_PARTICIPANT, LV_COLUMN_OWNER, 'column:' + key, min_level=LV_COLUMN_OWNER)
    parts = _norm_acl_participants(req.participants)
    dbe('UPDATE board_columns SET participants=? WHERE col_key=?', (parts, key))
    audit_log(username, client_ip(request), 'column_participants', f'板块 {key}',
              f'设置板块参与人：{parts or "(无)"}', 'success')
    return {'ok': True, 'col_key': key, 'participants': parts}


@app.put('/api/cards/{card_id}/participants')
async def set_card_participants(card_id: str, req: AclReq, username: str = Depends(require_writer),
                                request: Request = None):
    # 指派事项参与人（事项负责人及以上）。
    # 参与人 = 可修改该事项的**可见内容**，但无增删与指派权限。
    row = dbq('SELECT board_id, column_id FROM cards WHERE card_id=? AND deleted=0', (card_id,))
    if not row:
        raise HTTPException(404, '事项不存在或已删除')
    perm_check(username, perm_chain(card_id=card_id),
               OP_ASSIGN_PARTICIPANT, LV_CARD_OWNER, 'card:' + card_id)
    parts = _norm_acl_participants(req.participants)
    dbe('UPDATE cards SET cc=? WHERE card_id=? AND deleted=0', (parts, card_id))
    audit_log(username, client_ip(request), 'card_participants', f'事项 {card_id}',
              f'设置事项参与人：{parts or "(无)"}', 'success')
    await ws_mgr.broadcast({'type': 'card_update', 'card_id': card_id, 'by': username})
    return {'ok': True, 'card_id': card_id, 'participants': parts}


@app.put('/api/columns/{col_key}/acl')
async def set_column_acl(col_key: str, req: AclReq, username: str = Depends(require_writer),
                         request: Request = None):
    """设置板块负责人（仅管理员）。

    语义：与看板负责人一致 —— 板块负责人 = 该板块的**管理权**，
    不影响板块可见性。配置入口在【板块编辑】弹窗里。
    """
    key = col_key or ''
    row = dbq('SELECT board_id, column_id FROM board_columns WHERE col_key=? LIMIT 1', (key,))
    if not row:
        raise HTTPException(404, '板块不存在')
    # 分级权限（2026-11-02）：指派板块负责人 = 看板负责人及以上
    perm_check(username, perm_chain(board_id=row[0]['board_id'], column_id=row[0]['column_id']),
               OP_ASSIGN_OWNER, LV_COLUMN_OWNER, 'column:' + key, min_level=LV_BOARD_OWNER)
    owner = _norm_acl_owner(req.owner)
    dbe('UPDATE board_columns SET owner=?, participants=? WHERE col_key=?', (owner, '', key))
    audit_log(username, client_ip(request), 'column_acl', f'板块 {key}',
              f'设置板块负责人：{owner or "(无)"}', 'success')
    await ws_mgr.broadcast({'type': 'card_update', 'card_id': '*', 'by': username})
    return {'ok': True, 'col_key': key, 'owner': owner, 'participants': ''}


# ⚠️ 2026-11-04 下线两个批量接口（用户需求）：
#   ① POST /api/board-config/bulk   ——「应用到已选 N 个看板」（功能没用，已下线）
#   ② POST /api/board-config/bulk-delete ——「批量删除看板配置」（已改为删除看板本身，
#      新接口：POST /api/boards/bulk-delete）
# 删除看板本体请用 DELETE /api/boards/{board_id} 与 POST /api/boards/bulk-delete。

@app.put('/api/board-config/{cid}')
def update_board_config(cid: int, req: BoardConfigReq, username: str = Depends(require_auth), request: Request = None):
    """更新看板配置。board_id 创建后锁定，不可改挂其他看板。
    ⚠️ 不含归属年份 —— 年份在板块层单独配置。

    权限（2026-11-02）：**管理员，或该看板的负责人**（负责人 = 看板管理权）。
    """
    row = dbq('SELECT board_id FROM board_config WHERE id=?', (cid,))
    if not row:
        raise HTTPException(404, '配置不存在')
    # 分级权限（2026-11-02）：修改看板基本信息 = 看板负责人及以上
    perm_check(username, perm_chain(board_id=row[0]['board_id']),
               OP_UPDATE, LV_BOARD_OWNER, 'board:' + row[0]['board_id'])
    attr = req.attr.strip()
    status = (req.status or '启用').strip(); remark = (req.remark or '').strip()
    dept_node_id, dept, _is_center = _resolve_dept_node(req.dept, req.dept_node_id)
    if not (dept and attr):
        raise HTTPException(400, '归属部门 / 属性 均必填')
    _validate_board_config(dept, attr, status)
    dbe('UPDATE board_config SET dept=?, dept_node_id=?, attr=?, status=?, remark=? WHERE id=?',
        (dept, dept_node_id, attr, status, remark, cid))
    audit_log(username, client_ip(request), 'board_config_update', f'id={cid}',
              f'{dept}/{attr} 状态={status}', 'success')
    return {'ok': True}

@app.delete('/api/board-config/{cid}')
def delete_board_config(cid: int, username: str = Depends(require_auth), request: Request = None):
    """删除看板配置。权限：管理员，或该看板的负责人。"""
    r = dbq('SELECT board_id, dept, attr FROM board_config WHERE id=?', (cid,))
    if not r:
        raise HTTPException(404, '配置不存在')
    # 分级权限（2026-11-02）：删除看板配置 = 看板负责人及以上
    perm_check(username, perm_chain(board_id=r[0]['board_id']),
               OP_DELETE, LV_BOARD_OWNER, 'board:' + r[0]['board_id'])
    dbe('DELETE FROM board_config WHERE id=?', (cid,))
    row = r[0]
    audit_log(username, client_ip(request), 'board_config_delete',
              f'{row["dept"]}/{row["attr"]}', f'id={cid}', 'success')
    return {'ok': True}

# ---------------- API：部门主页（文化展示区 / 标杆部门 / 模范个人 / 部门介绍） ----------------
# 图片一律以 data URL 存进数据库：同步脚本只传代码不传数据文件，
# 存文件系统会在同步后指向服务器上不存在的路径（图片直接失效）。
MAX_IMAGE_BYTES = 512 * 1024        # 单张图片上限 512KB（data URL 后的实际字节数）
MAX_PHOTO_BYTES = 2 * 1024 * 1024   # 个人照片上限 2MB（形象照比头像大得多）
ALLOWED_IMAGE_TYPES = ('image/jpeg', 'image/png', 'image/gif', 'image/webp')

def _check_image_data_url(data_url: str, max_bytes: int = None) -> str:
    """校验图片 data URL：类型必须是常见图片格式，大小不得超过上限。
    返回去掉前缀的纯 base64 载荷（入库用）。不合规则抛 400。
    max_bytes：按用途区分上限（头像 512KB、个人照片 2MB）。"""
    limit = MAX_IMAGE_BYTES if max_bytes is None else max_bytes
    s = (data_url or '').strip()
    if not s:
        return ''
    if not s.startswith('data:'):
        raise HTTPException(400, '图片格式不正确')
    head, _, payload = s.partition(',')
    if not payload:
        raise HTTPException(400, '图片数据为空')
    mime = head[5:].split(';')[0].strip().lower()
    if mime not in ALLOWED_IMAGE_TYPES:
        raise HTTPException(400, '仅支持 JPG / PNG / GIF / WebP 格式的图片')
    # base64 长度 → 原始字节数（约 3/4）
    approx = len(payload) * 3 // 4
    if approx > limit:
        raise HTTPException(400, f'图片过大（{approx//1024}KB），请压缩到 {limit//1024}KB 以内')
    return s

class ProfileReq(BaseModel):
    """个人资料：头像 + 个人照片 + 个人状态"""
    avatar: str = ''          # 头像 data URL（空串=清除头像）
    photo: str = ''           # 个人照片 data URL（空串=清除照片）
    status_text: str = ''     # 个人状态（一句话）


@app.post('/api/profile')
def update_profile(req: ProfileReq, username: str = Depends(require_auth), request: Request = None):
    """保存个人资料（头像 + 个人照片 + 个人状态）。仅能改自己的。"""
    avatar = _check_image_data_url(req.avatar) if (req.avatar or '').strip() else ''
    # 个人照片用独立上限（2MB）；照片与头像分开校验，互不影响
    photo = _check_image_data_url(req.photo, MAX_PHOTO_BYTES) if (req.photo or '').strip() else ''
    status_text = (req.status_text or '').strip()[:120]
    dbe('UPDATE users SET avatar=?, photo=?, status_text=? WHERE username=?',
        (avatar, photo, status_text, username))
    parts = []
    if avatar:
        parts.append('更新头像')
    if photo:
        parts.append('更新个人照片')
    if status_text:
        parts.append('更新个人状态')
    audit_log(username, client_ip(request), 'profile_update', '个人资料',
              '，'.join(parts) or '更新个人资料', 'success')
    return {'ok': True, 'avatar': avatar, 'photo': photo, 'status_text': status_text}


class PasswordChangeReq(BaseModel):
    old_password: str
    new_password: str


@app.post('/api/profile/password')
def change_password(req: PasswordChangeReq, username: str = Depends(require_auth), request: Request = None):
    """修改自己的密码：必须校验旧密码；成功后当前令牌失效（需重新登录）。"""
    old = req.old_password or ''
    new = req.new_password or ''
    if not old:
        raise HTTPException(400, '请输入原密码')
    if len(new) < 6:
        raise HTTPException(400, '新密码至少 6 位')
    u = dbq('SELECT password_hash FROM users WHERE username=?', (username,))
    if not u:
        raise HTTPException(404, '账号不存在')
    if not verify_pw(old, u[0]['password_hash']):
        audit_log(username, client_ip(request), 'password_change', '修改密码', '原密码错误', 'failed')
        raise HTTPException(400, '原密码不正确')
    if old == new:
        raise HTTPException(400, '新密码不能与原密码相同')
    dbe('UPDATE users SET password_hash=? WHERE username=?', (hash_pw(new), username))
    audit_log(username, client_ip(request), 'password_change', '修改密码', '密码修改成功', 'success')
    return {'ok': True, 'need_relogin': True}


class DeptProfileReq(BaseModel):
    slogan: str = ''       # 文化标语
    intro: str = ''        # 部门职能介绍
    photo: str = ''        # 团队合照（data URL）

class DeptHonorReq(BaseModel):
    kind: str = 'dept'                       # 'dept'=标杆部门 / 'person'=模范个人
    target_name: str = ''                    # 标杆部门名 / 模范个人姓名
    photo: str = ''                          # 照片（data URL）
    remark: str = ''                         # 备注
    sort: int = 0

@app.get('/api/dept/{dept}/page')
def get_dept_page(dept: str, username: str = Depends(require_auth)):
    """部门主页数据：文化资料 + 标杆/模范 + 事项统计 + 成员/工作组。
    统计口径与「事项统计」模块一致：按当前用户可见范围过滤。"""
    if dept not in _dept_names():
        raise HTTPException(404, '部门不存在')
    boards, columns = user_allowed(username)
    prof = dbq('SELECT dept, slogan, intro, photo, updated_at FROM dept_profile WHERE dept=?', (dept,))
    honors = dbq('''SELECT id, dept, kind, target_name, photo, remark, sort, created_at
                    FROM dept_honors WHERE dept=? ORDER BY kind, sort, id''', (dept,))
    # 该部门下的看板（看板管理里配置的归属部门）
    dept_boards = [b['board_id'] for b in dbq('SELECT board_id FROM board_config WHERE dept=?', (dept,))]
    # 普通用户只看到自己可见的看板（与 /api/me 口径一致）
    if boards is not None:
        dept_boards = [b for b in dept_boards if b in boards]
    # 事项统计：只看该部门的看板，且是主事项（parent_id=''）
    stat = {'total': 0, 'done': 0, 'progressing': 0, 'open': 0, 'overdue': 0, 'owner_missing': 0}
    owner_cnt = defaultdict(int)
    if dept_boards:
        marks = ','.join('?' * len(dept_boards))
        rows = dbq(f"""SELECT c.* FROM cards c
                       WHERE c.deleted=0 AND c.parent_id='' AND c.board_id IN ({marks})""",
                    tuple(dept_boards))
        today = time.strftime('%Y-%m-%d')
        for r in rows:
            if not perm_pass(dict(r), boards, columns):
                continue
            stat['total'] += 1
            st = r['status'] or 'open'
            if st == 'done':
                stat['done'] += 1
            elif st == 'progressing':
                stat['progressing'] += 1
            else:
                stat['open'] += 1
            if r['due'] and st != 'done' and r['due'] < today:
                stat['overdue'] += 1
            names = [n.strip() for n in (r['owner'] or '').split(';') if n.strip()]
            if not names:
                stat['owner_missing'] += 1
            for n in names:
                owner_cnt[n] += 1
    # 部门成员与工作组（来自 workgroups / team_members，用于介绍页的组织架构）
    wgs = dbq('SELECT id, name, parent_id, leader, function FROM workgroups ORDER BY id')
    members = dbq('SELECT id, name, account, workgroups FROM team_members ORDER BY id')
    member_names = {m['name'] for m in members}
    # 顶层部门 → 其下的工作组（按 workgroups 的 parent_id 关系）
    top = [w for w in wgs if not w['name'] or w['name'] == dept]
    tree = []
    for t in wgs:
        if t['name'] == dept or (t['parent_id'] and any(p['id'] == t['parent_id'] and p['name'] == dept for p in wgs)):
            tree.append({
                'id': t['id'], 'name': t['name'], 'leader': t['leader'],
                'function': t['function'],
                'members': sorted([m['name'] for m in members if t['name'] and t['name'] in (m['workgroups'] or '')]),
            })
    return {
        'dept': dept,
        'profile': dict(prof[0]) if prof else {'dept': dept, 'slogan': '', 'intro': '', 'photo': '', 'updated_at': ''},
        'honors': [dict(h) for h in honors],
        'stats': stat,
        'owner_stats': [{'owner': k, 'count': v} for k, v in
                        sorted(owner_cnt.items(), key=lambda kv: (-kv[1], kv[0]))],
        'workgroups': tree,
        'boards': dept_boards,
    }

@app.put('/api/dept/{dept}/profile')
def update_dept_profile(dept: str, req: DeptProfileReq, username: str = Depends(require_admin), request: Request = None):
    """保存部门文化资料（仅管理员可编辑）"""
    if dept not in _dept_names():
        raise HTTPException(404, '部门不存在')
    photo = _check_image_data_url(req.photo)
    slogan = (req.slogan or '').strip()[:200]
    intro = (req.intro or '').strip()[:4000]
    dbe('''INSERT INTO dept_profile (dept, slogan, intro, photo, updated_at)
           VALUES (?,?,?,?,datetime('now','localtime'))
           ON CONFLICT(dept) DO UPDATE SET
             slogan=excluded.slogan, intro=excluded.intro,
             photo=excluded.photo, updated_at=excluded.updated_at''',
        (dept, slogan, intro, photo))
    audit_log(username, client_ip(request), 'dept_profile_update', dept,
              f'更新部门文化资料（标语 {len(slogan)} 字）', 'success')
    return {'ok': True}

@app.post('/api/dept/{dept}/honors')
def create_dept_honor(dept: str, req: DeptHonorReq, username: str = Depends(require_admin), request: Request = None):
    """新增标杆部门 / 模范个人（仅管理员）"""
    if dept not in _dept_names():
        raise HTTPException(404, '部门不存在')
    if req.kind not in ('dept', 'person'):
        raise HTTPException(400, '类型必须是标杆部门(dept)或模范个人(person)')
    name = (req.target_name or '').strip()[:60]
    if not name:
        raise HTTPException(400, '名称不能为空')
    photo = _check_image_data_url(req.photo)
    dbe('''INSERT INTO dept_honors (dept, kind, target_name, photo, remark, sort)
           VALUES (?,?,?,?,?,?)''',
        (dept, req.kind, name, photo, (req.remark or '').strip()[:200], req.sort))
    audit_log(username, client_ip(request), 'dept_honor_create', dept,
              f'新增{"标杆部门" if req.kind=="dept" else "模范个人"} {name}', 'success')
    return {'ok': True}

@app.put('/api/dept/honors/{hid}')
def update_dept_honor(hid: int, req: DeptHonorReq, username: str = Depends(require_admin), request: Request = None):
    if req.kind not in ('dept', 'person'):
        raise HTTPException(400, '类型必须是标杆部门(dept)或模范个人(person)')
    cur = dbq('SELECT id, dept, target_name FROM dept_honors WHERE id=?', (hid,))
    if not cur:
        raise HTTPException(404, '记录不存在')
    photo = _check_image_data_url(req.photo)
    dbe('''UPDATE dept_honors SET kind=?, target_name=?, photo=?, remark=?, sort=? WHERE id=?''',
        (req.kind, (req.target_name or '').strip()[:60], photo,
         (req.remark or '').strip()[:200], req.sort, hid))
    audit_log(username, client_ip(request), 'dept_honor_update', cur[0]['dept'],
              f'更新 id={hid}', 'success')
    return {'ok': True}

@app.delete('/api/dept/honors/{hid}')
def delete_dept_honor(hid: int, username: str = Depends(require_admin), request: Request = None):
    cur = dbq('SELECT id, dept FROM dept_honors WHERE id=?', (hid,))
    if not cur:
        raise HTTPException(404, '记录不存在')
    dbe('DELETE FROM dept_honors WHERE id=?', (hid,))
    audit_log(username, client_ip(request), 'dept_honor_delete', cur[0]['dept'],
              f'删除 id={hid}', 'success')
    return {'ok': True}

@app.get('/api/dept/{dept}/posts')
def get_dept_posts(dept: str, username: str = Depends(require_auth)):
    """部门介绍页的发文列表（部门文化内容区）"""
    if dept not in _dept_names():
        raise HTTPException(404, '部门不存在')
    rows = dbq('''SELECT id, dept, title, content, images, author, created_at
                   FROM dept_posts WHERE dept=? ORDER BY id DESC LIMIT 100''', (dept,))
    return {'posts': [dict(r) for r in rows]}

class DeptPostReq(BaseModel):
    title: str = ''
    content: str = ''
    images: list[str] = []      # 图片 data URL 列表

@app.post('/api/dept/{dept}/posts')
def create_dept_post(dept: str, req: DeptPostReq, username: str = Depends(require_admin), request: Request = None):
    """发布部门文章（仅管理员；支持发图）"""
    if dept not in _dept_names():
        raise HTTPException(404, '部门不存在')
    title = (req.title or '').strip()[:100]
    content = (req.content or '').strip()[:4000]
    if not title and not content and not req.images:
        raise HTTPException(400, '内容不能为空')
    imgs = []
    for u in (req.images or [])[:9]:
        imgs.append(_check_image_data_url(u))
    dbe('INSERT INTO dept_posts (dept, title, content, images, author) VALUES (?,?,?,?,?)',
        (dept, title, content, ';'.join(imgs), username))
    audit_log(username, client_ip(request), 'dept_post_create', dept,
              f'发布部门文章「{title or "无标题"}」', 'success')
    return {'ok': True}

@app.delete('/api/dept/posts/{pid}')
def delete_dept_post(pid: int, username: str = Depends(require_admin), request: Request = None):
    cur = dbq('SELECT id, dept FROM dept_posts WHERE id=?', (pid,))
    if not cur:
        raise HTTPException(404, '文章不存在')
    dbe('DELETE FROM dept_posts WHERE id=?', (pid,))
    audit_log(username, client_ip(request), 'dept_post_delete', cur[0]['dept'],
              f'删除文章 id={pid}', 'success')
    return {'ok': True}

# ---------------- API：公告栏 ----------------
class NoticeReq(BaseModel):
    scope: str = 'all'          # 'all' 或部门名
    title: str = ''
    content: str = ''
    enabled: int = 1
    sort: int = 0

@app.get('/api/notices')
def get_notices(username: str = Depends(require_auth)):
    """公告列表：全部公告 + 部门公告。登录即可读。"""
    rows = dbq('''SELECT id, scope, title, content, author, enabled, sort, created_at
                   FROM notices ORDER BY sort, id DESC''')
    return {'notices': [dict(r) for r in rows]}

@app.post('/api/notices')
def create_notice(req: NoticeReq, username: str = Depends(require_admin), request: Request = None):
    """新增公告（仅管理员）"""
    scope = (req.scope or 'all').strip() or 'all'
    if scope != 'all' and scope not in _dept_names():
        raise HTTPException(400, '公告范围必须是 all 或 ' + '/'.join(sorted(_dept_names())))
    title = (req.title or '').strip()[:100]
    content = (req.content or '').strip()[:2000]
    if not title and not content:
        raise HTTPException(400, '公告内容不能为空')
    dbe('INSERT INTO notices (scope, title, content, author, enabled, sort) VALUES (?,?,?,?,?,?)',
        (scope, title, content, username, 1 if req.enabled else 0, req.sort))
    audit_log(username, client_ip(request), 'notice_create', scope, title[:60], 'success')
    return {'ok': True}

@app.put('/api/notices/{nid}')
def update_notice(nid: int, req: NoticeReq, username: str = Depends(require_admin), request: Request = None):
    cur = dbq('SELECT id, scope FROM notices WHERE id=?', (nid,))
    if not cur:
        raise HTTPException(404, '公告不存在')
    scope = (req.scope or 'all').strip() or 'all'
    if scope != 'all' and scope not in _dept_names():
        raise HTTPException(400, '公告范围必须是 all 或 ' + '/'.join(sorted(_dept_names())))
    dbe('''UPDATE notices SET scope=?, title=?, content=?, enabled=?, sort=? WHERE id=?''',
        (scope, (req.title or '').strip()[:100], (req.content or '').strip()[:2000],
         1 if req.enabled else 0, req.sort, nid))
    audit_log(username, client_ip(request), 'notice_update', scope, f'id={nid}', 'success')
    return {'ok': True}

@app.delete('/api/notices/{nid}')
def delete_notice(nid: int, username: str = Depends(require_admin), request: Request = None):
    cur = dbq('SELECT id, scope FROM notices WHERE id=?', (nid,))
    if not cur:
        raise HTTPException(404, '公告不存在')
    dbe('DELETE FROM notices WHERE id=?', (nid,))
    audit_log(username, client_ip(request), 'notice_delete', cur[0]['scope'], f'id={nid}', 'success')
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
    # 分级权限（2026-11-02）：**配置「管理员」权限仅超级管理员可为**。
    # 管理员虽超脱于分层体系拥有全部权限，但不能授予他人管理员身份。
    if req.role == 'admin' and username != SUPER_ADMIN:
        raise PermError(E_ADMIN_ONLY,
                        '只有超级管理员可以授予管理员权限',
                        need_level=LV_SUPER, have_level=LV_ADMIN,
                        resource='user:' + name, op='assign_admin')
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
    # 分级权限（2026-11-02）：**变更「管理员」权限仅超级管理员可为**。
    # · 把别人**升为** admin → 仅超管
    # · 把 admin **降级**为 editor/viewer → 仅超管（防止管理员互相踢）
    cur_role = (u.get('role') or '').strip()
    if req.role is not None and username != SUPER_ADMIN:
        if req.role == 'admin' or cur_role == 'admin':
            raise PermError(E_ADMIN_ONLY,
                            '只有超级管理员可以配置管理员权限',
                            need_level=LV_SUPER, have_level=LV_ADMIN,
                            resource='user:' + name, op='assign_admin')
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
async def move_card(card_id: str, req: MoveReq, username: str = Depends(require_writer), request: Request = None):
    holder = lock_mgr.who(card_id)
    if holder and holder != username:
        raise HTTPException(409, f'卡片已被 {holder} 编辑中，无法移动')
    src_row = dbq('SELECT board_id FROM cards WHERE card_id=? AND deleted=0', (card_id,))
    if src_row:
        check_board_access(src_row[0]['board_id'], username)
    if not src_row:
        raise HTTPException(404, '卡片不存在或已删除')
    # 分级权限（2026-11-02）：移动事项 = 修改事项（事项负责人及以上）
    # ⚠️ 权限内核先于可见性校验（原因见 update_card 的同款说明）
    perm_check(username, perm_chain(card_id=card_id),
               OP_UPDATE, LV_CARD_OWNER, 'card:' + card_id)
    check_board_access(req.board_id, username)
    # 板块级校验：目标板块对当前账号不可见时拒绝移动
    check_column_access(req.board_id, req.column_id, username)
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
# 事项级导出列（一维表，每行一个事项）——2026-11-04 需求5
# 覆盖事项**关联的全部信息**：看板 / 板块 / 负责人 / 参与人 / 周数 /
# 日期类 / 描述类信息（除评论外）。
# ⚠️ 列名与 key 一一对应；key 为 cards 表列名或本文件内定义的派生列（_ 前缀）。
XLSX_COLUMNS = [
    ('事项名称',   'card_name',    40),
    ('事项编号',   'card_id',      18),
    ('所属看板',   'board_name',   22),
    ('所属板块',   'column_name',  18),
    ('板块年份',   '_col_year',    10),
    ('板块性质',   '_col_nature',  10),
    ('板块负责人', '_col_owner',   12),
    ('板块完成情况', '_col_completion', 12),
    ('完成情况',   '_status_text', 10),
    ('事项状态',   'status_name',  10),
    ('负责人',     'owner',        12),
    ('参与人',     'cc',           18),
    ('关注人',     'follower',     12),
    ('周数',       'week_no',      14),
    ('开始时间',   'begin',        14),
    ('截止时间',   'due',          14),
    ('创建时间',   'created',      18),
    ('修改时间',   'modified',     18),
    ('完成时间',   'completed',    14),
    ('优先级',     'priority',     10),
    ('创建人',     'creator',      12),
    ('描述',       'description',  50),
    ('标签',       'label',        14),
    ('归档状态',   'is_filed',     10),
    ('是否子事项', '_is_sub',      10),
    ('父事项名称', '_parent_name', 24),
]

@app.get('/api/export/xlsx')
def export_xlsx(board_id: str = '', board_ids: str = '', status: str = '',
                owner: str = '', column: str = '', q: str = '',
                created_start: str = '', created_end: str = '',
                cc: str = '', week: str = '', person: str = '', years: str = '',
                username: str = Depends(require_auth), request: Request = None):
    """导出**当前筛选结果**的事项为 xlsx（.xlsx，一维表，每行一个事项）

    2026-11-04 需求5：
    - 导出对象 = **事项**（不是全局数据）；
    - **页面上的筛选条件对导出结果生效** —— 本接口接受与 /api/cards 完全相同的
      筛选参数（status / q / cc / person / week / created_start / created_end /
      years / board_id(s) / owner / column），并**复用 /api/cards 的同一套过滤逻辑**
      （见 _filter_cards_for_user）→ 页面看到什么就导出什么；
    - 字段涵盖事项关联的全部信息（看板 / 板块 / 负责人 / 参与人 / 周数 /
      日期类 / 描述类信息，**除评论外**）；
    - 仍受用户可见性约束（看板 + 板块双层过滤）；
    - 全平铺结构，**不使用任何合并单元格**；表头加粗居中、首行冻结、自动筛选。
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
    elif board_ids:
        _bs = {x.strip() for x in board_ids.split(',') if x.strip()}
        if boards is not None:
            _bs = {b for b in _bs if b in boards}
        target_boards = _bs or set()
    # ★ 复用 /api/cards 的同一套过滤逻辑 → 页面筛选条件对导出结果生效
    cards, _week_opts, _col_hits = _filter_cards_for_user(
        username, boards, columns,
        board_id=board_id, board_ids=board_ids, status=status, owner=owner,
        column=column, q=q, created_start=created_start, created_end=created_end,
        cc=cc, week=week, person=person, years=years, board_set=target_boards)
    # 稳定排序：按开始时间、卡片名，保证多次导出一致
    cards.sort(key=lambda c: (str(c.get('begin') or ''), str(c.get('card_name') or '')))
    # 派生列需要板块元信息与父事项名称
    _colmap = {}
    for r in dbq('SELECT board_id, column_name, year, nature, owner, completion '
                 'FROM board_columns'):
        _colmap[(r['board_id'], r['column_name'])] = r
    _pmap = {}
    _pids = [c.get('parent_id') for c in cards if c.get('parent_id')]
    if _pids:
        _marks = ','.join('?' * len(_pids))
        for r in dbq('SELECT card_id, card_name FROM cards WHERE card_id IN (%s)' % _marks, _pids):
            _pmap[r['card_id']] = r['card_name']
    for c in cards:
        _cm = _colmap.get((c.get('board_id'), c.get('column_name') or ''))
        c['_col_year'] = (_cm['year'] if _cm else '') or ''
        c['_col_nature'] = (_cm['nature'] if _cm else '') or ''
        c['_col_owner'] = (_cm['owner'] if _cm else '') or ''
        c['_col_completion'] = _completion_text((_cm['completion'] if _cm else '') or 'open')
        c['_status_text'] = _status_text(c.get('status'))
        c['_is_sub'] = '是' if c.get('parent_id') else '否'
        c['_parent_name'] = _pmap.get(c.get('parent_id') or '', '')

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
    names = sorted({c.get('board_name') or '' for c in cards if c.get('board_name')})
    if len(names) == 1:
        board_label = names[0]
    elif names:
        board_label = f'{len(names)}个看板'
    else:
        board_label = '全部看板'
    safe = re.sub(r'[\\/:*?"<>|]', '_', board_label)
    filename = f'事项_{safe}_{ts}.xlsx'
    # RFC 5987 编码，兼容中文文件名
    from urllib.parse import quote
    disposition = f"attachment; filename*=UTF-8''{quote(filename)}"

    return Response(
        content=buf.getvalue(),
        media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        headers={'Content-Disposition': disposition},
    )


@app.get('/api/export')
def export_data(username: str = Depends(require_admin), request: Request = None):
    """备份：导出**整个架构下的全部数据**为 JSON（2026-11-04 需求4）

    ⚠️ 语义变更：此前只导出「当前用户可见范围」的数据 → 恢复时会丢数据。
    现在备份/恢复面向**全局**：看板 / 板块 / 事项 / 子事项 / 成员 / 架构节点
    全部导出，与操作者的可见范围无关（备份/恢复是管理员级操作）。

    仍**不包含**账号与密码（users 表）—— 账号体系独立管理，不随数据快照覆盖。
    """
    cards = [dict(r) for r in dbq('SELECT * FROM cards WHERE deleted=0')]
    teams = [dict(r) for r in dbq(
        'SELECT id, name, workgroups, account, created_at FROM team_members ORDER BY id')]
    subtasks = [dict(r) for r in dbq(
        'SELECT id, card_id, title, done, sort, done_by, done_at, created_by, created_at, parent_id '
        'FROM card_subtasks ORDER BY card_id, sort')]
    boards = [dict(r) for r in dbq('SELECT * FROM boards ORDER BY sort, board_id')]
    columns = [dict(r) for r in dbq('SELECT * FROM board_columns ORDER BY id')]
    board_cfg = [dict(r) for r in dbq('SELECT * FROM board_config ORDER BY id')]
    # 组织架构（节点树 + 任职关系）—— 备份的一部分
    org_nodes = [dict(r) for r in dbq('SELECT * FROM org_nodes ORDER BY id')]
    org_apps = [dict(r) for r in dbq('SELECT * FROM org_appointments ORDER BY id')]
    workgroups = [dict(r) for r in dbq('SELECT * FROM workgroups ORDER BY id')]
    audit_log(username, client_ip(request), 'export', '数据导出',
              f'导出全局备份：事项 {len(cards)} 张、板块 {len(columns)} 个、'
              f'看板 {len(boards)} 个、子事项 {len(subtasks)} 条、成员 {len(teams)} 人', 'success')
    return {'exported_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'exported_by': username,
            'scope': 'global',
            'boards': boards,
            'columns': columns,
            'board_config': board_cfg,
            'cards': cards,
            'subtasks': subtasks,
            'team': teams,
            'org_nodes': org_nodes,
            'org_appointments': org_apps,
            'workgroups': workgroups}

class ImportReq(BaseModel):
    cards: List[dict] = []
    subtasks: List[dict] = []
    team: List[dict] = []
    # 2026-11-04 需求4：恢复面向全局 → 看板 / 板块 / 板块配置 / 组织架构
    boards: List[dict] = []
    columns: List[dict] = []
    board_config: List[dict] = []
    org_nodes: List[dict] = []
    org_appointments: List[dict] = []
    workgroups: List[dict] = []

@app.post('/api/import')
async def import_data(req: ImportReq, username: str = Depends(require_admin), request: Request = None):
    """恢复：覆盖式还原 JSON 备份（2026-11-04 需求4 —— 全局快照）

    覆盖范围：事项 / 子事项 / 成员 / 看板 / 板块 / 板块配置 / 组织架构节点与任职。
    ⚠️ 不涉及账号与密码（users 表）—— 账号体系独立管理。
    """
    if not (req.cards or req.team or req.subtasks or req.boards or req.columns
            or req.board_config or req.org_nodes or req.workgroups):
        raise HTTPException(400, '导入内容为空')
    conn = get_conn()
    try:
        # ---- 看板 ----
        if req.boards:
            conn.execute('DELETE FROM boards')
            for b in req.boards:
                if not b.get('board_id'):
                    continue
                cols = [k for k in ('board_id', 'board_name', 'workspace_id', 'owner',
                                    'participants', 'sort', 'created_at', 'copy_from')
                        if k in b]
                conn.execute(f'INSERT OR REPLACE INTO boards ({",".join(cols)}) '
                             f'VALUES ({",".join("?"*len(cols))})',
                             [b[k] for k in cols])
        # ---- 板块 ----
        if req.columns:
            conn.execute('DELETE FROM board_columns')
            for c in req.columns:
                if not c.get('col_key'):
                    continue
                cols = [k for k in ('col_key', 'column_id', 'board_id', 'column_name',
                                    'created_at', 'creator', 'nature', 'year', 'pinned',
                                    'copy_from', 'owner', 'participants', 'completion')
                        if k in c]
                conn.execute(f'INSERT OR REPLACE INTO board_columns ({",".join(cols)}) '
                             f'VALUES ({",".join("?"*len(cols))})',
                             [c[k] for k in cols])
        # ---- 板块配置 ----
        if req.board_config:
            conn.execute('DELETE FROM board_config')
            for bc in req.board_config:
                cols = [k for k in ('board_id', 'dept', 'dept_node_id', 'attr', 'status',
                                    'remark', 'created_at') if k in bc]
                if not cols:
                    continue
                conn.execute(f'INSERT OR REPLACE INTO board_config ({",".join(cols)}) '
                             f'VALUES ({",".join("?"*len(cols))})',
                             [bc[k] for k in cols])
        # ---- 工作组（架构兼容视图）----
        if req.workgroups:
            conn.execute('DELETE FROM workgroups')
            for w in req.workgroups:
                if not w.get('name'):
                    continue
                cols = [k for k in ('id', 'name', 'parent_id', 'leader', 'function',
                                    'boards', 'created_at') if k in w]
                conn.execute(f'INSERT OR REPLACE INTO workgroups ({",".join(cols)}) '
                             f'VALUES ({",".join("?"*len(cols))})',
                             [w[k] for k in cols])
        # ---- 组织架构节点 + 任职 ----
        if req.org_nodes:
            conn.execute('DELETE FROM org_appointments')
            conn.execute('DELETE FROM org_nodes')
            for n in req.org_nodes:
                if not n.get('name'):
                    continue
                cols = [k for k in ('id', 'name', 'node_type', 'parent_id', 'wg_id',
                                    'is_anchor', 'function', 'sort', 'created_at',
                                    'owner', 'participants') if k in n]
                conn.execute(f'INSERT OR REPLACE INTO org_nodes ({",".join(cols)}) '
                             f'VALUES ({",".join("?"*len(cols))})',
                             [n[k] for k in cols])
            for a in req.org_appointments:
                cols = [k for k in ('id', 'node_id', 'member_id', 'role_key',
                                    'is_primary', 'created_at') if k in a]
                if not cols:
                    continue
                conn.execute(f'INSERT OR REPLACE INTO org_appointments ({",".join(cols)}) '
                             f'VALUES ({",".join("?"*len(cols))})',
                             [a[k] for k in cols])
        # ---- 事项 ----
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
                    'INSERT INTO card_subtasks (id, card_id, title, done, sort, done_by, done_at, created_by, created_at, parent_id) '
                    'VALUES (?,?,?,?,?,?,?,?,?,?)',
                    (s.get('id', 0), s['card_id'], s.get('title', ''),
                     1 if s.get('done') else 0, s.get('sort', 0),
                     s.get('done_by', ''), s.get('done_at', ''),
                     s.get('created_by', ''), s.get('created_at', '') or time.strftime('%Y-%m-%d %H:%M:%S'),
                     s.get('parent_id', 0)))
        # ---- 成员 ----
        if req.team:
            conn.execute('DELETE FROM team_members')
            for n in req.team:
                name = n.get('name') if isinstance(n, dict) else n
                if name and str(name).strip():
                    conn.execute(
                        'INSERT INTO team_members (id, name, workgroups, account, created_at) '
                        'VALUES (?,?,?,?,?)',
                        (n.get('id', 0) if isinstance(n, dict) else 0, str(name).strip(),
                         (n.get('workgroups', '') if isinstance(n, dict) else ''),
                         (n.get('account', '') if isinstance(n, dict) else ''),
                         (n.get('created_at', '') if isinstance(n, dict) else '')
                         or time.strftime('%Y-%m-%d %H:%M:%S')))
        conn.commit()
    except Exception:
        # 连接是线程内复用的：出错必须回滚，否则未提交事务会留给该线程的后续请求
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    log_action('__import__', username, 'import',
               f'cards={len(req.cards)} team={len(req.team)} columns={len(req.columns)}')
    audit_log(username, client_ip(request), 'import', '数据导入',
              f'恢复全局备份：事项 {len(req.cards)} 张、板块 {len(req.columns)} 个、'
              f'看板 {len(req.boards)} 个、子事项 {len(req.subtasks)} 条、成员 {len(req.team)} 人',
              'success')
    await ws_mgr.broadcast({'type': 'card_update', 'card_id': '*', 'by': username})
    return {'ok': True, 'cards': len(req.cards), 'team': len(req.team),
            'columns': len(req.columns), 'boards': len(req.boards)}

# ---------------- API：从 xlsx 导入 TAPD 数据 ----------------
# 模板列（第一行为表头，列名即 TAPD 字段名）：
#   必填：card_name（事项名称）、board_name（所属看板）
#   选填：card_id / board_id / column_id / column_name / workspace_id / status /
#         status_name / creator / owner / cc / follower / begin / due /
#         completed / created / modified / description / label / b_sort
# 行为：追加式导入（已有数据不动），同 card_id 视为同一条则更新。
# 与 /api/import（JSON 覆盖式恢复）语义不同，两者并存。

# 模板中允许用户填写的列 -> cards 表列
XLSX_IMPORT_COLS = [
    'card_id', 'board_id', 'board_name', 'column_id', 'column_name', 'workspace_id',
    'card_name', 'status', 'status_name', 'priority', 'creator', 'owner', 'cc',
    'follower', 'begin', 'due', 'completed', 'created', 'modified', 'description',
    'label', 'b_sort', 'entity_type', 'cover_setted', 'is_filed', 'comments',
    'column_sort', 'board_status', 'board_creator',
]
XLSX_REQUIRED = ['card_name', 'board_name']

# 中文表头（模板展示用）+ 反向别名表（导入时兼容中英文两种表头）
XLSX_COL_LABELS = {
    'card_id': '事项ID',
    'board_id': '看板ID',
    'board_name': '所属看板名称',
    'column_id': '板块ID',
    'column_name': '板块名称',
    'workspace_id': '工作空间ID',
    'card_name': '事项名称',
    'status': '状态',
    'status_name': '状态显示名',
    'priority': '优先级',
    'creator': '创建人',
    'owner': '负责人',
    'cc': '知会人',
    'follower': '关注人',
    'begin': '开始日期',
    'due': '截止日期',
    'completed': '完成时间',
    'created': '创建时间',
    'modified': '修改时间',
    'description': '详细描述',
    'label': '标签',
    'b_sort': '排序值',
    'entity_type': '实体类型',
    'cover_setted': '是否有封面',
    'is_filed': '是否归档',
    'comments': '评论数',
    'column_sort': '板块排序值',
    'board_status': '看板状态',
    'board_creator': '看板创建人',
}


def _build_header_aliases():
    """表头别名表：中文名 / 英文名 / 去下划线英文名 → 内部字段名"""
    al = {}
    for k, v in XLSX_COL_LABELS.items():
        for key in (v, v.replace(' ', ''), k, k.replace('_', '')):
            al[str(key).strip().lower()] = k
    return al


XLSX_HEADER_ALIASES = _build_header_aliases()


def norm_xlsx_header(h):
    """归一化表头：去掉必填标记与空白，再查别名表（查不到就原样返回）"""
    s = str(h or '').strip()
    if not s:
        return ''
    # 去掉「*」「必填」「（必填）」等标注
    for junk in ('（必填）', '(必填)', '必填', '*', '＊'):
        s = s.replace(junk, '')
    s = s.strip().lower()
    s = re.sub(r'[\s_\-]+', '', s)
    return XLSX_HEADER_ALIASES.get(s, s)

# 状态归一：用户可能填中文「已完成」，转成系统内部状态值
XLSX_STATUS_MAP = {
    '已完成': 'done', '完成': 'done', 'done': 'done', '已关闭': 'done', 'closed': 'done',
    '进行中': 'progressing', '处理中': 'progressing', 'progressing': 'progressing',
    '未开始': 'open', '待处理': 'open', 'open': 'open', '未完成': 'open', 'todo': 'open',
}

@app.get('/api/import/template')
def download_import_template(username: str = Depends(require_auth)):
    """下载 TAPD 数据导入模板（.xlsx），含表头 + 字段说明 + 2 行示例"""
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter
    from urllib.parse import quote
    import io

    notes = {
        'card_name': '事项名称（必填）',
        'board_name': '所属看板名称（必填）',
        'card_id': '事项 ID（留空自动生成；与库中已有 ID 相同则更新该条）',
        'board_id': '看板 ID（留空自动生成）',
        'column_name': '板块名称（如 2026年第1/2周）',
        'column_id': '板块 ID',
        'workspace_id': 'TAPD 工作空间 ID',
        'status': '状态（open/progressing/done，也接受 已完成/进行中/未开始）',
        'status_name': '状态显示名（留空按状态自动生成）',
        'creator': '创建人',
        'owner': '负责人（多人用分号分隔）',
        'cc': '知会人（分号分隔）',
        'follower': '关注人（分号分隔）',
        'begin': '开始日期（YYYY-MM-DD）',
        'due': '截止日期（YYYY-MM-DD）',
        'completed': '完成时间',
        'created': '创建时间',
        'modified': '修改时间',
        'description': '详细描述',
        'label': '标签',
        'priority': '优先级',
        'b_sort': '排序值（数字）',
        'entity_type': '实体类型（默认 BoardCard）',
        'cover_setted': '是否有封面（0/1）',
        'is_filed': '是否归档（0/1）',
        'comments': '评论数',
        'column_sort': '板块排序值',
        'board_status': '看板状态（默认 open）',
        'board_creator': '看板创建人',
    }

    wb = Workbook()
    # Sheet1：导入数据（中文表头；必填列红色底 + 星号标注）
    ws = wb.active
    ws.title = '导入数据'
    headers = [(XLSX_COL_LABELS.get(c, c) + (' *' if c in XLSX_REQUIRED else ''))
               for c in XLSX_IMPORT_COLS]
    ws.append(headers)
    hdr_fill = PatternFill('solid', fgColor='002D74')
    req_fill = PatternFill('solid', fgColor='B42318')     # 必填列：红底
    hdr_font = Font(bold=True, color='FFFFFF', size=11)
    thin = Side(style='thin', color='D9D9D9')
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    for i, c in enumerate(XLSX_IMPORT_COLS, 1):
        cell = ws.cell(1, i)
        required = c in XLSX_REQUIRED
        cell.fill = req_fill if required else hdr_fill
        cell.font = hdr_font
        cell.alignment = Alignment(horizontal='center', vertical='center')
        cell.border = border
        ws.column_dimensions[get_column_letter(i)].width = 20 if required else 14
    ws.row_dimensions[1].height = 22
    # 两行示例 —— 用字典构造再按 COLS 顺序取值，避免手写列表导致列错位
    sample_a = {
        'card_name': '示例-事项A', 'board_name': '示例看板（2026年度）',
        'column_name': '2026年第1/2周（1.4-1.9）', 'status': 'open', 'status_name': '未开始',
        'creator': '张三', 'owner': '张三', 'begin': '2026-01-04', 'due': '2026-01-10',
        'created': '2026-01-02 09:00:00', 'modified': '2026-01-02 09:00:00',
        'description': '这是详细描述，可留空', 'b_sort': '1',
    }
    sample_b = {
        'card_name': '示例-事项B', 'board_name': '示例看板（2026年度）',
        'column_name': '2026年第1/2周（1.4-1.9）', 'status': 'done', 'status_name': '已完成',
        'creator': '李四', 'owner': '王五', 'begin': '2026-01-05', 'due': '2026-01-12',
        'completed': '2026-01-11 17:30:00', 'created': '2026-01-02 09:00:00',
        'modified': '2026-01-02 09:00:00', 'b_sort': '2',
    }
    for smp in (sample_a, sample_b):
        ws.append([smp.get(c, '') for c in XLSX_IMPORT_COLS])
    ws.freeze_panes = 'A2'
    ws.auto_filter.ref = ws.dimensions

    # Sheet2：字段说明
    ws2 = wb.create_sheet('字段说明')
    ws2.append(['列名', '是否必填', '说明'])
    for i, h in enumerate(['列名', '是否必填', '说明'], 1):
        cell = ws2.cell(1, i)
        cell.fill = hdr_fill
        cell.font = hdr_font
        cell.alignment = Alignment(horizontal='center', vertical='center')
        cell.border = border
    ws2.column_dimensions['A'].width = 20
    ws2.column_dimensions['B'].width = 12
    ws2.column_dimensions['C'].width = 56
    for col in XLSX_IMPORT_COLS:
        req = '必填' if col in XLSX_REQUIRED else '选填'
        label = XLSX_COL_LABELS.get(col, col)
        ws2.append([label + (' *' if col in XLSX_REQUIRED else ''), req, notes.get(col, '')])
    for r in range(2, ws2.max_row + 1):
        for c in range(1, 4):
            ws2.cell(r, c).border = border
            ws2.cell(r, c).alignment = Alignment(vertical='center')
        if ws2.cell(r, 2).value == '必填':
            ws2.cell(r, 2).font = Font(bold=True, color='B42318')
            ws2.cell(r, 1).font = Font(bold=True, color='B42318')

    # Sheet3：使用说明
    ws3 = wb.create_sheet('使用说明')
    for line in [
        ['TAPD 数据导入模板 · 使用说明'],
        [''],
        ['1. 填写「导入数据」工作表，第一行表头请勿修改、勿增删列。'],
        ['2. 表头为中文；带红色底色和 * 号的列是必填列，只有两列：'],
        ['   「事项名称 *」和「所属看板名称 *」，其余均可留空。'],
        ['3. 负责人 / 知会人 / 关注人 多人时用英文分号 ; 分隔。'],
        ['4. 导入为「追加式」：库中已有的数据不会被删除；'],
        ['   「事项ID」相同视为同一条事项，会更新该条；留空则自动生成。'],
        ['5. 导入的看板会自动登记到「看板管理」中，可在那边指定归属部门。'],
        ['6. 日期建议统一用 YYYY-MM-DD；Excel 单元格格式设为文本以免被自动转换。'],
        ['7. 以「示例」开头的事项名 / 看板名会被自动跳过，不会导入真实数据。'],
        ['8. 表头也兼容英文写法（如 card_name / board_name），两种写法都能识别。'],
        [''],
        ['示例数据为占位内容，正式导入前可自行删除（留着也不会被导入）。'],
    ]:
        ws3.append(line)
    ws3.column_dimensions['A'].width = 92
    ws3['A1'].font = Font(bold=True, size=13, color='002D74')

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    fn = 'TAPD数据导入模板_%s.xlsx' % time.strftime('%Y%m%d%H%M%S')
    return Response(
        content=buf.getvalue(),
        media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        headers={'Content-Disposition': "attachment; filename*=UTF-8''%s" % quote(fn, safe='')}
    )

@app.post('/api/import/xlsx')
async def import_xlsx(request: Request, username: str = Depends(require_editor)):
    """从上传的 .xlsx 导入 TAPD 数据（追加式，不删除既有数据）"""
    if 'multipart/form-data' not in (request.headers.get('content-type') or ''):
        raise HTTPException(400, '请以 multipart/form-data 方式上传 xlsx 文件')
    form = await request.form()
    up = form.get('file')
    if up is None:
        raise HTTPException(400, '未收到文件')
    raw = await up.read()
    if not raw:
        raise HTTPException(400, '文件为空')
    if not raw[:2] == b'PK':
        raise HTTPException(400, '不是有效的 xlsx 文件（请用 .xlsx 格式，不要用 .xls）')

    from openpyxl import load_workbook
    import io as _io
    try:
        wb = load_workbook(_io.BytesIO(raw), read_only=True, data_only=True)
    except Exception as ex:
        raise HTTPException(400, 'xlsx 解析失败：%s' % ex)

    # 优先读「导入数据」工作表，否则读第一个工作表
    ws = wb['导入数据'] if '导入数据' in wb.sheetnames else wb[wb.sheetnames[0]]
    rows = ws.iter_rows(values_only=True)
    try:
        header = next(rows)
    except StopIteration:
        raise HTTPException(400, 'xlsx 里没有数据行')
    # 表头归一：兼容中文表头与英文表头；自动去掉「*」「必填」等标注
    hmap = {}
    for i, h in enumerate(header):
        if h is None:
            continue
        key = norm_xlsx_header(h)
        if key:
            hmap[key] = i
    missing = [c for c in XLSX_REQUIRED if c not in hmap]
    if missing:
        raise HTTPException(400, '缺少必填列：%s'
                            % '、'.join(XLSX_COL_LABELS.get(c, c) for c in missing))

    conn = get_conn()
    created = updated = skipped = 0
    new_boards = {}
    try:
        for r in rows:
            if r is None or all(c is None or str(c).strip() == '' for c in r):
                continue
            def cell(name):
                i = hmap.get(name)
                if i is None or i >= len(r):
                    return ''
                v = r[i]
                if v is None:
                    return ''
                # 日期型单元格转成字符串，避免 2026-01-04 变成时间戳
                if hasattr(v, 'strftime'):
                    v = v.strftime('%Y-%m-%d %H:%M:%S')
                return str(v).strip()
            # ID 归一：从 Excel 导出的 ID 常带前后单引号（如 '116206979...），
            # 不去掉会导致与库中已有记录匹配不上、导入出重复数据
            def norm_id(v):
                return str(v).strip().strip("'").strip('"').strip()
            card_name = cell('card_name')
            board_name = cell('board_name')
            if not card_name or not board_name:
                skipped += 1
                continue
            # 示例行：以「示例」开头的事项名视为模板占位，不导入真实库
            if card_name.startswith('示例') or board_name.startswith('示例'):
                skipped += 1
                continue
            board_id = norm_id(cell('board_id')) or ('B' + str(int(time.time() * 1000)) + str(len(new_boards)))
            # 同一 xlsx 内同名的看板共用一个 board_id
            if board_name in new_boards:
                board_id = new_boards[board_name]
            else:
                new_boards[board_name] = board_id
                # 看板不存在则登记（不写 board_config，归属部门稍后由管理员在「看板管理」指定）
                if not dbq('SELECT 1 FROM boards WHERE board_id=?', (board_id,)):
                    dbe('INSERT OR IGNORE INTO boards (board_id, board_name, workspace_id, owner, sort, created_at) '
                        'VALUES (?,?,?,?,?,?)',
                        (board_id, board_name, cell('workspace_id'), cell('board_creator') or username, 0,
                         time.strftime('%Y-%m-%d %H:%M:%S')))
            card_id = norm_id(cell('card_id')) or ('C' + str(int(time.time() * 1000000)) + str(created + updated))
            status = cell('status').lower()
            status = XLSX_STATUS_MAP.get(status, status) or 'open'
            status_name = cell('status_name') or {'done': '已完成', 'progressing': '进行中', 'open': '未完成'}.get(status, '未完成')
            vals = {
                'card_id': card_id, 'board_id': board_id, 'board_name': board_name,
                'column_id': norm_id(cell('column_id')), 'column_name': cell('column_name'),
                'workspace_id': norm_id(cell('workspace_id')), 'card_name': card_name,
                'status': status, 'status_name': status_name,
                'priority': cell('priority'), 'creator': cell('creator') or username,
                'owner': cell('owner'), 'cc': cell('cc'), 'follower': cell('follower'),
                'begin': cell('begin'), 'due': cell('due'), 'completed': cell('completed'),
                'created': cell('created') or time.strftime('%Y-%m-%d %H:%M:%S'),
                'modified': cell('modified') or time.strftime('%Y-%m-%d %H:%M:%S'),
                'description': cell('description'), 'attachment_count': '0',
                'label': cell('label'), 'b_sort': cell('b_sort') or '0',
                'entity_type': cell('entity_type') or 'BoardCard',
                'cover_setted': cell('cover_setted') or '0', 'cover_info': '',
                'is_filed': cell('is_filed') or '0', 'created_from': '',
                'date_status': '', 'due_time_ux': cell('due'), 'begin_date_status': '',
                'begin_time_ux': cell('begin'), 'comments': cell('comments') or '0',
                'column_sort': cell('column_sort') or '0',
                'board_status': cell('board_status') or 'open',
                'board_creator': cell('board_creator'), 'parent_id': '', 'version': '1', 'deleted': '0',
            }
            exists = dbq('SELECT 1 FROM cards WHERE card_id=?', (card_id,))
            cols = [k for k in CARD_FIELDS if k in vals]
            conn.execute(f'INSERT OR REPLACE INTO cards ({",".join(cols)}) VALUES ({",".join("?"*len(cols))})',
                         [vals[k] for k in cols])
            if exists:
                updated += 1
            else:
                created += 1
        conn.commit()
    except HTTPException:
        conn.rollback()
        raise
    except Exception as ex:
        conn.rollback()
        raise HTTPException(500, '写入失败：%s' % ex)

    log_action('__import_xlsx__', username, 'import', f'created={created} updated={updated} skipped={skipped}')
    audit_log(username, client_ip(request), 'import_xlsx', 'xlsx 数据导入',
              f'新增 {created} 条、更新 {updated} 条、跳过 {skipped} 条', 'success')
    await ws_mgr.broadcast({'type': 'card_update', 'card_id': '*', 'by': username})
    return {'ok': True, 'created': created, 'updated': updated, 'skipped': skipped,
            'boards': len(new_boards)}


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

# 默认占位图（用户未上传头像/个人照片时统一展示）。
# 用白名单而非通用静态目录挂载 —— 避免路径穿越把任意文件暴露出去。
_STATIC_FILES = {
    '/static/default-photo.jpg': 'default-photo.jpg',
}

@app.get('/static/{filename}')
def static_asset(filename: str):
    real = _STATIC_FILES.get('/static/' + filename)
    if not real:
        raise HTTPException(404, '资源不存在')
    path = os.path.join(STATIC_DIR, real)
    if not os.path.isfile(path):
        raise HTTPException(404, '资源不存在')
    return FileResponse(path, headers={'Cache-Control': 'public, max-age=86400'})

# ---------------- 启动初始化：确保数据表存在（含 workgroups 表） ----------------
try:
    from app.init_db import init_db
    init_db()
except Exception as e:
    print('WARN: init_db() 失败:', e)
