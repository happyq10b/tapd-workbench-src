# -*- coding: utf-8 -*-
"""
分级权限内核（2026-11-02）

层级结构：**架构 > 看板 > 板块 > 事项**
（架构 = org_nodes 节点；看板 = boards；板块 = board_columns；事项 = cards）

角色（自上而下继承 —— 上级角色拥有下级角色的全部权限）：

| 等级 | 角色 | 作用域 | 说明 |
|---|---|---|---|
| 0 | 超管 SUPER_ADMIN | 全局 | 唯一能配置「管理员」角色的人 |
| 1 | 管理员 ADMIN | 全局 | 超脱于本体系，拥有全部权限；但**不能配置管理员权限** |
| 2 | 架构负责人 ARCH_OWNER | 架构节点（含后代） | 可增删改所属架构下的看板，指派看板负责人 |
| 3 | 看板负责人 BOARD_OWNER | 看板（含其下板块/事项） | 可增删改本看板，可增删改其下板块，指派板块负责人与参与人 |
| 4 | 板块负责人 COLUMN_OWNER | 板块（含其下事项） | 可删改本板块并指定参与人；可增删改其下事项，指派事项负责人与参与人 |
| 5 | 事项负责人 CARD_OWNER | 事项 | 可删改本事项并指定事项参与人 |
| 6 | 参与人 PARTICIPANT | 事项 / 板块 | 可修改自己参与的事项、板块的可见内容；**无增删与指派权** |

设计要点
--------
1. **继承**：`effective_level()` 沿「事项 → 板块 → 看板 → 架构」向上回溯，
   任一层命中负责人/参与人身份即取得该层能力；上级层的角色**天然包含**下级层能力
   （体现在 `LEVEL_CAPABILITY` 的能力集合上）。
2. **双口径身份匹配**：现状里 `cards.owner/cc` 存**姓名**，`boards.owner` /
   `board_columns.owner` 存**账号**。内核统一用 `identity_names(username)`
   同时匹配「账号」与「绑定成员姓名」，两套口径都能命中。
3. **fail-closed**：未配置负责人/参与人的资源，其上层权限依然有效；
   但资源本身无任何负责人时，**只有管理员与超管**能改它。
4. **即时失效**：权限判定每次实时查库（无缓存），
   「被移除负责人后权限立即失效」是天然成立的。
5. **越权统一形式**：抛 `PermError`，由 app.py 的异常处理器转成
   HTTP 403 + 统一错误体 `{"error":"PERMISSION_DENIED", "code":..., "message":...}`。
"""
import re

# ---------------- 角色等级 ----------------
LV_NONE = 0
LV_PARTICIPANT = 1
LV_CARD_OWNER = 2
LV_COLUMN_OWNER = 3
LV_BOARD_OWNER = 4
LV_ARCH_OWNER = 5
LV_ADMIN = 6
LV_SUPER = 7

ROLE_NAMES = {
    LV_NONE: '无权限',
    LV_PARTICIPANT: '参与人',
    LV_CARD_OWNER: '事项负责人',
    LV_COLUMN_OWNER: '板块负责人',
    LV_BOARD_OWNER: '看板负责人',
    LV_ARCH_OWNER: '架构负责人',
    LV_ADMIN: '管理员',
    LV_SUPER: '超级管理员',
}

# ---------------- 操作码 ----------------
# 资源层级：ARCH / BOARD / COLUMN / CARD
OP_VIEW = 'view'
OP_CREATE = 'create'      # 新增下级资源
OP_UPDATE = 'update'      # 修改本资源（基本信息）
OP_DELETE = 'delete'      # 删除本资源
OP_ASSIGN_OWNER = 'assign_owner'          # 指派本资源负责人
OP_ASSIGN_PARTICIPANT = 'assign_participant'  # 指派本资源参与人
OP_EDIT_CONTENT = 'edit_content'          # 修改「可见内容」（参与人可做）

ALL_OPS = (OP_VIEW, OP_CREATE, OP_UPDATE, OP_DELETE,
           OP_ASSIGN_OWNER, OP_ASSIGN_PARTICIPANT, OP_EDIT_CONTENT)

# 操作码 → 允许执行的最低角色等级
OP_MIN_LEVEL = {
    OP_VIEW: LV_PARTICIPANT,
    # 参与人可改「可见内容」—— 比 OP_UPDATE 更宽松的一档。
    # ⚠️ OP_EDIT_CONTENT 与 OP_UPDATE 的区别：
    #   EDIT_CONTENT = 参与人也能做（改事项内容/描述等，不含增删与指派）
    #   UPDATE      = 至少负责人级（改资源的**归属类**信息，如负责人、状态）
    OP_EDIT_CONTENT: LV_PARTICIPANT,
    OP_UPDATE: LV_CARD_OWNER,          # 改本资源基本信息：至少事项负责人
    OP_DELETE: LV_CARD_OWNER,
    OP_ASSIGN_PARTICIPANT: LV_CARD_OWNER,
    OP_ASSIGN_OWNER: LV_CARD_OWNER,    # 指派负责人：上级层可指派下级
    OP_CREATE: LV_COLUMN_OWNER,        # 新增下级资源
}

# 操作码 → 允许执行该操作的**资源层级**（资源自身的层级，不是角色等级）
#
# ⚠️ 关键区分（这是本内核最容易搞错的地方）：
#   · `resource_level` = **目标资源在哪一层**（架构/看板/板块/事项）
#   · `have_level`     = **操作者持有的角色等级**（参与人…超管）
#   两者是**不同维度**，不能混用！
#   例：架构负责人（have=5）要改一个事项（resource=LV_CARD_OWNER）→ 完全合法。
#
# 所以这里的元组是「资源层级」的集合，用**资源层级的编号**表示。
RES_ARCH = LV_ARCH_OWNER      # 架构层资源
RES_BOARD = LV_BOARD_OWNER    # 看板层资源
RES_COLUMN = LV_COLUMN_OWNER  # 板块层资源
RES_CARD = LV_CARD_OWNER      # 事项层资源

ALL_RES = (RES_ARCH, RES_BOARD, RES_COLUMN, RES_CARD)

# 「新增」只能作用于**下级**资源：看板层 → 板块层，板块层 → 事项层
OP_TARGET_LEVEL = {
    OP_VIEW: ALL_RES,
    OP_EDIT_CONTENT: ALL_RES,
    OP_UPDATE: ALL_RES,
    OP_DELETE: ALL_RES,
    OP_ASSIGN_OWNER: ALL_RES,
    OP_ASSIGN_PARTICIPANT: ALL_RES,
    OP_CREATE: (RES_BOARD, RES_COLUMN, RES_CARD),
}

# 各资源层级的「资源标识符」，用于拼错误信息
LEVEL_KEY = {RES_ARCH: 'arch', RES_BOARD: 'board',
             RES_COLUMN: 'column', RES_CARD: 'card'}


class PermError(Exception):
    """权限拒绝的统一异常。

    ⚠️ 由 app.py 注册异常处理器，转成 HTTP 403 + 统一错误体。
    `code` 用于程序判断，`message` 面向用户。
    """

    def __init__(self, code, message, need_level=LV_NONE, have_level=LV_NONE,
                 resource=None, op=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.need_level = need_level
        self.have_level = have_level
        self.resource = resource
        self.op = op

    def to_dict(self):
        return {
            'error': 'PERMISSION_DENIED',
            'code': self.code,
            'message': self.message,
            'need_level': self.need_level,
            'need_role': ROLE_NAMES.get(self.need_level, '?'),
            'have_level': self.have_level,
            'have_role': ROLE_NAMES.get(self.have_level, '?'),
            'resource': self.resource,
            'op': self.op,
        }


# 错误码
E_DENIED = 'PERMISSION_DENIED'
E_CROSS_SCOPE = 'CROSS_SCOPE_DENIED'      # 跨架构越权
E_NOT_OWNER = 'NOT_OWNER'                  # 需要负责人身份但操作者不是
E_NOT_MEMBER = 'NOT_PARTICIPANT'           # 需要参与人身份但操作者不是
E_LEVEL = 'LEVEL_INSUFFICIENT'             # 角色等级不足
E_ADMIN_ONLY = 'ADMIN_ONLY'                # 仅管理员/超管
E_SELF_LOCK = 'SELF_LOCK_DENIED'           # 不能自我降权导致失权


# ---------------- 身份解析 ----------------
def _split_list(raw):
    """逗号 / 分号分隔的名单 → 集合（去空白、去空项）"""
    if not raw:
        return set()
    return {x.strip() for x in re.split(r'[,;、]', str(raw)) if x.strip()}


def identity_names(username, dbq=None):
    """操作者的**全部身份标识**：登录账号 + 绑定的成员姓名。

    ⚠️ 为什么需要双口径：现状里 `cards.owner/cc` 存**中文姓名**，
    而 `boards.owner` / `board_columns.owner` 存**登录账号**。
    内核统一按「账号 或 姓名」匹配，两种存量口径都能命中。

    姓名取自 `team_members.account = username` 的那一行（一名成员一个账号）。
    同名不同账号时，只要有一个匹配即算命中（fail-open 于身份识别，
    但真正的权限判定仍受账号级约束，不放大写权限）。
    """
    names = {username}
    if dbq is None:
        return names
    try:
        rows = dbq('SELECT name FROM team_members WHERE account=? LIMIT 1', (username,))
        if rows and rows[0]['name']:
            names.add(rows[0]['name'])
    except Exception:
        pass
    return names


def _matches(actor_names, stored_list):
    """操作者身份集合与资源上记录的（负责人/参与人）是否相交"""
    return bool(actor_names & stored_list)


# ---------------- 资源定位 ----------------
def resource_chain(dbq, board_id=None, column_id=None, card_id=None):
    """把资源标识解析成 **架构 → 看板 → 板块 → 事项** 的完整祖先链。

    返回 dict：
        {'arch': {...} | None, 'board': {...} | None,
         'column': {...} | None, 'card': {...} | None}

    ⚠️ 每一层都可能是 None（如事项没有登记板块元信息），
    判定时逐层跳过，**不允许**因为中间层缺失就放行。
    """
    chain = {'arch': None, 'board': None, 'column': None, 'card': None}

    if card_id:
        r = dbq('SELECT card_id, board_id, column_id, owner, cc FROM cards'
                ' WHERE card_id=? AND deleted=0', (card_id,))
        if not r:
            raise PermError(E_DENIED, '事项不存在或已删除', resource={'card_id': card_id})
        chain['card'] = dict(r[0])
        board_id = chain['card']['board_id']
        column_id = chain['card']['column_id']

    if column_id and not chain['column']:
        r = dbq('SELECT column_id, col_key, board_id, owner, participants FROM board_columns'
                ' WHERE column_id=? LIMIT 1', (column_id,))
        if r:
            chain['column'] = dict(r[0])
            board_id = chain['column']['board_id']

    if board_id and not chain['board']:
        r = dbq('SELECT board_id, board_name, owner, participants FROM boards'
                ' WHERE board_id=? LIMIT 1', (board_id,))
        if r:
            chain['board'] = dict(r[0])

    # 看板 → 架构节点（经 board_config.dept_node_id）
    if chain['board']:
        r = dbq('SELECT dept_node_id FROM board_config WHERE board_id=? LIMIT 1',
                (chain['board']['board_id'],))
        node_id = r[0]['dept_node_id'] if r else 0
        if node_id:
            r = dbq('SELECT id, name, node_type, parent_id, owner, participants'
                    ' FROM org_nodes WHERE id=? LIMIT 1', (node_id,))
            if r:
                chain['arch'] = dict(r[0])
    return chain


def _arch_leader_nodes(dbq, username):
    """该用户担任「架构负责人」的节点 id 集合 —— **两个来源的并集**。

    来源 A：`org_nodes.owner` 字段（显式配置的架构负责人）
    来源 B：`org_appointments` 里担任负责人岗位
             （`center_head` / `gm` / `dept_head` / `group_leader`，
               与 `org_roles` 的 unique_slot=1 岗位一致）

    ⚠️ 两套来源并存是**有意的**：来源 B 是历史机制（架构管理里的岗位任命），
    来源 A 是本轮新增的显式配置。两者都表示「这个人是这个架构的负责人」，
    取并集 → 已有配置立即生效，新配置也能用。
    兼容两套身份口径：登录账号 与 成员姓名。
    """
    names = identity_names(username, dbq)
    marks = ','.join('?' * len(names))
    out = set()
    # 来源 A：显式配置的架构负责人
    rows = dbq('SELECT id FROM org_nodes WHERE owner IN (%s)' % marks, tuple(names))
    out.update(r['id'] for r in rows)
    # 来源 B：岗位任命
    rows = dbq(
        "SELECT DISTINCT a.node_id FROM org_appointments a"
        " JOIN team_members m ON m.id=a.member_id"
        " WHERE a.role_key IN ('center_head','gm','dept_head','group_leader')"
        " AND (m.account IN (%s) OR m.name IN (%s))" % (marks, marks),
        tuple(names) + tuple(names))
    out.update(r['node_id'] for r in rows)
    return out


def _arch_scope_nodes(dbq, username):
    """架构负责人覆盖的节点集合 = 其负责节点 + 全部后代节点。

    ⚠️ 沿父链向上收集：某人被任命为「财务中心负责人」时，
    其管辖范围包含所有后代节点（部门、组）。
    """
    leader_nodes = _arch_leader_nodes(dbq, username)
    if not leader_nodes:
        return set()
    nmap = {r['id']: dict(r) for r in
            dbq('SELECT id, name, node_type, parent_id FROM org_nodes')}
    scope = set()
    for nid in leader_nodes:
        scope.add(nid)
        stack = [nid]
        while stack:
            cur = stack.pop()
            for cid, n in nmap.items():
                if n['parent_id'] == cur:
                    scope.add(cid)
                    stack.append(cid)
    return scope


# ---------------- 角色判定 ----------------
def effective_level(dbq, username, chain):
    """算出操作者对**这条资源链末端资源**的有效角色等级。

    判定顺序（自下而上，取**最高**等级）：
      1. 事项层：cards.owner 命中 → LV_CARD_OWNER；cards.cc 命中 → LV_PARTICIPANT
      2. 板块层：board_columns.owner 命中 → LV_COLUMN_OWNER；participants 命中 → LV_PARTICIPANT
      3. 看板层：boards.owner 命中 → LV_BOARD_OWNER；participants 命中 → LV_PARTICIPANT
      4. 架构层：org_nodes.owner 命中 → LV_ARCH_OWNER；participants 命中 → LV_PARTICIPANT
                 另：担任负责人岗位（部门长/组长/中心负责人/总经理）→ LV_ARCH_OWNER

    ⚠️ **负责人同时是参与人**（边界情形）：
       负责人身份**优先** —— 同一层上 owner 命中即取该层负责人等级，
       不因同时出现在 participants 里而降级。
       例：某人是某板块的负责人且也是参与人 → 有效等级 = 板块负责人，
       他可删改该板块（若仅是参与人则不能）。
    """
    actor = identity_names(username, dbq)

    lv = LV_NONE

    # ① 事项层
    card = chain.get('card')
    if card:
        if _matches(actor, {card['owner']} if card['owner'] else set()):
            lv = max(lv, LV_CARD_OWNER)
        if _matches(actor, _split_list(card['cc'])):
            lv = max(lv, LV_PARTICIPANT)

    # ② 板块层
    col = chain.get('column')
    if col:
        if _matches(actor, {col['owner']} if col['owner'] else set()):
            lv = max(lv, LV_COLUMN_OWNER)
        if _matches(actor, _split_list(col['participants'])):
            lv = max(lv, LV_PARTICIPANT)

    # ③ 看板层
    board = chain.get('board')
    if board:
        if _matches(actor, {board['owner']} if board['owner'] else set()):
            lv = max(lv, LV_BOARD_OWNER)
        if _matches(actor, _split_list(board['participants'])):
            lv = max(lv, LV_PARTICIPANT)

    # ④ 架构层
    arch = chain.get('arch')
    if arch:
        if _matches(actor, {arch['owner']} if arch['owner'] else set()):
            lv = max(lv, LV_ARCH_OWNER)
        if _matches(actor, _split_list(arch['participants'])):
            lv = max(lv, LV_PARTICIPANT)
    # 架构负责人岗位任命（覆盖该节点及其全部后代）
    scope = _arch_scope_nodes(dbq, username)
    if arch and scope:
        # 沿父链找：该用户负责的节点是否是当前架构节点或其祖先
        nmap = {r['id']: dict(r) for r in
                dbq('SELECT id, parent_id FROM org_nodes')}
        cur = arch['id']
        guard = 0
        while cur and guard < 30:
            guard += 1
            if cur in scope:
                lv = max(lv, LV_ARCH_OWNER)
                break
            cur = nmap.get(cur, {}).get('parent_id') or 0
    return lv


def has_role(dbq, username, chain, min_level):
    """操作者对资源是否达到指定角色等级"""
    return effective_level(dbq, username, chain) >= min_level


# ---------------- 操作许可 ----------------
def can_do(dbq, username, chain, op, resource_level, is_admin=False,
           is_super=False, admin_can_assign_admin=False):
    """判定操作者能否对目标资源执行某操作。

    参数
    ----
    chain        : resource_chain() 的结果
    op           : OP_* 操作码
    resource_level: 目标资源所在层级（LV_ARCH_OWNER/BOARD/COLUMN/CARD）
    is_admin     : 是否管理员（超脱体系，拥有全部权限）
    is_super     : 是否超级管理员

    返回 (allowed: bool, reason: dict)
    """
    # ① 超管：全部权限
    if is_super:
        return True, {'reason': 'super_admin'}

    # ② 管理员：超脱体系，全部权限；**但不能配置管理员权限**
    #    （resource_level == LV_ADMIN 表示「账号/管理员角色」这一虚拟资源层）
    if is_admin and not (op == OP_ASSIGN_OWNER and resource_level == LV_ADMIN):
        return True, {'reason': 'admin'}

    need = OP_MIN_LEVEL.get(op, LV_CARD_OWNER)
    have = effective_level(dbq, username, chain)

    # ③ 层级约束：操作码是否适用于该**资源层级**
    #    ⚠️ resource_level 是「资源在哪一层」，与 have_level（角色等级）是不同维度。
    allowed_levels = OP_TARGET_LEVEL.get(op, ())
    if resource_level not in allowed_levels:
        return False, {'reason': 'level_mismatch', 'need_level': need,
                       'have_level': have}

    # ④ 角色等级：达到门槛即放行（这就是「继承」—— 上级角色等级更高，自然覆盖下级）
    if have >= need:
        return True, {'reason': 'granted', 'level': have}

    # ④ 失败：给出可读的拒绝原因
    if have == LV_NONE:
        code = E_DENIED
    elif need == LV_CARD_OWNER and have == LV_PARTICIPANT:
        code = E_NOT_OWNER
    else:
        code = E_LEVEL
    return False, {'reason': code, 'need_level': need, 'have_level': have}


def can_do_level(dbq, username, chain, op, resource_level, min_level,
                 is_admin=False, is_super=False):
    """同 `can_do`，但**自定义最低角色等级**。

    ⚠️ 为什么需要它：有些操作的门槛与「操作码默认值」不同 ——
    例：`OP_EDIT_CONTENT` 默认门槛是参与人级，但对**事项**来说
    「指派事项负责人」的门槛是板块负责人级。
    门槛与「资源层级」必须分开表达。
    """
    if is_super:
        return True, {'reason': 'super_admin'}
    if is_admin:
        return True, {'reason': 'admin'}
    allowed_levels = OP_TARGET_LEVEL.get(op, ())
    if resource_level not in allowed_levels:
        return False, {'reason': 'level_mismatch', 'need_level': min_level,
                       'have_level': LV_NONE}
    have = effective_level(dbq, username, chain)
    if have >= min_level:
        return True, {'reason': 'granted', 'level': have}
    if have == LV_NONE:
        code = E_DENIED
    elif min_level == LV_CARD_OWNER and have == LV_PARTICIPANT:
        code = E_NOT_OWNER
    else:
        code = E_LEVEL
    return False, {'reason': code, 'need_level': min_level, 'have_level': have}


def require_perm_level(dbq, username, chain, op, resource_level, min_level,
                       resource_desc='', is_admin=False, is_super=False):
    # 自定义门槛的校验入口 —— 不通过则抛 PermError。
    ok, info = can_do_level(dbq, username, chain, op, resource_level, min_level,
                             is_admin=is_admin, is_super=is_super)
    if ok:
        return info
    need = info.get('need_level', min_level)
    have = info.get('have_level', LV_NONE)
    code = info.get('reason', E_DENIED)
    msg = ('无权执行「%s」：需要「%s」及以上，当前身份为「%s」%s'
           % (op, ROLE_NAMES.get(need, '?'), ROLE_NAMES.get(have, '无权限'),
              ('（目标：%s）' % resource_desc) if resource_desc else ''))
    raise PermError(code, msg, need_level=need, have_level=have,
                    resource=resource_desc, op=op)


def require_perm(dbq, username, chain, op, resource_level, resource_desc='',
            is_admin=False, is_super=False):
    """权限校验入口 —— 不通过则抛 `PermError`。"""
    ok, info = can_do(dbq, username, chain, op, resource_level,
                      is_admin=is_admin, is_super=is_super)
    if ok:
        return info
    need = info.get('need_level', LV_CARD_OWNER)
    have = info.get('have_level', LV_NONE)
    code = info.get('reason', E_DENIED)
    msg = ('无权执行「%s」：需要「%s」及以上，当前身份为「%s」%s'
           % (op, ROLE_NAMES.get(need, '?'), ROLE_NAMES.get(have, '无权限'),
              ('（目标：%s）' % resource_desc) if resource_desc else ''))
    raise PermError(code, msg, need_level=need, have_level=have,
                    resource=resource_desc, op=op)


# ---------------- 越权范围检查（跨架构） ----------------
def assert_same_arch(dbq, chain_a, chain_b):
    """跨架构越权检查：两个资源不在同一架构分支下 → 拒绝。

    ⚠️ 边界情形：
      · 任一链的 arch 为 None（资源未挂架构）→ 放行（由管理员/负责人自行判定）
      · arch id 相同 → 同一架构，放行
      · 一方是另一方的祖先 → 同一架构分支，放行
      · 否则 → 跨架构，拒绝
    """
    a = (chain_a or {}).get('arch')
    b = (chain_b or {}).get('arch')
    if not a or not b:
        return True
    if a['id'] == b['id']:
        return True
    nmap = {r['id']: dict(r) for r in dbq('SELECT id, parent_id FROM org_nodes')}
    # b 是否是 a 的祖先
    cur = b['id']
    guard = 0
    while cur and guard < 30:
        guard += 1
        if cur == a['id']:
            return True
        cur = nmap.get(cur, {}).get('parent_id') or 0
    # a 是否是 b 的祖先
    cur = a['id']
    guard = 0
    while cur and guard < 30:
        guard += 1
        if cur == b['id']:
            return True
        cur = nmap.get(cur, {}).get('parent_id') or 0
    raise PermError(E_CROSS_SCOPE,
                    '跨架构越权：目标资源不在操作者所属架构下',
                    resource='arch:%s vs arch:%s' % (a['id'], b['id']))
