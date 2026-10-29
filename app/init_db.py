# -*- coding: utf-8 -*-
"""数据库初始化：建表 + 首次导入宽表 CSV"""
import sqlite3, csv, os, json

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'app.db')
CSV_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data', '全部看板_2026年度_总宽表.csv')

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS cards (
    card_id        TEXT PRIMARY KEY,
    board_id       TEXT NOT NULL,
    board_name     TEXT NOT NULL DEFAULT '',
    column_id      TEXT NOT NULL DEFAULT '',
    column_name    TEXT NOT NULL DEFAULT '',
    workspace_id   TEXT NOT NULL DEFAULT '',
    card_name      TEXT NOT NULL DEFAULT '',
    status         TEXT NOT NULL DEFAULT '',
    status_name    TEXT NOT NULL DEFAULT '',
    priority       TEXT NOT NULL DEFAULT '',
    creator        TEXT NOT NULL DEFAULT '',
    owner          TEXT NOT NULL DEFAULT '',
    cc             TEXT NOT NULL DEFAULT '',
    follower       TEXT NOT NULL DEFAULT '',
    begin          TEXT NOT NULL DEFAULT '',
    due            TEXT NOT NULL DEFAULT '',
    completed      TEXT NOT NULL DEFAULT '',
    created        TEXT NOT NULL DEFAULT '',
    modified       TEXT NOT NULL DEFAULT '',
    description    TEXT NOT NULL DEFAULT '',
    attachment_count TEXT NOT NULL DEFAULT '',
    label          TEXT NOT NULL DEFAULT '',
    b_sort         TEXT NOT NULL DEFAULT '',
    entity_type    TEXT NOT NULL DEFAULT '',
    cover_setted   TEXT NOT NULL DEFAULT '',
    cover_info     TEXT NOT NULL DEFAULT '',
    is_filed       TEXT NOT NULL DEFAULT '',
    created_from   TEXT NOT NULL DEFAULT '',
    date_status    TEXT NOT NULL DEFAULT '',
    due_time_ux    TEXT NOT NULL DEFAULT '',
    begin_date_status TEXT NOT NULL DEFAULT '',
    begin_time_ux  TEXT NOT NULL DEFAULT '',
    comments       TEXT NOT NULL DEFAULT '',
    column_sort    TEXT NOT NULL DEFAULT '',
    board_status   TEXT NOT NULL DEFAULT '',
    board_creator  TEXT NOT NULL DEFAULT '',
    parent_id      TEXT NOT NULL DEFAULT '',
    version        INTEGER NOT NULL DEFAULT 1,
    deleted        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_cards_board ON cards(board_id);
CREATE INDEX IF NOT EXISTS idx_cards_status ON cards(status);
CREATE INDEX IF NOT EXISTS idx_cards_deleted ON cards(deleted);
CREATE INDEX IF NOT EXISTS idx_cards_parent ON cards(parent_id);

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'viewer',   -- viewer/editor/admin
    allowed_boards TEXT NOT NULL DEFAULT '*',        -- '*' 或逗号分隔 board_id
    allowed_columns TEXT NOT NULL DEFAULT '*',       -- '*' 或 JSON {board_id:[column_id,...]} 板块级细分
    created_at    TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS team_members (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    workgroups TEXT NOT NULL DEFAULT '',        -- 所属工作组（原 groups），分号分隔工作组名
    account    TEXT NOT NULL DEFAULT '',        -- 关联登录账号 users.username，可空
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS workgroups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    parent_id   INTEGER NOT NULL DEFAULT 0,    -- 上级工作组 id，0=顶层部门
    leader      TEXT NOT NULL DEFAULT '',      -- 组长，必须存在于 team_members.name
    function    TEXT NOT NULL DEFAULT '',      -- 职能（非必填）
    boards      TEXT NOT NULL DEFAULT '',      -- 板块绑定：'*'=全部，逗号分隔 board_id，空=未绑定（跟随账号权限）
    created_at  TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE(parent_id, name)
);

CREATE TABLE IF NOT EXISTS boards (
    board_id      TEXT PRIMARY KEY,
    board_name    TEXT NOT NULL DEFAULT '',
    workspace_id  TEXT NOT NULL DEFAULT '',   -- TAPD 工作空间 ID（可空）
    owner         TEXT NOT NULL DEFAULT '',    -- 看板负责人
    sort          INTEGER NOT NULL DEFAULT 0,  -- 排序权重（小在前）
    created_at    TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_boards_sort ON boards(sort, board_id);

-- 看板管理（配置板块）：年份 / 归属部门 / 属性 / 状态 四维配置
-- 归属部门不再用固定枚举，改由【架构管理】的部门层级决定：
--   dept         归属部门名称（冗余存储，便于按名称分组展示）
--   dept_node_id 归属部门对应的 org_nodes.id（权威关联；0=未配置）
-- 年份/属性/状态的枚举仍由 CHECK 约束限定。
CREATE TABLE IF NOT EXISTS board_config (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    board_id    TEXT NOT NULL DEFAULT '',
    year        TEXT NOT NULL CHECK (year IN ('2025','2026','2027','2028','2029','2030')),
    dept        TEXT NOT NULL DEFAULT '',
    dept_node_id INTEGER NOT NULL DEFAULT 0,
    attr        TEXT NOT NULL CHECK (attr IN ('日常','专项')),
    status      TEXT NOT NULL DEFAULT '启用' CHECK (status IN ('启用','封存')),
    remark      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE(board_id)
);
CREATE INDEX IF NOT EXISTS idx_board_config ON board_config(year, dept, attr);
-- 注：idx_board_config_dept 依赖 dept_node_id，老库需先补列才能建索引，
--     统一放在 _migrate_schema() 的 ALTER/重建之后创建。

-- ============================================================
-- 组织架构（新模型）
--
-- 与旧表 workgroups 的关系：
--   workgroups 保留为「架构节点」的兼容视图（id/name/parent_id/boards 等），
--   旧权限逻辑（_leader_boards / _group_boards）继续读它，零改动。
--   本组三张表承载新需求：节点类型、岗位角色、多重归属（一人多岗）。
--
-- org_nodes —— 架构节点（一棵树）
--   node_type 决定它能有哪些岗位、能挂在什么下面：
--     center  中心（顶级，唯一，parent_id=0）
--     dept    部门（挂在中心下）
--     group   常规小组（挂在部门下）
--     special 专项小组（可挂在中心或部门下 —— 跨部门临时协作）
--   is_anchor=1 表示该节点同时是 workgroups 中的可见节点（数据同源）。
--
-- org_roles —— 岗位定义（节点类型 → 可设岗位）
--   unique_slot=1 表示该岗位在一个节点内**至多一人**（组长/部门长/中心负责人…），
--   unique_slot=0 表示**可多人**（组员/骨干…）。
--
-- org_appointments —— 任职关系（人与节点的多对多 + 岗位）
--   同一节点同一人同一岗位唯一（UNIQUE(node_id,member_id,role)）；
--   同一节点同一人可担任多个岗位（一人多岗）；
--   同一人可在多个节点任职（一人多组织）。
--   唯一性由「节点内岗位唯一槽位」在应用层保证（DB 层用 partial unique index）。
-- ============================================================
CREATE TABLE IF NOT EXISTS org_nodes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    node_type   TEXT NOT NULL DEFAULT 'group'
                CHECK (node_type IN ('center','dept','group','special')),
    parent_id   INTEGER NOT NULL DEFAULT 0,   -- 上级节点 id；0=顶级（中心）
    wg_id       INTEGER NOT NULL DEFAULT 0,   -- 关联 workgroups.id（兼容视图），0=未关联
    is_anchor   INTEGER NOT NULL DEFAULT 0,   -- 1=主架构锚点节点（与 workgroups 一一对应）
    function    TEXT NOT NULL DEFAULT '',
    sort        INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE(parent_id, name)
);
CREATE INDEX IF NOT EXISTS idx_org_nodes_parent ON org_nodes(parent_id);
CREATE INDEX IF NOT EXISTS idx_org_nodes_wg ON org_nodes(wg_id);

-- 岗位定义：每个节点类型可配置的岗位清单
CREATE TABLE IF NOT EXISTS org_roles (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    node_type   TEXT NOT NULL CHECK (node_type IN ('center','dept','group','special')),
    role_key    TEXT NOT NULL,                -- 岗位标识，如 group_leader
    role_name   TEXT NOT NULL,                -- 岗位显示名，如 组长
    unique_slot INTEGER NOT NULL DEFAULT 0,   -- 1=该节点内至多一人；0=可多人
    sort        INTEGER NOT NULL DEFAULT 0,
    UNIQUE(node_type, role_key)
);
CREATE INDEX IF NOT EXISTS idx_org_roles_type ON org_roles(node_type, sort);

-- 任职关系：人 × 节点 × 岗位
CREATE TABLE IF NOT EXISTS org_appointments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id     INTEGER NOT NULL,
    member_id   INTEGER NOT NULL,
    role_key    TEXT NOT NULL,
    is_primary  INTEGER NOT NULL DEFAULT 0,   -- 1=主岗（该人以此节点为第一归属）
    created_at  TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE(node_id, member_id, role_key),
    FOREIGN KEY (node_id) REFERENCES org_nodes(id) ON DELETE CASCADE,
    FOREIGN KEY (member_id) REFERENCES team_members(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_org_appt_node ON org_appointments(node_id);
CREATE INDEX IF NOT EXISTS idx_org_appt_member ON org_appointments(member_id);
-- 「节点内唯一槽位」岗位的强约束：同一节点同一 unique_slot 岗位只能有一个人。
-- ⚠️ SQLite 的 partial index 的 WHERE 子句**不允许子查询**（不能引用 org_roles），
--    因此这里把唯一槽位岗位键写死。与 org_roles 中的 unique_slot=1 集合保持一致
--    （中心负责人 / 总经理 / 部门长 / 组长），改岗位表时必须同步改这里。
CREATE UNIQUE INDEX IF NOT EXISTS ux_org_unique_slot
    ON org_appointments(node_id, role_key)
    WHERE role_key IN ('center_head','gm','dept_head','group_leader');


-- 部门主页：文化展示区（标语 / 职能介绍 / 团队合照）
-- dept 与 DEPT_ORDER 的部门名一一对应；一个部门一条记录
CREATE TABLE IF NOT EXISTS dept_profile (
    dept        TEXT PRIMARY KEY,              -- 部门名（财务中心 / 核算部 / 总账部 / 管理部 / 资金部 / 商务部）
    slogan      TEXT NOT NULL DEFAULT '',      -- 文化标语
    intro       TEXT NOT NULL DEFAULT '',      -- 部门职能介绍
    photo       TEXT NOT NULL DEFAULT '',      -- 团队合照（data URL）
    updated_at  TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

-- 部门主页：标杆部门 / 模范个人
-- kind: 'dept' 标杆部门 / 'person' 模范个人
-- target_name: 标杆部门名或模范个人姓名
CREATE TABLE IF NOT EXISTS dept_honors (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    dept         TEXT NOT NULL,                 -- 归属部门（挂在哪个部门的页面上）
    kind         TEXT NOT NULL DEFAULT 'dept',  -- 'dept'=标杆部门 / 'person'=模范个人
    target_name  TEXT NOT NULL DEFAULT '',      -- 标杆部门名 / 模范个人姓名
    photo        TEXT NOT NULL DEFAULT '',      -- 照片（data URL）
    remark       TEXT NOT NULL DEFAULT '',      -- 备注说明
    sort         INTEGER NOT NULL DEFAULT 0,   -- 排序权重（小在前）
    created_at   TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_dept_honors ON dept_honors(dept, kind, sort);

-- 部门介绍页：发文（支持发图）
-- images 是图片 data URL 的分号分隔串（与 mentions 同口径）
CREATE TABLE IF NOT EXISTS dept_posts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    dept        TEXT NOT NULL,
    title       TEXT NOT NULL DEFAULT '',
    content     TEXT NOT NULL DEFAULT '',
    images      TEXT NOT NULL DEFAULT '',
    author      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_dept_posts ON dept_posts(dept, id);

-- 公告栏：工作台顶部横幅位置展示的平台公告
-- scope: 'all' 全局公告 | 部门名（按部门显示各自的公告）
-- enabled: 0 = 暂停展示（保留内容，便于下次启用）
CREATE TABLE IF NOT EXISTS notices (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scope       TEXT NOT NULL DEFAULT 'all',   -- 'all' 或部门名
    title       TEXT NOT NULL DEFAULT '',
    content     TEXT NOT NULL DEFAULT '',
    author      TEXT NOT NULL DEFAULT '',
    enabled     INTEGER NOT NULL DEFAULT 1,    -- 0 暂停 / 1 展示
    sort        INTEGER NOT NULL DEFAULT 0,    -- 排序权重（小在前）
    created_at  TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_notices ON notices(scope, enabled, sort);

-- 板块元信息（看板内的分组，如「成本组（第1周）」）
-- 板块本身此前只隐含在 cards.column_name 中，没有独立记录，
-- 导致「创建日期 / 性质 / 置顶」无处存放。这里补一张表：
--   col_key      = board_id + '::' + column_name，稳定业务主键
--   column_id    = TAPD 原始列 ID（板块级权限 perm_pass 依赖它）
--   nature       = 性质：日常 / 专项
--   pinned       = 置顶标记（作用域：所在看板内）
CREATE TABLE IF NOT EXISTS board_columns (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    col_key     TEXT NOT NULL UNIQUE,
    column_id   TEXT NOT NULL DEFAULT '',
    board_id    TEXT NOT NULL DEFAULT '',
    column_name TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    creator     TEXT NOT NULL DEFAULT '',
    nature      TEXT NOT NULL DEFAULT '日常' CHECK (nature IN ('日常','专项')),
    year        TEXT NOT NULL DEFAULT '',
    pinned      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_board_columns_board ON board_columns(board_id);
CREATE INDEX IF NOT EXISTS idx_board_columns_name ON board_columns(column_name);

CREATE TABLE IF NOT EXISTS actions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    card_id     TEXT NOT NULL,
    username    TEXT NOT NULL,
    action      TEXT NOT NULL,        -- create/update/delete/comment
    detail      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_actions_card ON actions(card_id);

CREATE TABLE IF NOT EXISTS comments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    card_id     TEXT NOT NULL,
    username    TEXT NOT NULL,
    content     TEXT NOT NULL DEFAULT '',
    mentions    TEXT NOT NULL DEFAULT '',      -- 被 @ 的成员名，分号分隔（与 owner 字段同口径）
    created_at  TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_comments_card ON comments(card_id);

-- 消息中心：@ 提及与相关消息的收件箱
-- kind: 'mention'（被 @ 提及） / 'system'（系统消息）
-- 状态：unread 未读 / read 已读
CREATE TABLE IF NOT EXISTS messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    receiver    TEXT NOT NULL,                  -- 接收人（登录账号）
    sender      TEXT NOT NULL DEFAULT '',       -- 发送人
    card_id     TEXT NOT NULL DEFAULT '',       -- 关联事项（可空，如部门通知）
    kind        TEXT NOT NULL DEFAULT 'mention',
    content     TEXT NOT NULL DEFAULT '',
    read_at     TEXT NOT NULL DEFAULT '',       -- 空 = 未读
    created_at  TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver, read_at, id);
CREATE INDEX IF NOT EXISTS idx_messages_card ON messages(card_id);

CREATE TABLE IF NOT EXISTS card_subtasks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    card_id     TEXT NOT NULL,           -- 所属卡片
    title       TEXT NOT NULL DEFAULT '',
    done        INTEGER NOT NULL DEFAULT 0,   -- 0 未完成 / 1 已完成
    sort        INTEGER NOT NULL DEFAULT 0,   -- 排序权重（小的在前）
    done_by     TEXT NOT NULL DEFAULT '',
    done_at     TEXT NOT NULL DEFAULT '',
    created_by  TEXT NOT NULL DEFAULT '',
    parent_id   INTEGER NOT NULL DEFAULT 0,   -- 上级子事项 id（0 = 顶层）
    created_at  TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_subtasks_card ON card_subtasks(card_id);
-- 注意：parent_id 的索引不能在 SCHEMA 里建 —— 老库还没有该列，
-- executescript(SCHEMA) 会因 "no such column" 中断整个初始化。
-- 索引统一在 init_db() 的 ALTER 之后创建。

-- 审计日志：登录/登出/各类操作（仅管理员可查）
CREATE TABLE IF NOT EXISTS audit_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    username    TEXT NOT NULL DEFAULT '',   -- 操作账号
    ip          TEXT NOT NULL DEFAULT '',   -- 来源 IP
    action      TEXT NOT NULL DEFAULT '',   -- login/logout/view/create/update/delete/...
    target      TEXT NOT NULL DEFAULT '',   -- 操作对象（card_id / 成员名 / 小组名 ...）
    detail      TEXT NOT NULL DEFAULT '',   -- 操作详情
    result      TEXT NOT NULL DEFAULT 'success'  -- success / failed / denied
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(username);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
"""

def _drop_description_columns(conn):
    """删除 org_nodes / workgroups 上的「职能说明」（description）遗留列。

    「职能说明」已从架构管理模块整体下线（表单、渲染、提交、接口模型全部清理），
    存量库里残留的列不再被任何代码读写，一并清掉以免留下死字段。
    仅当列存在时才执行，幂等；SQLite < 3.35 不支持 DROP COLUMN 时跳过（旧库兼容）。
    """
    for table in ('org_nodes', 'workgroups'):
        cols = [r[1] for r in conn.execute(f'PRAGMA table_info({table})').fetchall()]
        if 'description' not in cols:
            continue
        try:
            conn.execute(f'ALTER TABLE {table} DROP COLUMN description')
        except sqlite3.OperationalError:
            pass  # 老版本 SQLite 不支持 DROP COLUMN，保留空列（无任何读写，不影响运行）


def _migrate_schema(conn):
    """增量迁移（幂等，仅列缺失时执行）：
    1) boards 表增加自增 id 主键，board_id 保留为 UNIQUE 业务键继续关联 cards；
    2) board_config 重构为按 board_id 关联真实看板（UNIQUE(board_id)），
       原无 board_id 的抽象配置行直接丢弃（与真实看板脱节，本就是脏数据）；
    3) groups 表重命名为 workgroups，team_members.groups 重命名为 workgroups。
    注意：重建表会丢失原表的索引，下方已重新建回。"""
    # ---- boards：增加自增 id 主键 ----
    bcols = [r[1] for r in conn.execute('PRAGMA table_info(boards)').fetchall()]
    if 'id' not in bcols:
        conn.execute('ALTER TABLE boards RENAME TO boards_bak')
        conn.execute("""CREATE TABLE boards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            board_id TEXT NOT NULL UNIQUE,
            board_name TEXT NOT NULL DEFAULT '',
            workspace_id TEXT NOT NULL DEFAULT '',
            owner TEXT NOT NULL DEFAULT '',
            sort INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
        )""")
        conn.execute("""INSERT INTO boards (board_id, board_name, workspace_id, owner, sort, created_at)
                       SELECT board_id, board_name, workspace_id, owner, sort, created_at FROM boards_bak""")
        conn.execute('DROP TABLE boards_bak')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_boards_sort ON boards(sort, board_id)')
    # ---- board_config：重构为按 board_id 关联真实看板 ----
    ccols = [r[1] for r in conn.execute('PRAGMA table_info(board_config)').fetchall()]
    csql = (conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='board_config'")
                .fetchone() or [''])[0] or ''
    # 归属部门改为联动架构管理层级：
    #   1) 去掉 dept 的固定枚举 CHECK（部门集合随架构层级动态变化）
    #   2) 新增 dept_node_id 指向 org_nodes.id
    # 需要重建表时：CHECK 约束在 SQLite 中无法直接修改，只能建新表拷贝数据。
    need_rebuild = ('dept_node_id' not in ccols) or ('CHECK (dept IN' in csql)
    if 'board_id' not in ccols:
        conn.execute('ALTER TABLE board_config RENAME TO board_config_old')
        conn.execute("""CREATE TABLE board_config (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            board_id    TEXT NOT NULL DEFAULT '',
            year        TEXT NOT NULL CHECK (year IN ('2025','2026','2027','2028','2029','2030')),
            dept        TEXT NOT NULL DEFAULT '',
            dept_node_id INTEGER NOT NULL DEFAULT 0,
            attr        TEXT NOT NULL CHECK (attr IN ('日常','专项')),
            status      TEXT NOT NULL DEFAULT '启用' CHECK (status IN ('启用','封存')),
            remark      TEXT NOT NULL DEFAULT '',
            created_at  TEXT NOT NULL DEFAULT (datetime('now','localtime')),
            UNIQUE(board_id)
        )""")
        conn.execute('DROP TABLE board_config_old')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_board_config_board ON board_config(board_id)')
    elif need_rebuild:
        # 保留原有行，仅放宽 dept 约束并补 dept_node_id
        conn.execute('ALTER TABLE board_config RENAME TO board_config_old')
        conn.execute("""CREATE TABLE board_config (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            board_id    TEXT NOT NULL DEFAULT '',
            year        TEXT NOT NULL CHECK (year IN ('2025','2026','2027','2028','2029','2030')),
            dept        TEXT NOT NULL DEFAULT '',
            dept_node_id INTEGER NOT NULL DEFAULT 0,
            attr        TEXT NOT NULL CHECK (attr IN ('日常','专项')),
            status      TEXT NOT NULL DEFAULT '启用' CHECK (status IN ('启用','封存')),
            remark      TEXT NOT NULL DEFAULT '',
            created_at  TEXT NOT NULL DEFAULT (datetime('now','localtime')),
            UNIQUE(board_id)
        )""")
        conn.execute("""INSERT INTO board_config (id, board_id, year, dept, attr, status, remark, created_at)
                        SELECT id, board_id, year, dept, attr, status, remark, created_at FROM board_config_old""")
        conn.execute('DROP TABLE board_config_old')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_board_config_board ON board_config(board_id)')
    # 索引统一在重建后补建（重建会丢索引）
    conn.execute('CREATE INDEX IF NOT EXISTS idx_board_config ON board_config(year, dept, attr)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_board_config_dept ON board_config(dept_node_id)')

    # ---- groups -> workgroups（组织概念改为工作组，字段同步更名） ----
    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    if 'groups' in tables and 'workgroups' not in tables:
        conn.execute('''CREATE TABLE workgroups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            parent_id INTEGER NOT NULL DEFAULT 0,
            leader TEXT NOT NULL DEFAULT '',
            function TEXT NOT NULL DEFAULT '',
            boards TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
            UNIQUE(parent_id, name)
        )''')
        conn.execute('''INSERT INTO workgroups (id, name, parent_id, leader, function, boards, created_at)
                        SELECT id, name, parent_id, leader, function, boards, created_at FROM groups''')
        conn.execute('DROP TABLE groups')
    elif 'groups' in tables and 'workgroups' in tables:
        # 两个表同时存在：以 workgroups 为准，删除旧表
        conn.execute('DROP TABLE groups')

    # ---- team_members.groups -> team_members.workgroups ----
    tcols = [r[1] for r in conn.execute('PRAGMA table_info(team_members)').fetchall()]
    if 'groups' in tcols and 'workgroups' not in tcols:
        conn.execute('ALTER TABLE team_members ADD COLUMN workgroups TEXT NOT NULL DEFAULT ""')
        conn.execute('UPDATE team_members SET workgroups=groups')
        # 重建表以删除旧列 groups（SQLite 低版本不支持 DROP COLUMN）
        conn.execute('ALTER TABLE team_members RENAME TO team_members_bak')
        conn.execute('''CREATE TABLE team_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            workgroups TEXT NOT NULL DEFAULT '',
            account TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
        )''')
        conn.execute('''INSERT INTO team_members (id, name, workgroups, account, created_at)
                        SELECT id, name, workgroups, account, created_at FROM team_members_bak''')
        conn.execute('DROP TABLE team_members_bak')

def _migrate_org(conn):
    """组织架构迁移：workgroups（层级 + 单个 leader + 成员分号串）
    → org_nodes（带类型的节点树） + org_roles（岗位定义） + org_appointments（任职关系）。

    幂等策略：
      1) 岗位定义用 INSERT OR IGNORE 补齐（org_roles 有 UNIQUE(node_type,role_key)）。
      2) 存量节点转换只在「org_nodes 中不存在同名锚点节点」时进行。
      3) 任职关系用 INSERT OR IGNORE（表上有 UNIQUE(node_id,member_id,role_key)）。

    节点类型推断（基于旧层级 + 是否含子节点）：
      parent_id=0            → center（中心）
      有子节点                → dept（部门）
      叶子节点                → group（常规小组）
    专项小组（special）旧库里不存在，全部由新接口创建。
    """
    # ---------- 1) 岗位定义 ----------
    # unique_slot=1 的岗位在一个节点内至多一人（DB partial unique index 强制）
    # unique_slot=0 的岗位可多人（组员 / 骨干）
    ROLE_DEFS = [
        # (node_type, role_key, role_name, unique_slot, sort)
        ('center',  'center_head',    '中心负责人', 1, 1),
        ('center',  'gm',             '总经理',     1, 2),
        ('center',  'center_backbone','中心骨干',   0, 3),
        ('dept',    'dept_head',      '部门长',     1, 1),
        ('dept',    'dept_backbone',  '部门骨干',   0, 2),
        ('group',   'group_leader',   '组长',       1, 1),
        ('group',   'member',         '组员',       0, 2),
        ('special', 'group_leader',   '组长',       1, 1),
        ('special', 'member',         '组员',       0, 2),
    ]
    for nt, rk, rn, us, so in ROLE_DEFS:
        conn.execute('INSERT OR IGNORE INTO org_roles (node_type, role_key, role_name, unique_slot, sort)'
                     ' VALUES (?,?,?,?,?)', (nt, rk, rn, us, so))

    # ---------- 2) 节点转换 ----------
    wgs = [dict(zip(('id', 'name', 'parent_id', 'leader', 'function'), r))
           for r in conn.execute('SELECT id, name, parent_id, leader, function'
                                 ' FROM workgroups ORDER BY id')]
    if not wgs:
        return
    # 有子节点者 = 部门
    has_child = set(r['parent_id'] for r in wgs if r['parent_id'])
    existing = set(r[0] for r in conn.execute('SELECT id FROM org_nodes'))
    # 先算出「中心」节点的 id 集合：parent_id=0 的即中心
    center_wg_ids = set(r['id'] for r in wgs if r['parent_id'] == 0)

    def _node_type(w):
        """类型推断（依据业务层级：中心 → 部门 → 常规小组）：
          parent_id=0            → center
          挂在中心下            → dept   （部门可能还没有子组，不能因「是叶子」就判成 group）
          挂在部门下 / 其他      → group
        """
        if w['parent_id'] == 0:
            return 'center'
        if w['parent_id'] in center_wg_ids:
            return 'dept'
        return 'group'

    # workgroups.id → org_nodes.id 的映射（迁移后要用）
    id_map = {}
    for w in wgs:
        row = conn.execute('SELECT id FROM org_nodes WHERE name=? AND parent_id=?',
                           (w['name'], 0 if w['parent_id'] == 0 else -1)).fetchone()
        if row:
            id_map[w['id']] = row[0]
            continue
        # 找同名的既有节点（按 wg_id 关联最准）
        row = conn.execute('SELECT id FROM org_nodes WHERE wg_id=?', (w['id'],)).fetchone()
        if row:
            id_map[w['id']] = row[0]
            conn.execute('UPDATE org_nodes SET name=?, node_type=?, is_anchor=1,'
                         ' function=? WHERE id=?',
                         (w['name'], _node_type(w), w['function'] or '', row[0]))
            continue
        # 新建：父级先建（按 parent_id 递增顺序，父 id 更小）
        pid = id_map.get(w['parent_id'], 0)
        cur = conn.execute('INSERT INTO org_nodes (name, node_type, parent_id, wg_id, is_anchor,'
                            ' function) VALUES (?,?,?,?,1,?)',
                            (w['name'], _node_type(w), pid, w['id'], w['function'] or ''))
        id_map[w['id']] = cur.lastrowid
        existing.add(cur.lastrowid)

    # ---------- 3) 任职关系转换 ----------
    # 3a) leader → 唯一槽位岗位
    LEADER_ROLE = {'center': 'center_head', 'dept': 'dept_head', 'group': 'group_leader',
                   'special': 'group_leader'}
    for w in wgs:
        leader = (w['leader'] or '').strip()
        if not leader:
            continue
        m = conn.execute('SELECT id FROM team_members WHERE name=?', (leader,)).fetchone()
        if not m:
            continue
        nid = id_map.get(w['id'])
        if not nid:
            continue
        nt = conn.execute('SELECT node_type FROM org_nodes WHERE id=?', (nid,)).fetchone()[0]
        conn.execute('INSERT OR IGNORE INTO org_appointments (node_id, member_id, role_key, is_primary)'
                     ' VALUES (?,?,?,1)', (nid, m[0], LEADER_ROLE.get(nt, 'group_leader')))

    # 3b) team_members.workgroups（分号串）→ 组员任职
    # 只挂到「常规小组 / 专项小组」节点；部门与中心的成员归属由下级组传导。
    for m in conn.execute('SELECT id, name, workgroups FROM team_members'):
        m = dict(zip(('id', 'name', 'workgroups'), m))
        names = [x.strip() for x in (m['workgroups'] or '').split(';') if x.strip()]
        for nm in names:
            nid = None
            for w in wgs:
                if w['name'] != nm:
                    continue
                nt = conn.execute('SELECT node_type FROM org_nodes WHERE id=?',
                                  (id_map.get(w['id'], 0),)).fetchone()
                if nt and nt[0] in ('group', 'special'):
                    nid = id_map[w['id']]
                break
            if not nid:
                continue
            # 该成员若是此组组长，则不再重复挂「组员」
            is_leader = conn.execute('SELECT 1 FROM org_appointments WHERE node_id=? AND member_id=?'
                                     ' AND role_key=?', (nid, m['id'], 'group_leader')).fetchone()
            if is_leader:
                continue
            conn.execute('INSERT OR IGNORE INTO org_appointments (node_id, member_id, role_key, is_primary)'
                         ' VALUES (?,?,?,0)', (nid, m['id'], 'member'))


def init_db(force_import=False):
    conn = sqlite3.connect(DB_FILE)
    conn.executescript(SCHEMA)
    _migrate_schema(conn)
    # 兼容旧库：cards 缺 parent_id 列时补上
    cols = [r[1] for r in conn.execute('PRAGMA table_info(cards)').fetchall()]
    if 'parent_id' not in cols:
        conn.execute("ALTER TABLE cards ADD COLUMN parent_id TEXT NOT NULL DEFAULT ''")
        conn.execute('CREATE INDEX IF NOT EXISTS idx_cards_parent ON cards(parent_id)')
    # 事项置顶：作用域为所在板块内部
    if 'pinned' not in cols:
        conn.execute('ALTER TABLE cards ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_cards_pinned ON cards(pinned)')
    # 子事项层级：parent_id 指向同卡片下的另一个子事项，0 表示顶层
    scols = [r[1] for r in conn.execute('PRAGMA table_info(card_subtasks)').fetchall()]
    if 'parent_id' not in scols:
        conn.execute('ALTER TABLE card_subtasks ADD COLUMN parent_id INTEGER NOT NULL DEFAULT 0')
    # 板块归属年份：老库补列（新增列的索引不能写进 SCHEMA，必须放在 ALTER 之后）
    bcols = [r[1] for r in conn.execute('PRAGMA table_info(board_columns)').fetchall()]
    if 'year' not in bcols:
        conn.execute("ALTER TABLE board_columns ADD COLUMN year TEXT NOT NULL DEFAULT ''")
    # 归属年份默认值 = 板块创建年份：老数据回填（幂等，只补空值）
    conn.execute("UPDATE board_columns SET year=substr(created_at,1,4)"
                 " WHERE (year IS NULL OR year='') AND created_at IS NOT NULL AND created_at<>''")
    # 索引放在 ALTER 之后建（老库要先补列才能建索引）
    conn.execute('CREATE INDEX IF NOT EXISTS idx_subtasks_parent ON card_subtasks(parent_id)')
    cols = [r[1] for r in conn.execute('PRAGMA table_info(team_members)').fetchall()]
    if 'workgroups' not in cols:
        conn.execute("ALTER TABLE team_members ADD COLUMN workgroups TEXT NOT NULL DEFAULT ''")
    if 'account' not in cols:
        conn.execute("ALTER TABLE team_members ADD COLUMN account TEXT NOT NULL DEFAULT ''")
    # 评论 @ 提及：老库补列（mentions 与 owner 字段同口径，分号分隔成员名）
    ccols = [r[1] for r in conn.execute('PRAGMA table_info(comments)').fetchall()]
    if 'mentions' not in ccols:
        conn.execute("ALTER TABLE comments ADD COLUMN mentions TEXT NOT NULL DEFAULT ''")
    # 消息中心：老库补表（SCHEMA 里的 CREATE TABLE IF NOT EXISTS 已覆盖新库，这里只兜底）
    conn.execute('''CREATE TABLE IF NOT EXISTS messages (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        receiver    TEXT NOT NULL,
        sender      TEXT NOT NULL DEFAULT '',
        card_id     TEXT NOT NULL DEFAULT '',
        kind        TEXT NOT NULL DEFAULT 'mention',
        content     TEXT NOT NULL DEFAULT '',
        read_at     TEXT NOT NULL DEFAULT '',
        created_at  TEXT NOT NULL DEFAULT (datetime('now','localtime'))
    )''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver, read_at, id)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_messages_card ON messages(card_id)')
    # 部门主页相关表（老库兜底）
    conn.execute('''CREATE TABLE IF NOT EXISTS dept_profile (
        dept TEXT PRIMARY KEY, slogan TEXT NOT NULL DEFAULT '',
        intro TEXT NOT NULL DEFAULT '', photo TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime')))''')
    conn.execute('''CREATE TABLE IF NOT EXISTS dept_honors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        dept TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'dept',
        target_name TEXT NOT NULL DEFAULT '', photo TEXT NOT NULL DEFAULT '',
        remark TEXT NOT NULL DEFAULT '', sort INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')))''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_dept_honors ON dept_honors(dept, kind, sort)')
    conn.execute('''CREATE TABLE IF NOT EXISTS dept_posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        dept TEXT NOT NULL, title TEXT NOT NULL DEFAULT '',
        content TEXT NOT NULL DEFAULT '', images TEXT NOT NULL DEFAULT '',
        author TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')))''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_dept_posts ON dept_posts(dept, id)')
    # 公告栏（老库兜底）
    conn.execute('''CREATE TABLE IF NOT EXISTS notices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scope TEXT NOT NULL DEFAULT 'all', title TEXT NOT NULL DEFAULT '',
        content TEXT NOT NULL DEFAULT '', author TEXT NOT NULL DEFAULT '',
        enabled INTEGER NOT NULL DEFAULT 1, sort INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')))''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_notices ON notices(scope, enabled, sort)')
    # workgroups 表兼容（防御旧库缺列）
    wcols = [r[1] for r in conn.execute('PRAGMA table_info(workgroups)').fetchall()]
    for c, ddl in (('parent_id', "ALTER TABLE workgroups ADD COLUMN parent_id INTEGER NOT NULL DEFAULT 0"),
                   ('boards', "ALTER TABLE workgroups ADD COLUMN boards TEXT NOT NULL DEFAULT ''"),
                   ('leader', "ALTER TABLE workgroups ADD COLUMN leader TEXT NOT NULL DEFAULT ''"),
                   ('function', "ALTER TABLE workgroups ADD COLUMN function TEXT NOT NULL DEFAULT ''")):
        if c not in wcols:
            conn.execute(ddl)
    # 「职能说明」（description）已从架构管理模块整体下线：清掉存量库里的遗留列
    _drop_description_columns(conn)
    # 首次导入：cards 为空才导入
    cnt = conn.execute("SELECT COUNT(*) FROM cards WHERE deleted=0").fetchone()[0]
    if cnt == 0 or force_import:
        import_csv(conn)
    # 板块元信息回填：从已有卡片派生板块，创建日期取该板块最早的事项创建时间
    # （必须放在 CSV 导入之后 —— 新库导入完成才有板块可派生）
    conn.execute("""
        INSERT OR IGNORE INTO board_columns
            (col_key, column_id, board_id, column_name, created_at, creator, nature, pinned)
        SELECT board_id || '::' || column_name,
               COALESCE(MIN(NULLIF(column_id,'')), ''),
               board_id,
               column_name,
               MIN(NULLIF(created,'')),
               COALESCE(MIN(NULLIF(creator,'')), ''),
               '日常',
               0
        FROM cards
        WHERE deleted=0 AND column_name IS NOT NULL AND column_name!=''
        GROUP BY board_id, column_name
    """)
    # 架构管理（工作组树）：初始化部门层级（最顶层：财务中心）
    gcnt = conn.execute('SELECT COUNT(*) FROM workgroups').fetchone()[0]
    depts = ['管理部', '总账部', '核算部', '资金部', '商务部']
    def _ensure_center():
        """确保存在最顶层「财务中心」，返回其 id"""
        c = conn.execute('SELECT id FROM workgroups WHERE name=? AND parent_id=0', ('财务中心',)).fetchone()
        if c:
            return c[0]
        conn.execute('INSERT INTO workgroups (name, parent_id) VALUES (?,0)', ('财务中心',))
        return conn.execute('SELECT id FROM workgroups WHERE name=? AND parent_id=0', ('财务中心',)).fetchone()[0]
    if gcnt == 0:
        # 全新库：财务中心 → 部门 → 核算部子组
        cid = _ensure_center()
        for d in depts:
            conn.execute('INSERT INTO workgroups (name, parent_id) VALUES (?,?)', (d, cid))
        hs_id = conn.execute('SELECT id FROM workgroups WHERE name=? AND parent_id=?', ('核算部', cid)).fetchone()[0]
        for sub in ('收入组', '成本组', '费用组', '资产组', '税务组', '统筹'):
            conn.execute('INSERT INTO workgroups (name, parent_id) VALUES (?,?)', (sub, hs_id))
    else:
        # 旧库迁移：确保财务中心存在；将顶层部门挂到财务中心之下
        cid = _ensure_center()
        for d in depts:
            r = conn.execute('SELECT id FROM workgroups WHERE name=? AND parent_id=?', (d, cid)).fetchone()
            if not r:
                r2 = conn.execute('SELECT id FROM workgroups WHERE name=? AND parent_id=0', (d,)).fetchone()
                if r2:
                    conn.execute('UPDATE workgroups SET parent_id=? WHERE id=?', (cid, r2[0]))
                else:
                    conn.execute('INSERT INTO workgroups (name, parent_id) VALUES (?,?)', (d, cid))
        # 财务中心下应只有部门；将其他顶层节点（如转岗）也挂到财务中心下
        for r in conn.execute('SELECT id, name FROM workgroups WHERE parent_id=0 AND name!=?', ('财务中心',)):
            conn.execute('UPDATE workgroups SET parent_id=? WHERE id=?', (cid, r[0]))
        hs_id = conn.execute('SELECT id FROM workgroups WHERE name=? AND parent_id=?', ('核算部', cid)).fetchone()[0]
        grp_names = ('收入组', '成本组', '费用组', '资产组', '税务组', '统筹')
        for sub in grp_names:
            r = conn.execute('SELECT id FROM workgroups WHERE name=? AND parent_id=?', (sub, cid)).fetchone()
            if not r:
                r2 = conn.execute('SELECT id FROM workgroups WHERE name=? AND parent_id=?', (sub, hs_id)).fetchone()
                if not r2:
                    r3 = conn.execute('SELECT id FROM workgroups WHERE name=? AND parent_id=0', (sub,)).fetchone()
                    if r3:
                        conn.execute('UPDATE workgroups SET parent_id=? WHERE id=?', (hs_id, r3[0]))
    # ============================================================
    # 组织架构（新模型）迁移：workgroups → org_nodes / org_roles / org_appointments
    #
    # 幂等：以「org_nodes 是否已有锚点节点」为开关，只在首次迁移时转换存量数据，
    # 之后新建的节点直接写 org_nodes（并同步 workgroups 兼容视图）。
    # ============================================================
    _migrate_org(conn)
    # 看板归属部门 → 架构部门节点（按名称匹配中心/部门节点；匹配不到则保持 0=未配置）
    conn.execute("""UPDATE board_config SET dept_node_id = COALESCE((
                            SELECT n.id FROM org_nodes n
                            WHERE n.name = board_config.dept AND n.node_type IN ('center','dept')
                            ORDER BY n.id LIMIT 1), 0)
                     WHERE dept_node_id = 0 AND dept <> ''""")
    # 看板表：从现有 cards 派生已存在的看板，保证历史看板不丢失（全新看板由 /api/boards 写入）
    for r in conn.execute('SELECT DISTINCT board_id, board_name, workspace_id FROM cards WHERE deleted=0'):
        conn.execute('INSERT OR IGNORE INTO boards (board_id, board_name, workspace_id) VALUES (?,?,?)',
                     (r[0], r[1], r[2] or ''))
    conn.commit()
    conn.close()
    return DB_FILE

def import_csv(conn):
    if not os.path.exists(CSV_FILE):
        print(f'WARN: CSV 不存在 {CSV_FILE}，跳过导入')
        return 0
    cols = ['card_id','board_id','board_name','column_id','column_name','workspace_id',
            'card_name','status','status_name','priority','creator','owner','cc','follower',
            'begin','due','completed','created','modified','description','attachment_count',
            'label','b_sort','entity_type','cover_setted','cover_info','is_filed','created_from',
            'date_status','due_time_ux','begin_date_status','begin_time_ux','comments',
            'column_sort','board_status','board_creator']
    n = 0
    members = set()
    with open(CSV_FILE, encoding='utf-8-sig') as f:
        for r in csv.DictReader(f):
            vals = []
            for c in cols:
                v = r.get(c) or ''
                if c in ('card_id', 'board_id', 'column_id', 'workspace_id') and v.startswith("'"):
                    v = v[1:]  # 去单引号前缀
                vals.append(v)
            conn.execute(
                f"INSERT OR REPLACE INTO cards ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})",
                vals)
            # 提取成员（owner/cc/follower/creator 去重）
            for c in ('owner', 'cc', 'follower', 'creator'):
                for name in (r.get(c) or '').replace(';', ';').split(';'):
                    name = name.strip()
                    if name and name not in members:
                        members.add(name)
            n += 1
    # 成员入库（幂等）
    for name in sorted(members):
        if name == 'admin':
            continue  # 系统账号不加入成员名单
        conn.execute('INSERT OR IGNORE INTO team_members (name) VALUES (?)', (name,))
    print(f'imported {n} cards from CSV, members={len(members)}')
    return n

if __name__ == '__main__':
    init_db(force_import='--force' in os.sys.argv)
    print('DB ready:', DB_FILE)
