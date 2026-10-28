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
    description TEXT NOT NULL DEFAULT '',      -- 职能说明（长文本，非必填）
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

-- 看板管理（配置板块）：年份 / 归属部门 / 属性 / 状态 四维配置，枚举值由 CHECK 约束限定
CREATE TABLE IF NOT EXISTS board_config (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    year        TEXT NOT NULL CHECK (year IN ('2025','2026','2027','2028','2029','2030')),
    dept        TEXT NOT NULL CHECK (dept IN ('财务中心','核算部','总账部','管理部','资金部','商务部')),
    attr        TEXT NOT NULL CHECK (attr IN ('日常','专项')),
    status      TEXT NOT NULL DEFAULT '启用' CHECK (status IN ('启用','封存')),
    remark      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE(year, dept, attr)   -- 同一（年份,归属部门,属性）仅一条配置，状态为其当前态
);
CREATE INDEX IF NOT EXISTS idx_board_config ON board_config(year, dept, attr);

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
    created_at  TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_comments_card ON comments(card_id);

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
    if 'board_id' not in ccols:
        conn.execute('ALTER TABLE board_config RENAME TO board_config_old')
        conn.execute("""CREATE TABLE board_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            board_id TEXT NOT NULL DEFAULT '',
            year TEXT NOT NULL CHECK (year IN ('2025','2026','2027','2028','2029','2030')),
            dept TEXT NOT NULL CHECK (dept IN ('财务中心','核算部','总账部','管理部','资金部','商务部')),
            attr TEXT NOT NULL CHECK (attr IN ('日常','专项')),
            status TEXT NOT NULL DEFAULT '启用' CHECK (status IN ('启用','封存')),
            remark TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
            UNIQUE(board_id)
        )""")
        conn.execute('DROP TABLE board_config_old')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_board_config_board ON board_config(board_id)')

    # ---- groups -> workgroups（组织概念改为工作组，字段同步更名） ----
    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    if 'groups' in tables and 'workgroups' not in tables:
        conn.execute('''CREATE TABLE workgroups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            parent_id INTEGER NOT NULL DEFAULT 0,
            leader TEXT NOT NULL DEFAULT '',
            function TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            boards TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
            UNIQUE(parent_id, name)
        )''')
        conn.execute('''INSERT INTO workgroups (id, name, parent_id, leader, function, description, boards, created_at)
                        SELECT id, name, parent_id, leader, function, description, boards, created_at FROM groups''')
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
    # 索引放在 ALTER 之后建（老库要先补列才能建索引）
    conn.execute('CREATE INDEX IF NOT EXISTS idx_subtasks_parent ON card_subtasks(parent_id)')
    cols = [r[1] for r in conn.execute('PRAGMA table_info(team_members)').fetchall()]
    if 'workgroups' not in cols:
        conn.execute("ALTER TABLE team_members ADD COLUMN workgroups TEXT NOT NULL DEFAULT ''")
    if 'account' not in cols:
        conn.execute("ALTER TABLE team_members ADD COLUMN account TEXT NOT NULL DEFAULT ''")
    # workgroups 表兼容（防御旧库缺列）
    wcols = [r[1] for r in conn.execute('PRAGMA table_info(workgroups)').fetchall()]
    for c, ddl in (('parent_id', "ALTER TABLE workgroups ADD COLUMN parent_id INTEGER NOT NULL DEFAULT 0"),
                   ('boards', "ALTER TABLE workgroups ADD COLUMN boards TEXT NOT NULL DEFAULT ''"),
                   ('leader', "ALTER TABLE workgroups ADD COLUMN leader TEXT NOT NULL DEFAULT ''"),
                   ('function', "ALTER TABLE workgroups ADD COLUMN function TEXT NOT NULL DEFAULT ''"),
                   ('description', "ALTER TABLE workgroups ADD COLUMN description TEXT NOT NULL DEFAULT ''")):
        if c not in wcols:
            conn.execute(ddl)
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
