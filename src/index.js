// src/index.js
import { Hono } from 'hono'
import { bearerAuth } from 'hono/bearer-auth'
import htmlContent from '../public/index.html'  // 前端静态页

const app = new Hono()

/* ==========================================================
 * 0. 数据库初始化（D1）
 * ========================================================== */
const initDB = async (db) => {
  const sqls = [
    `CREATE TABLE IF NOT EXISTS users (
       id   INTEGER PRIMARY KEY AUTOINCREMENT,
       user TEXT UNIQUE NOT NULL,
       pwd  TEXT NOT NULL,
       created_at DATETIME DEFAULT CURRENT_TIMESTAMP
     );`,
    `CREATE TABLE IF NOT EXISTS categories (
       id  INTEGER PRIMARY KEY AUTOINCREMENT,
       uid INTEGER,
       type TEXT CHECK(type IN ('income','expense')) NOT NULL,
       name TEXT NOT NULL
     );`,
    `CREATE TABLE IF NOT EXISTS records (
       id   INTEGER PRIMARY KEY AUTOINCREMENT,
       uid  INTEGER NOT NULL,
       type TEXT CHECK(type IN ('income','expense')) NOT NULL,
       amount REAL NOT NULL,
       category TEXT NOT NULL,
       date TEXT NOT NULL,
       note TEXT
     );`,
    `CREATE TABLE IF NOT EXISTS login_logs (
       id INTEGER PRIMARY KEY,
       user TEXT NOT NULL,
       login_date DATE NOT NULL,
       error_10 INTEGER NOT NULL,
       error_today INTEGER NOT NULL,
       error_all INTEGER NOT NULL,
       created_at DATETIME DEFAULT CURRENT_TIMESTAMP
     );`
  ]
  for (const s of sqls) await db.prepare(s).run()

  // 内置分类
  const builtIn = [
    ['工资', null, 'income'],
    ['理财', null, 'income'],
    ['其他', null, 'income'],
    ['餐饮', null, 'expense'],
    ['交通', null, 'expense'],
    ['购物', null, 'expense']
  ]
  for (const [n, u, t] of builtIn) {
    await db.prepare('INSERT OR IGNORE INTO categories(name,uid,type) VALUES (?,?,?)').bind(n, u, t).run()
  }
}

/* ==========================================================
 * 1. JWT 工具（HS256）
 * ========================================================== */
const JWT_KEY = 'your-256-bit-secret' // 与 PHP 保持一致

function base64u(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}
function base64uDecode(str) {
  str += '=='.substring(0, (4 - (str.length & 3)) & 3)
  return atob(str.replace(/-/g, '+').replace(/_/g, '/'))
}

function jwtEncode(uid, uname) {
  const h = base64u(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
  const p = base64u(JSON.stringify({ uid, uname, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 86400 * 7 }))
  const sig = base64u(crypto.createHmac('sha256', JWT_KEY).update(h + '.' + p).digest('base64'))
  return h + '.' + p + '.' + sig
}

function jwtDecode(tok) {
  const [h, p, s] = tok.split('.')
  if (!h || !p || !s) return null
  const sig2 = base64u(crypto.createHmac('sha256', JWT_KEY).update(h + '.' + p).digest('base64'))
  if (sig2 !== s) return null
  return JSON.parse(base64uDecode(p))
}

/* 兼容 PHP 的 jz_hash */
function jzHash(p) {
  const salt = 'zxcvbnm'
  return crypto.createHash('sha1').update(crypto.createHash('md5').update(salt + p + salt).digest('hex')).digest('hex')
}

/* ==========================================================
 * 2. 统一鉴权中间件（仿 PHP 逻辑）
 * ========================================================== */
async function authMiddleware(c, next) {
  const hdr = c.req.header('Authorization') || ''
  const tok = hdr.replace('Bearer ', '')
  const claims = jwtDecode(tok)
  if (!claims) return c.json({ error: '未授权' }, 401)
  c.set('jwtClaims', claims)
  return next()
}

/* ==========================================================
 * 3. 前端页面
 * ========================================================== */
app.get('/', (c) => c.html(htmlContent))

/* ==========================================================
 * 4. 业务接口（完全兼容 PHP 协议）
 * ========================================================== */
app.post('/api.php', async (c) => {
  const db = c.env.DB
  await initDB(db)
  const body = await c.req.json().catch(() => ({}))
  const op = body.op

  /* ---------------- 注册 ---------------- */
  if (op === 'register') {
    const u = (body.user || '').trim()
    const p = jzHash((body.pwd || '').trim())
    if (!u || !p) return c.json({ error: '用户名或密码为空' }, 400)
    const exist = await db.prepare('SELECT id FROM users WHERE user=?').bind(u).first()
    if (exist) return c.json({ error: '用户名已存在' }, 400)
    const { meta } = await db.prepare('INSERT INTO users(user,pwd) VALUES (?,?)').bind(u, p).run()
    return c.json({ ok: true })
  }

  /* ---------------- 登录 ---------------- */
  if (op === 'login') {
    const u = (body.user || '').trim()
    const p = jzHash((body.pwd || '').trim())
    const row = await db.prepare('SELECT id,user FROM users WHERE user=? AND pwd=?').bind(u, p).first()
    if (!row) return c.json({ error: '账号或密码错误' }, 401)
    const token = jwtEncode(row.id, row.user)
    return c.json({ token, uid: row.user }) // 与 PHP 保持一致字段
  }

  /* ---------------- token 校验 ---------------- */
  if (op === 'check') {
    const hdr = c.req.header('Authorization') || ''
    const claims = jwtDecode(hdr.replace('Bearer ', ''))
    return c.json({ ok: !!claims, uid: claims?.uid || null, uname: claims?.uname || null })
  }

  /* ---------------- 需要登录的接口 ---------------- */
  if (!op) return c.json({ error: '未知操作' }, 400)
  return authMiddleware(c, async () => {
    const claims = c.get('jwtClaims')
    const uid = claims.uid

    /* ---- 分类列表 ---- */
    if (op === 'catList') {
      const { results } = await db.prepare('SELECT name,type FROM categories WHERE (uid=? OR uid IS NULL) ORDER BY id DESC').bind(uid).all()
      return c.json(results)
    }

    /* ---- 新增分类 ---- */
    if (op === 'catAdd') {
      const name = (body.name || '').trim()
      const typ = body.type || 'expense'
      if (!name) return c.json({ error: '名称空' }, 400)
      await db.prepare('INSERT INTO categories(uid,type,name) VALUES (?,?,?)').bind(uid, typ, name).run()
      return c.json({ ok: true })
    }

    /* ---- 记账 ---- */
    if (op === 'add') {
      const { type, amount, category, date, note } = body
      await db.prepare('INSERT INTO records(uid,type,amount,category,date,note) VALUES (?,?,?,?,?,?)')
        .bind(uid, type, amount, category, date, note || '').run()
      return c.json({ ok: true })
    }

    /* ---- 流水列表 ---- */
    if (op === 'list') {
      const per = body.period || '' // week/month/year
      const off = parseInt(body.offset || 0)
      const id = parseInt(body.id || 0)
      const cat = body.category || ''
      const limit = parseInt(body.limit || 0)
      let page = parseInt(body.page || 1)
      if (page < 1) page = 1
      const offset = limit ? (page - 1) * limit : 0

      let start = '', end = ''
      if (per) {
        const now = new Date()
        now.setMonth(now.getMonth() + off)
        switch (per) {
          case 'week':
            start = new Date(now.setDate(now.getDate() - now.getDay() + 1)).toISOString().slice(0, 10)
            end = new Date(now.setDate(now.getDate() - now.getDay() + 7)).toISOString().slice(0, 10)
            break
          case 'month':
            start = new Date(now.getFullYear(), now.getMonth(), 1).toISOString().slice(0, 10)
            end = new Date(now.getFullYear(), now.getMonth() + 1, 0).toISOString().slice(0, 10)
            break
          case 'year':
            start = new Date(now.getFullYear(), 0, 1).toISOString().slice(0, 10)
            end = new Date(now.getFullYear(), 11, 31).toISOString().slice(0, 10)
            break
        }
      }

      let sql = 'SELECT * FROM records WHERE uid=? '
      const bind = [uid]

      if (id) {
        sql += 'AND id=? '
        bind.push(id)
      } else {
        if (per && start && end) {
          sql += 'AND date BETWEEN ? AND ? '
          bind.push(start, end)
        }
        if (cat) {
          sql += 'AND category=? '
          bind.push(cat)
        }
        sql += 'ORDER BY date DESC, id DESC '
        if (limit) {
          sql += 'LIMIT ? OFFSET ? '
          bind.push(limit, offset)
        }
      }

      const { results } = await db.prepare(sql).bind(...bind).all()
      return c.json(results)
    }

    /* ---- 编辑记录 ---- */
    if (op === 'edit') {
      const id = parseInt(body.id)
      const { type, amount, category, date, note } = body
      await db.prepare('UPDATE records SET type=?,amount=?,category=?,date=?,note=? WHERE id=? AND uid=?')
        .bind(type, amount, category, date, note || '', id, uid).run()
      return c.json({ ok: true })
    }

    /* ---- 删除记录 ---- */
    if (op === 'del') {
      const id = parseInt(body.id)
      await db.prepare('DELETE FROM records WHERE id=? AND uid=?').bind(id, uid).run()
      return c.json({ ok: true })
    }

    /* ---- 统计 ---- */
    if (op === 'stat') {
      const per = body.period || 'month'
      const off = parseInt(body.offset || 0)
      const now = new Date()
      now.setMonth(now.getMonth() + off)
      let start, end, title
      switch (per) {
        case 'week':
          start = new Date(now.setDate(now.getDate() - now.getDay() + 1)).toISOString().slice(0, 10)
          end = new Date(now.setDate(now.getDate() - now.getDay() + 7)).toISOString().slice(0, 10)
          title = `第${now.getWeek()}周`
          break
        case 'month':
          start = new Date(now.getFullYear(), now.getMonth(), 1).toISOString().slice(0, 10)
          end = new Date(now.getFullYear(), now.getMonth() + 1, 0).toISOString().slice(0, 10)
          title = `${now.getFullYear()}年${now.getMonth() + 1}月`
          break
        case 'year':
          start = new Date(now.getFullYear(), 0, 1).toISOString().slice(0, 10)
          end = new Date(now.getFullYear(), 11, 31).toISOString().slice(0, 10)
          title = `${now.getFullYear()}年`
          break
      }

      const cat = await db.prepare(`
        SELECT category, type, SUM(amount) as total
        FROM records
        WHERE uid=? AND date BETWEEN ? AND ?
        GROUP BY category, type
        ORDER BY total DESC
      `).bind(uid, start, end).all()

      const list = await db.prepare(`
        SELECT * FROM records
        WHERE uid=? AND date BETWEEN ? AND ?
        ORDER BY date DESC, id DESC
      `).bind(uid, start, end).all()

      return c.json({ title, cat: cat.results, list: list.results })
    }

    return c.json({ error: '未知操作' }, 400)
  })
})

export default app
