import { Hono } from 'hono'
import htmlContent from '../public/index.html'   // HTML 字符串

const app = new Hono()
const JWT_SECRET = c.env.JWT_SECRET   // 从环境变量读取

/* ===== 0. 数据库初始化 ===== */
const initDB = async (db) => {
  const stmts = [
    `CREATE TABLE IF NOT EXISTS users (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       user TEXT UNIQUE NOT NULL,
       pwd TEXT NOT NULL,
       created_at DATETIME DEFAULT CURRENT_TIMESTAMP
     );`,
    `CREATE TABLE IF NOT EXISTS categories (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       user_id INTEGER NOT NULL,
       name TEXT NOT NULL,
       type TEXT CHECK(type IN ('income','expense')) NOT NULL
     );`,
    `CREATE TABLE IF NOT EXISTS records (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       user_id INTEGER NOT NULL,
       date DATE NOT NULL,
       amount REAL NOT NULL,
       category TEXT NOT NULL,
       type TEXT CHECK(type IN ('income','expense')) NOT NULL,
       note TEXT,
       updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
       FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
     );`
  ]
  for (const sql of stmts) await db.prepare(sql).run()
}

/* ===== 1. 工具：哈希 & JWT ===== */
async function hashPwd(p) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(p + JWT_SECRET))
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('')
}
async function signJWT(sub) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
  const payload = btoa(JSON.stringify({ sub, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 86400 }))
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(header + '.' + payload))
  return header + '.' + payload + '.' + [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('')
}
async function verifyJWT(token) {
  const [h, p, s] = token.split('.')
  if (!h || !p || !s) throw new Error('bad token')
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify'])
  const valid = await crypto.subtle.verify('HMAC', key, new Uint8Array(s.match(/.{1,2}/g).map(b => parseInt(b, 16))), new TextEncoder().encode(h + '.' + p))
  if (!valid) throw new Error('invalid')
  return JSON.parse(atob(p))
}

/* ===== 2. 统一鉴权中间件 ===== */
async function auth(c, next) {
  try {
    const token = c.req.header('Authorization')?.replace('Bearer ', '') || ''
    const payload = await verifyJWT(token)
    c.set('uid', payload.sub)
    return next()
  } catch {
    return c.json({ error: '未登录' }, 401)
  }
}

/* ===== 3. 前端页面 ===== */
app.get('/', (c) => c.html(htmlContent))

/* ===== 4. API 总入口 ===== */
app.post('/api', async (c) => {
  const db = c.env.DB
  await initDB(db)
  const body = await c.req.json().catch(() => ({}))
  const op = body.op
  const uid = c.get('uid')

  // 登录/注册
  if (op === 'register' || op === 'login') {
    const user = body.user?.trim(), pwd = body.pwd?.trim()
    if (!user || !pwd) return c.json({ error: '用户名/密码必填' }, 400)
    if (op === 'register') {
      const exist = await db.prepare('SELECT id FROM users WHERE user=?').bind(user).first()
      if (exist) return c.json({ error: '用户名已存在' }, 400)
      const { meta } = await db.prepare('INSERT INTO users(user,pwd) VALUES(?,?)').bind(user, await hashPwd(pwd)).run()
      const id = meta.last_row_id
      const token = await signJWT(id)
      return c.json({ token, uname: user, uid: id })
    }
    if (op === 'login') {
      const row = await db.prepare('SELECT id,pwd FROM users WHERE user=?').bind(user).first()
      if (!row || row.pwd !== (await hashPwd(pwd))) return c.json({ error: '账号或密码错误' }, 401)
      const token = await signJWT(row.id)
      return c.json({ token, uname: user, uid: row.id })
    }
  }

  // 需要登录的接口
  return auth(c, async () => {
    if (op === 'check') {
      const row = await db.prepare('SELECT id, user FROM users WHERE id=?').bind(c.get('uid')).first()
      if (!row) return c.json({ error: 'token无效' }, 401)
      return c.json({ ok: true, uid: row.id, uname: row.user })   // ← 这里加上 uname
    }

    // 分类
    if (op === 'catList') {
      const list = await db.prepare('SELECT name FROM categories WHERE (user_id=0 or user_id=?) AND type=? ORDER BY id DESC').bind(c.get('uid'), body.type).all()
      return c.json(list.results)
    }
    if (op === 'catAdd') {
      const { name, type } = body
      if (!name) return c.json({ error: '名称必填' }, 400)
      await db.prepare('INSERT INTO categories(user_id,name,type) VALUES(?,?,?)').bind(c.get('uid'), name, type).run()
      return c.json({ ok: true })
    }

    // 流水
    if (op === 'list') {
      if (body.id) {   // 单条
        const row = await db.prepare('SELECT * FROM records WHERE id=? AND user_id=?').bind(body.id, c.get('uid')).first()
        return c.json(row ? [row] : [])
      }
      // 最近 6 条
      const list = await db.prepare(`
        SELECT * FROM records WHERE user_id=? ORDER BY date DESC, id DESC LIMIT 6
      `).bind(c.get('uid')).all()
      return c.json(list.results)
    }
    if (op === 'add' || op === 'edit') {
      const { type, amount, category, date, note } = body
      if (!amount || !category || !date) return c.json({ error: '字段不完整' }, 400)
      if (op === 'add') {
        await db.prepare(`
          INSERT INTO records(user_id,date,amount,category,type,note)
          VALUES(?,?,?,?,?,?)
        `).bind(c.get('uid'), date, amount, category, type, note || '').run()
      }
      if (op === 'edit') {
        await db.prepare(`
          UPDATE records SET date=?,amount=?,category=?,type=?,note=? WHERE id=? AND user_id=?
        `).bind(date, amount, category, type, note || '', body.id, c.get('uid')).run()
      }
      return c.json({ ok: true })
    }
    if (op === 'del') {
      await db.prepare('DELETE FROM records WHERE id=? AND user_id=?').bind(body.id, c.get('uid')).run()
      return c.json({ ok: true })
    }
    if (op === 'stat') {
      // 按周期汇总（示例：月）
      const userId = c.get('uid')
      const period = body.period || 'month'
      const offset = body.offset || 0
      // 简单实现：取当前年-月 ±offset
      const now = new Date()
      now.setMonth(now.getMonth() + offset)
      const year = String(now.getFullYear()), month = String(now.getMonth() + 1).padStart(2, '0')
      const title = `${year}-${month}`

      // 分类汇总
      const cat = await db.prepare(`
        SELECT category, type, SUM(amount) as total
        FROM records
        WHERE user_id=? AND strftime('%Y',date)=? AND strftime('%m',date)=?
        GROUP BY category, type
        ORDER BY total DESC
      `).bind(userId, year, month).all()

      // 明细列表
      const list = await db.prepare(`
        SELECT * FROM records
        WHERE user_id=? AND strftime('%Y',date)=? AND strftime('%m',date)=?
        ORDER BY date DESC, id DESC
      `).bind(userId, year, month).all()

      return c.json({ title, cat: cat.results, list: list.results })
    }

    return c.json({ error: '未知操作' }, 400)
  })
})

export default app
