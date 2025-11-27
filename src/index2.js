import { Hono } from 'hono'   // hono 本体是内置的，无需安装
const app = new Hono()
const JWT_SECRET = 'change-me-123456'   // 密钥，自己换
/* ===== 工具：WebCrypto 版哈希 ===== */
async function hashPwd(password) {
const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password + JWT_SECRET))
return btoa(String.fromCharCode(...new Uint8Array(buf)))   // base64
}
/* ===== 工具：简易 JWT（仅 sign / verify） ===== */
async function signJWT(payload) {
const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
const payloadB64 = btoa(JSON.stringify({ ...payload, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 86400 }))
const signingInput = header + '.' + payloadB64
const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signingInput))
const signature = btoa(String.fromCharCode(...new Uint8Array(sig)))
return signingInput + '.' + signature
}
async function verifyJWT(token) {
const [header, payload, signature] = token.split('.')
if (!header || !payload || !signature) throw new Error('bad token')
const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify'])
const valid = await crypto.subtle.verify('HMAC', key, new Uint8Array(atob(signature).split('').map(c => c.charCodeAt(0))), new TextEncoder().encode(header + '.' + payload))
if (!valid) throw new Error('invalid signature')
return JSON.parse(atob(payload))
}
/* ===== 统一鉴权中间件 ===== */
async function auth(c, next) {
const hdr = c.req.header('Authorization') || ''
const token = hdr.replace('Bearer ', '')
try {
const payload = await verifyJWT(token)
c.set('jwtPayload', payload)
return next()
} catch {
return c.json({ msg: '未登录或令牌失效' }, 401)
}
}
/* ===== 初始化数据库 ===== */
const initDB = async (db) => {
const stmts = [
`CREATE TABLE IF NOT EXISTS users (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       email TEXT UNIQUE NOT NULL,
       pwd TEXT NOT NULL,
       created_at DATETIME DEFAULT CURRENT_TIMESTAMP
     );`
,
`CREATE TABLE IF NOT EXISTS categories (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       user_id INTEGER NOT NULL,
       name TEXT NOT NULL,
       type TEXT CHECK(type IN ('收入','支出')) NOT NULL,
       FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
     );`
,
`CREATE TABLE IF NOT EXISTS records (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       user_id INTEGER NOT NULL,
       date DATE NOT NULL,
       amount REAL NOT NULL,
       category_id INTEGER NOT NULL,
       remark TEXT,
       updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
       FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
       FOREIGN KEY(category_id) REFERENCES categories(id) ON DELETE CASCADE
     );`
]
for (const sql of stmts) await db.prepare(sql).run()
}
/* ===== 用户 ===== */
app.post('/api/register', async c => {
const db = c.env.DB
await initDB(db)
const { email, pwd } = await c.req.json()
const exist = await db.prepare('SELECT id FROM users WHERE email=?').bind(email).first()
if (exist) return c.json({ msg: '邮箱已存在' }, 400)
const { meta } = await db.prepare('INSERT INTO users(email,pwd) VALUES(?,?)').bind(email, await hashPwd(pwd)).run()
return c.json({ id: meta.last_row_id })
})
app.post('/api/login', async c => {
const db = c.env.DB
await initDB(db)
const { email, pwd } = await c.req.json()
const u = await db.prepare('SELECT id,pwd FROM users WHERE email=?').bind(email).first()
if (!u || u.pwd !== (await hashPwd(pwd))) return c.json({ msg: '账号或密码错误' }, 401)
const token = await signJWT({ sub: u.id })
return c.json({ token })
})
/* ===== 分类 ===== */
app.get('/api/categories', auth, async c => {
const list = await c.env.DB.prepare('SELECT id,name,type FROM categories WHERE user_id=?').bind(c.get('jwtPayload').sub).all()
return c.json(list.results)
})
app.post('/api/categories', auth, async c => {
const userId = c.get('jwtPayload').sub
const { name, type } = await c.req.json()
await c.env.DB.prepare('INSERT INTO categories(user_id,name,type) VALUES(?,?,?)').bind(userId, name, type).run()
return c.json({ ok: true })
})
/* ===== 流水 ===== */
// 分页+筛选
app.get('/api/records/search', auth, async c => {
const userId = c.get('jwtPayload').sub
const { category_id, year, month, page = 1, size = 20 } = c.req.query()
const db = c.env.DB
let where = 'WHERE r.user_id=?'
const params = [userId]
if (category_id) { where += ' AND r.category_id=?'; params.push(category_id) }
if (year) { where += ' AND strftime("%Y",r.date)=?'; params.push(year) }
if (month) { where += ' AND strftime("%m",r.date)=?'; params.push(month.padStart(2, '0')) }
const countSql = 'SELECT COUNT(*) as total FROM records r ' + where
const { total } = await db.prepare(countSql).bind(...params).first()
const listSql = 
`SELECT r.id, r.date, r.amount, r.remark, c.name as category, c.type
    FROM records r JOIN categories c ON r.category_id=c.id
    ${where} ORDER BY r.date DESC, r.id DESC LIMIT ? OFFSET ?`

const list = await db.prepare(listSql).bind(...params, Number(size), (page - 1) * size).all()
const statSql = 
`SELECT
      SUM(CASE WHEN c.type='收入' THEN r.amount ELSE 0 END) AS income,
      SUM(CASE WHEN c.type='支出' THEN r.amount ELSE 0 END) AS expense
    FROM records r JOIN categories c ON r.category_id=c.id ${where}`

const stat = await db.prepare(statSql).bind(...params).first()
return c.json({ total, page: Number(page), size: Number(size), pages: Math.ceil(total / size), list: list.results, stat })
})
// 年月下拉
app.get('/api/records/dates', auth, async c => {
const rows = await c.env.DB.prepare(
`SELECT DISTINCT strftime('%Y',date) as year, strftime('%m',date) as month
     FROM records WHERE user_id=? ORDER BY year DESC, month DESC`

).bind(c.get('jwtPayload').sub).all()
return c.json(rows.results)
})
// 增删改
app.post('/api/records', auth, async c => {
const userId = c.get('jwtPayload').sub
const { date, amount, category_id, remark } = await c.req.json()
await c.env.DB.prepare('INSERT INTO records(user_id,date,amount,category_id,remark) VALUES(?,?,?,?,?)')
.bind(userId, date, amount, category_id, remark || '').run()
return c.json({ ok: true })
})
app.put('/api/records/:id', auth, async c => {
const userId = c.get('jwtPayload').sub
const id = c.req.param('id')
const { date, amount, category_id, remark } = await c.req.json()
await c.env.DB.prepare('UPDATE records SET date=?,amount=?,category_id=?,remark=? WHERE id=? AND user_id=?')
.bind(date, amount, category_id, remark || '', id, userId).run()
return c.json({ ok: true })
})
app.delete('/api/records/:id', auth, async c => {
const userId = c.get('jwtPayload').sub
const id = c.req.param('id')
await c.env.DB.prepare('DELETE FROM records WHERE id=? AND user_id=?').bind(id, userId).run()
return c.json({ ok: true })
})
/* ===== 前端 ===== */
app.get('', async () => {
const html = await fetch(new URL('../public/index.html', import.meta.url)).then(r => r.text())
return new Response(html, { headers: { 'content-type': 'text/html;charset=utf-8' } })
})
export default app
