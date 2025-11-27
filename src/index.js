import { Hono } from 'hono'
import { jwt } from 'hono/jwt'
import { bcrypt } from 'bcrypt-wasm'
const app = new Hono()
const JWT_SECRET = 'change-me-123456'
const hash = p => bcrypt.hashSync(p, 10)
const compare = (p, h) => bcrypt.compareSync(p, h)

/* ===== 中间件 ===== */
const auth = jwt({ secret: JWT_SECRET })
/* ===== 用户 ===== */
app.post('/api/register', async c => {
const { email, pwd } = await c.req.json()
const db = c.env.DB
await initDB(db)
const exist = await db.prepare('SELECT id FROM users WHERE email=?').bind(email).first()
if (exist) return c.json({ msg: '邮箱已存在' }, 400)
const { meta } = await db.prepare('INSERT INTO users(email,pwd) VALUES(?,?)').bind(email, hash(pwd)).run()
return c.json({ id: meta.last_row_id })
})
app.post('/api/login', async c => {
const { email, pwd } = await c.req.json()
const db = c.env.DB
await initDB(db)
const u = await db.prepare('SELECT id,pwd FROM users WHERE email=?').bind(email).first()
if (!u || !compare(pwd, u.pwd)) return c.json({ msg: '账号或密码错误' }, 401)
const token = await jwt.sign({ sub: u.id }, JWT_SECRET)
return c.json({ token })
})
/* ===== 分类 ===== */
app.get('/api/categories', auth, async c => {
const userId = c.get('jwtPayload').sub
const list = await c.env.DB.prepare('SELECT id,name,type FROM categories WHERE user_id=?').bind(userId).all()
return c.json(list.results)
})
app.post('/api/categories', auth, async c => {
const userId = c.get('jwtPayload').sub
const { name, type } = await c.req.json()
await c.env.DB.prepare('INSERT INTO categories(user_id,name,type) VALUES(?,?,?)').bind(userId, name, type).run()
return c.json({ ok: true })
})
/* ===== 流水 ===== */
// 分页 + 筛选
app.get('/api/records/search', auth, async c => {
const userId = c.get('jwtPayload').sub
const { category_id, year, month, page = 1, size = 20 } = c.req.query()
const db = c.env.DB
let where = 'WHERE r.user_id=?'
const params = [userId]
if (category_id) { where += ' AND r.category_id=?'; params.push(category_id) }
if (year) { where += ' AND strftime("%Y",r.date)=?'; params.push(year) }
if (month) { where += ' AND strftime("%m",r.date)=?'; params.push(month.padStart(2, '0')) }
const { total } = await db.prepare(SELECT COUNT(*) as total FROM records r ${where}).bind(...params).first()
const list = await db.prepare(
SELECT r.id, r.date, r.amount, r.remark, c.name as category, c.type
     FROM records r JOIN categories c ON r.category_id=c.id
     ${where} ORDER BY r.date DESC, r.id DESC LIMIT ? OFFSET ?

).bind(...params, Number(size), (page - 1) * size).all()


const stat = await db.prepare(
SELECT
       SUM(CASE WHEN c.type='收入' THEN r.amount ELSE 0 END) AS income,
       SUM(CASE WHEN c.type='支出' THEN r.amount ELSE 0 END) AS expense
     FROM records r JOIN categories c ON r.category_id=c.id ${where}

).bind(...params).first()
return c.json({ total, page: Number(page), size: Number(size), pages: Math.ceil(total / size), list: list.results, stat })
})
// 年月下拉
app.get('/api/records/dates', auth, async c => {
const userId = c.get('jwtPayload').sub
const rows = await c.env.DB.prepare(
SELECT DISTINCT strftime('%Y',date) as year, strftime('%m',date) as month
     FROM records WHERE user_id=? ORDER BY year DESC, month DESC

).bind(userId).all()
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
