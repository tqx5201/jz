import { Hono } from 'hono'
const app = new Hono()   // 1. 新建实例

app.get('/', async () => {            // 2. 路由路径不能是空字符串，用 '/'
  const html = 'hello'
  return new Response(html, { headers: { 'content-type': 'text/html;charset=utf-8' } })
})

export default app     // 3. 导出实例
