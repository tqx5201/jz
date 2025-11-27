import { Hono } from 'hono'   // hono 本体是内置的，无需安装
const app = new Hono()
const JWT_SECRET = 'change-me-123456'   // 密钥，自己换
/* ===== 工具：WebCrypto 版哈希 ===== */
async function hashPwd(password) {
       const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password + JWT_SECRET))
       return btoa(String.fromCharCode(...new Uint8Array(buf)))   // base64
}


import indexHtml from '../public/index.html.js'
/* ===== 前端 ===== */
app.get('/', (c) => {
  return c.html(indexHtml)
})
export default app
