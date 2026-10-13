// Cloudflare Worker: وسيط بسيط بين الصفحة وشركة الشحن (بيتحط من لوحة Cloudflare بدون CMD).
// عدّل السطر ده لرابط موقعك على GitHub Pages (من غير / في الآخر):
const ALLOWED_ORIGINS = ['https://YOURNAME.github.io'];
// الشركات المسموح الاتصال بيها. أضف دومين أي شركة شحن تانية هنا:
const ALLOWED_HOSTS = ['app.bosta.co'];

export default {
  async fetch(req) {
    const origin = req.headers.get('Origin') || '';
    const cors = {
      'Access-Control-Allow-Origin': ALLOWED_ORIGINS.includes(origin) ? origin : 'null',
      'Access-Control-Allow-Headers': 'Authorization, Content-Type',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Vary': 'Origin'
    };
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    if (!ALLOWED_ORIGINS.includes(origin)) return new Response('Forbidden', { status: 403, headers: cors });
    let u;
    try { u = new URL(new URL(req.url).searchParams.get('url')); } catch { return new Response('Bad url', { status: 400, headers: cors }); }
    if (u.protocol !== 'https:' || !ALLOWED_HOSTS.includes(u.hostname)) return new Response('Host not allowed', { status: 403, headers: cors });
    const r = await fetch(u, { method: 'GET', headers: { Authorization: req.headers.get('Authorization') || '', 'Content-Type': 'application/json' } });
    return new Response(r.body, { status: r.status, headers: { ...cors, 'Content-Type': r.headers.get('Content-Type') || 'application/json' } });
  }
};
