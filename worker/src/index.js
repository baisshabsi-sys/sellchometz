// SellChometz API — Cloudflare Worker + D1. Secrets: ADMIN_PASSWORD, SESSION_SECRET
const enc=new TextEncoder();
const norm=s=>String(s??"").trim().toLowerCase().replace(/\s+/g," ");
const b64u=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
async function hmac(env,msg){const k=await crypto.subtle.importKey("raw",enc.encode(env.SESSION_SECRET),{name:"HMAC",hash:"SHA-256"},false,["sign"]);return b64u(await crypto.subtle.sign("HMAC",k,enc.encode(msg)))}
function safeEq(a,b){a=String(a);b=String(b);let r=a.length^b.length;for(let i=0;i<Math.max(a.length,b.length);i++)r|=(a.charCodeAt(i)||0)^(b.charCodeAt(i)||0);return r===0}
async function sign(env,kind,sub,ttl){const exp=Date.now()+ttl;const p=`${kind}.${sub}.${exp}`;return p+"."+(await hmac(env,p))}
async function verify(env,tok,kind){if(!tok)return null;const i=tok.lastIndexOf(".");if(i<0)return null;const p=tok.slice(0,i),s=tok.slice(i+1);if(!safeEq(s,await hmac(env,p)))return null;const [k,sub,exp]=p.split(".");if(k!==kind||+exp<Date.now())return null;return sub}
function cors(env,req){const o=req.headers.get("Origin")||"";const ok=(env.ALLOWED_ORIGINS||"").split(",").map(s=>s.trim()).includes(o);return ok?{"Access-Control-Allow-Origin":o,"Access-Control-Allow-Headers":"Content-Type,Authorization","Access-Control-Allow-Methods":"GET,POST,PUT,DELETE,OPTIONS","Vary":"Origin"}:{}}
const J=(h,data,status=200)=>new Response(JSON.stringify(data),{status,headers:{...h,"Content-Type":"application/json","Cache-Control":"no-store"}});
async function limited(env,ip,kind,max,winMs){const since=Date.now()-winMs;await env.DB.prepare("DELETE FROM attempts WHERE ts<?").bind(Date.now()-86400000).run();const r=await env.DB.prepare("SELECT COUNT(*) c FROM attempts WHERE ip=? AND kind=? AND ts>?").bind(ip,kind,since).first();if(r.c>=max)return true;await env.DB.prepare("INSERT INTO attempts(ip,kind,ts) VALUES(?,?,?)").bind(ip,kind,Date.now()).run();return false}
const PUBLIC_SETTINGS=["rabbi","shul","shulEmail","deadline","donation","showHebrew"];
const DEFAULTS={rabbi:"Rabbi Yaakov Kaplan",shul:"Bais Shabsi",shulEmail:"baisshabsi@gmail.com",deadline:"",donation:"",showHebrew:true};
async function getSettings(env){const rs=(await env.DB.prepare("SELECT k,v FROM settings").all()).results;const s={...DEFAULTS};rs.forEach(r=>{try{s[r.k]=JSON.parse(r.v)}catch{}});return s}
const ALLOWED=["first","last","address","city","state","phone","email","places","placeOther","more","moreOther","zone","products","affixed","productOther","value","home","keys","keyPlace","comb","combo","bedika","bedikaText","sig","kinyan","date","year","donation"];
function clean(r){const o={};for(const k of ALLOWED)if(k in r)o[k]=r[k];return o}
async function isAdmin(env,req){const a=req.headers.get("Authorization")||"";return !!(await verify(env,a.replace(/^Bearer /,""),"admin"))}

export default{async fetch(req,env){
 const url=new URL(req.url),p=url.pathname,h=cors(env,req),ip=req.headers.get("CF-Connecting-IP")||"local";
 if(req.method==="OPTIONS")return new Response(null,{status:204,headers:h});
 if(!env.SESSION_SECRET||!env.ADMIN_PASSWORD)return J(h,{error:"server not configured"},500);
 try{
 if(p==="/api/settings"&&req.method==="GET"){const s=await getSettings(env);return J(h,Object.fromEntries(PUBLIC_SETTINGS.map(k=>[k,s[k]])))}
 if(p==="/api/lookup"&&req.method==="POST"){
  if(await limited(env,ip,"lookup",10,15*60000))return J(h,{error:"Too many attempts. Please try again later."},429);
  const {email,last}=await req.json();if(!norm(email)||!norm(last))return J(h,{error:"Email and last name required"},400);
  const r=await env.DB.prepare("SELECT id,data FROM submissions WHERE email_norm=? AND last_norm=? ORDER BY ts DESC LIMIT 1").bind(norm(email),norm(last)).first();
  if(!r)return J(h,{error:"Not found"},404);
  const d=JSON.parse(r.data);delete d.sig;delete d.kinyan;
  return J(h,{record:d,token:await sign(env,"edit",r.id,2*3600000)})}
 if(p==="/api/submit"&&req.method==="POST"){
  if(await limited(env,ip,"submit",30,15*60000))return J(h,{error:"Too many submissions. Please try again later."},429);
  const body=await req.json();const rec=clean(body.record||{});
  if(JSON.stringify(rec).length>300000)return J(h,{error:"Submission too large"},413);
  if(!norm(rec.first)||!norm(rec.last)||!norm(rec.email))return J(h,{error:"Missing name or email"},400);
  if(!rec.sig||!rec.kinyan)return J(h,{error:"Signature and kinyan required"},400);
  rec.year=parseInt(rec.year)||new Date().getFullYear();const ts=Date.now();
  let id=null;const tokId=await verify(env,body.token,"edit");
  if(tokId){const ex=await env.DB.prepare("SELECT id,year FROM submissions WHERE id=?").bind(tokId).first();if(ex&&+ex.year===rec.year&&!String(ex.id).startsWith("IMP"))id=ex.id}
  if(!id)id="MC"+ts.toString(36).toUpperCase()+crypto.getRandomValues(new Uint32Array(1))[0].toString(36).toUpperCase();
  rec.id=id;rec.ts=ts;
  await env.DB.prepare("INSERT INTO submissions(id,email_norm,last_norm,year,ts,data,imported) VALUES(?,?,?,?,?,?,0) ON CONFLICT(id) DO UPDATE SET email_norm=excluded.email_norm,last_norm=excluded.last_norm,year=excluded.year,ts=excluded.ts,data=excluded.data").bind(id,norm(rec.email),norm(rec.last),rec.year,ts,JSON.stringify(rec)).run();
  return J(h,{id,token:await sign(env,"edit",id,2*3600000)})}
 if(p==="/api/admin/login"&&req.method==="POST"){
  if(await limited(env,ip,"login",8,15*60000))return J(h,{error:"Too many attempts. Try again in 15 minutes."},429);
  const {password}=await req.json();if(!safeEq(password||"",env.ADMIN_PASSWORD))return J(h,{error:"Incorrect password"},401);
  return J(h,{token:await sign(env,"admin","admin",12*3600000)})}
 if(p.startsWith("/api/admin/")){
  if(!(await isAdmin(env,req)))return J(h,{error:"Unauthorized"},401);
  if(p==="/api/admin/records"&&req.method==="GET"){const rs=(await env.DB.prepare("SELECT data FROM submissions ORDER BY ts DESC").all()).results;return J(h,rs.map(r=>JSON.parse(r.data)))}
  if(p.startsWith("/api/admin/records/")&&req.method==="DELETE"){await env.DB.prepare("DELETE FROM submissions WHERE id=?").bind(decodeURIComponent(p.split("/").pop())).run();return J(h,{ok:true})}
  if(p==="/api/admin/settings"&&req.method==="PUT"){const s=await req.json();const st=[];for(const k of PUBLIC_SETTINGS)if(k in s)st.push(env.DB.prepare("INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(k,JSON.stringify(s[k])));if(st.length)await env.DB.batch(st);return J(h,{ok:true})}
  if(p==="/api/admin/import"&&req.method==="POST"){const d=await req.json();const recs=(d.records||d);let n=0;const st=[];for(const r0 of recs){if(!r0||!r0.id)continue;const r={...clean(r0),id:String(r0.id),ts:+r0.ts||Date.now(),imported:!!r0.imported,source:r0.source};st.push(env.DB.prepare("INSERT OR IGNORE INTO submissions(id,email_norm,last_norm,year,ts,data,imported) VALUES(?,?,?,?,?,?,?)").bind(r.id,norm(r.email),norm(r.last),parseInt(r.year)||0,r.ts,JSON.stringify(r),r.imported?1:0))}
   for(let i=0;i<st.length;i+=50){const res=await env.DB.batch(st.slice(i,i+50));res.forEach(x=>n+=x.meta.changes||0)}return J(h,{imported:n})}
 }
 return J(h,{error:"Not found"},404)}catch(e){return J(h,{error:"Server error"},500)}}};
