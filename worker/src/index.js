// SellChometz API — Cloudflare Worker + D1. Secrets: ADMIN_PASSWORD, SESSION_SECRET
const enc=new TextEncoder();
const loose=s=>String(s??"").toLowerCase().replace(/[^a-z0-9\u0590-\u05ff]/g,"");
const digits=s=>String(s??"").replace(/\D/g,"");
const canon=s=>String(s??"").normalize("NFKC").replace(/[\u2018\u2019\u201A\u201B\u2032]/g,"'").replace(/[\u201C\u201D\u201E\u2033]/g,'"').replace(/[\u2010-\u2015]/g,"-").replace(/[\u00A0\u200B-\u200D\uFEFF]/g," ").trim();
async function diag(env,kind,info){try{await env.DB.prepare("CREATE TABLE IF NOT EXISTS diag(ts INTEGER, kind TEXT, info TEXT)").run();await env.DB.prepare("INSERT INTO diag VALUES(?,?,?)").bind(Date.now(),kind,JSON.stringify(info)).run()}catch(e){}}
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
  const b=await req.json().catch(()=>({}));
  const ident=norm(canon(b.email)),lastL=loose(canon(b.last)),ph=digits(b.phone);
  if(!ident&&!(lastL&&ph.length>=7))return J(h,{error:"Enter your e-mail/username and last name (or your last name and phone number)."},400);
  if(!lastL&&ph.length<7)return J(h,{error:"Please also enter your last name or phone number to verify it's you."},400);
  const rec=await env.DB.prepare("SELECT COUNT(*) c FROM attempts WHERE ip=? AND kind='lookupfail' AND ts>?").bind(ip,Date.now()-15*60000).first();
  if(rec.c>=20)return J(h,{error:"Too many unsuccessful tries. Please wait 15 minutes or ask the Rav for help."},429);
  // any year: newest first
  // The 2018-19 server stripped the domain suffix (".com") from usernames, e.g. name@gmail. Match both forms.
  const v=new Set([ident]);if(ident.includes("@")){const [u,dom]=ident.split("@");v.add(u+"@"+dom.split(".")[0]);if(!dom.includes("."))v.add(ident+".com")}
  const vs=[...v];const pre=(ident.includes("@")&&!ident.split("@")[1].includes("."))?ident+".%":"\u0000";const rows=ident?(await env.DB.prepare(`SELECT id,data FROM submissions WHERE email_norm IN (${vs.map(()=>"?").join(",")}) OR email_norm LIKE ? ORDER BY ts DESC`).bind(...vs,pre).all()).results
                  :(await env.DB.prepare("SELECT id,data FROM submissions ORDER BY ts DESC").all()).results;
  const ok=rows.find(r=>{const d=JSON.parse(r.data);const lastOk=lastL&&loose(d.last)===lastL;const phOk=ph.length>=7&&digits(d.phone).slice(-7)===ph.slice(-7);
    return ident?(lastOk||phOk||(!loose(d.last)&&phOk)):(lastOk&&phOk)});
  if(!ok){await env.DB.prepare("INSERT INTO attempts(ip,kind,ts) VALUES(?,?,?)").bind(ip,"lookupfail",Date.now()).run();
    let lastExists=false;if(lastL){const all=(await env.DB.prepare("SELECT data FROM submissions").all()).results;lastExists=all.some(r=>loose(JSON.parse(r.data).last)===lastL)}
    await diag(env,"lookupfail",{identGiven:!!ident,identHasAt:ident.includes("@"),identFoundRows:ident?rows.length:null,lastGiven:!!lastL,lastExistsAnywhere:lastExists,phoneDigits:ph.length});
    return J(h,{error:"Not found"},404)}
  const d=JSON.parse(ok.data);delete d.sig;delete d.kinyan;
  return J(h,{record:d,token:await sign(env,"edit",ok.id,2*3600000)})}
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
  const f=await env.DB.prepare("SELECT COUNT(*) c FROM attempts WHERE ip=? AND kind='loginfail' AND ts>?").bind(ip,Date.now()-15*60000).first();
  if(f.c>=10)return J(h,{error:"Locked out after too many wrong passwords. Please wait 15 minutes and try again.",locked:true},429);
  const {password}=await req.json().catch(()=>({}));
  const typed=canon(password),real=canon(env.ADMIN_PASSWORD);
  if(!safeEq(typed,real)){await diag(env,"loginfail",{typedLen:typed.length,realLen:real.length,caseInsensitiveMatch:typed.toLowerCase()===real.toLowerCase(),rawHadNonAscii:/[^\x20-\x7e]/.test(String(password||"")),secretHadOuterWs:String(env.ADMIN_PASSWORD)!==String(env.ADMIN_PASSWORD).trim()});await env.DB.prepare("INSERT INTO attempts(ip,kind,ts) VALUES(?,?,?)").bind(ip,"loginfail",Date.now()).run();
   const left=Math.max(0,9-f.c);return J(h,{error:left?`Incorrect password (${left} tr${left===1?"y":"ies"} left before a 15-minute lockout).`:"Incorrect password. Locked out for 15 minutes."},401)}
  await env.DB.prepare("DELETE FROM attempts WHERE ip=? AND kind='loginfail'").bind(ip).run();
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
