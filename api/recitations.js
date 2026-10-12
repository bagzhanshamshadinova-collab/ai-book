import crypto from 'node:crypto';

const base=process.env.SUPABASE_URL;
const key=process.env.SUPABASE_SERVICE_ROLE_KEY;
const secret=process.env.AI_BOOK_SESSION_SECRET;
const reply=(res,status,obj)=>res.status(status).setHeader('Cache-Control','no-store').json(obj);
const b64=s=>Buffer.from(s).toString('base64url');
const sig=s=>crypto.createHmac('sha256',secret).update(s).digest('base64url');
const safeEqual=(a,b)=>{const x=Buffer.from(String(a)),y=Buffer.from(String(b));return x.length===y.length&&crypto.timingSafeEqual(x,y)};
const parseCookie=(req,name)=>String(req.headers.cookie||'').split(';').map(s=>s.trim()).find(s=>s.startsWith(name+'='))?.slice(name.length+1)||'';
function isTeacher(req){const [expires,signature]=parseCookie(req,'ai_teacher').split('.');return expires&&signature&&Number(expires)>Date.now()&&safeEqual(signature,sig(expires))}
function studentId(req){const [id,expires,signature]=parseCookie(req,'ai_pupil').split('.');if(!/^[0-9a-f-]{36}$/.test(id||'')||!expires||!signature||Number(expires)<=Date.now()||!safeEqual(signature,sig(`${id}.${expires}`)))return null;return id}
const hashCode=code=>crypto.createHash('sha256').update(`${secret}:student-code:${String(code).toUpperCase()}`).digest('hex');
function cookie(res,name,value,maxAge){res.setHeader('Set-Cookie',`${name}=${value}; HttpOnly; Secure; SameSite=Strict; Path=/api/; Max-Age=${maxAge}`)}
async function db(path,method='GET',body){
 const resp=await fetch(`${base}/rest/v1/${path}`,{method,headers:{apikey:key,Authorization:`Bearer ${key}`,'Content-Type':'application/json',Prefer:'return=representation,resolution=merge-duplicates'},body:body===undefined?undefined:JSON.stringify(body)});
 if(!resp.ok)throw new Error(`Дерекқор қатесі (${resp.status})`);
 const t=await resp.text();return t?JSON.parse(t):[];
}
async function storage(method,path,data){const resp=await fetch(`${base}/storage/v1/${path}`,{method,headers:{apikey:key,Authorization:`Bearer ${key}`,'Content-Type':'application/json'},body:data===undefined?undefined:JSON.stringify(data)});if(!resp.ok)throw Error(`Жазба қоймасының қатесі (${resp.status})`);return resp.json().catch(()=>({}))}
function pupilNameValid(n){return typeof n==='string'&&n.trim().length>=3&&n.trim().length<=80}
function validPosition(m,w){return Number.isInteger(m)&&m>=1&&m<=12&&Number.isInteger(w)&&w>=1&&w<=4}
const types={audio:['audio/mpeg','audio/mp4','audio/wav','audio/ogg','audio/webm'],video:['video/mp4','video/webm','video/quicktime']};
export default async function handler(req,res){
 try{
  if(!base||!key||!secret||secret.length<32)return reply(res,503,{error:'Сервер баптауы дайын емес.'});
  if(req.method!=='POST')return reply(res,405,{error:'POST ғана қолданылады'});
  if(req.headers.origin&&new URL(req.headers.origin).host!==req.headers.host)return reply(res,403,{error:'Сайттан тыс сұранысқа рұқсат жоқ'});
  const v=typeof req.body==='object'&&req.body||{};const action=v.action;
  if(action==='student_register'){
   const name=String(v.name||'').trim().replace(/\s+/g,' ');
   if(!pupilNameValid(name))return reply(res,400,{error:'Толық аты-жөніңізді енгізіңіз.'});
   const existingId=studentId(req);
   if(existingId){
    const existing=await db(`ai_students_secure?id=eq.${existingId}&select=id,display_name`);
    if(existing.length){
     if(existing[0].display_name!==name)return reply(res,409,{error:'Бұл браузерде басқа оқушы тіркелген. Мұғалімнен көмек сұраңыз.'});
     return reply(res,200,{ok:true,name:existing[0].display_name});
    }
   }
   // A browser-bound random session: students never have to type or share a code.
   // Name is self-declared, not verified identity. Do not expose recordings to peers.
   const token=crypto.randomBytes(32).toString('hex');
   const inserted=await db('ai_students_secure','POST',{display_name:name,access_hash:hashCode(token)});
   const id=inserted[0]?.id;if(!id)throw Error('Оқушы тіркелмеді');
   const exp=String(Date.now()+30*24*3600*1000);
   cookie(res,'ai_pupil',`${id}.${exp}.${sig(`${id}.${exp}`)}`,2592000);
   return reply(res,200,{ok:true,name});
  }
  if(action==='student_logout'){cookie(res,'ai_pupil','',0);return reply(res,200,{ok:true})}
  if(action==='teacher_add_student'){
   if(!isTeacher(req))return reply(res,401,{error:'Мұғалім ретінде қайта кіріңіз.'});
   const name=String(v.name||'').trim().replace(/\s+/g,' ');if(!pupilNameValid(name))return reply(res,400,{error:'Оқушының толық аты қажет.'});
   const alphabet='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';const code=Array.from(crypto.randomBytes(10),n=>alphabet[n%alphabet.length]).join('');
   await db('ai_students_secure','POST',{display_name:name,access_hash:hashCode(code)});
   return reply(res,200,{ok:true,name,code});
  }
  if(action==='teacher_roster'){
   if(!isTeacher(req))return reply(res,401,{error:'Мұғалім ретінде қайта кіріңіз.'});
   const students=await db('ai_students_secure?select=id,display_name,created_at&order=created_at.asc');
   const recordings=await db('ai_recitations?select=id,student_id,month_id,week,media_type,status,storage_path,created_at&order=created_at.desc');
   return reply(res,200,{students,recordings:recordings.map(({storage_path,...rest})=>rest)});
  }
  if(action==='teacher_remove_student'){
   if(!isTeacher(req))return reply(res,401,{error:'Мұғалім ретінде қайта кіріңіз.'});
   if(!/^[0-9a-f-]{36}$/.test(v.id||''))return reply(res,400,{error:'Оқушы коды қате'});
   const files=await db(`ai_recitations?student_id=eq.${v.id}&select=storage_path`);
   for(const f of files)await storage('DELETE',`object/ai-book-recitations/${f.storage_path}`);
   await db(`ai_students_secure?id=eq.${v.id}`,'DELETE');return reply(res,200,{ok:true});
  }
  if(action==='teacher_get_video'){
   if(!isTeacher(req))return reply(res,401,{error:'Мұғалім ретінде қайта кіріңіз.'});
   const rows=await db(`ai_recitations?id=eq.${encodeURIComponent(v.id||'')}&select=storage_path`);
   if(!rows.length)return reply(res,404,{error:'Жазба табылмады'});
   const signed=await storage('POST',`object/sign/ai-book-recitations/${rows[0].storage_path}`,{expiresIn:600});
   return reply(res,200,{url:`${base}/storage/v1${signed.signedURL}`});
  }
  if(action==='teacher_review'){
   if(!isTeacher(req))return reply(res,401,{error:'Мұғалім ретінде қайта кіріңіз.'});
   if(!['approved','retry'].includes(v.status))return reply(res,400,{error:'Шешім қате'});
   const rows=await db(`ai_recitations?id=eq.${encodeURIComponent(v.id||'')}&select=id`);if(!rows.length)return reply(res,404,{error:'Жазба жоқ'});
   await db(`ai_recitations?id=eq.${rows[0].id}`,'PATCH',{status:v.status,reviewed_at:new Date().toISOString()});return reply(res,200,{ok:true});
  }
  const id=studentId(req);if(!id)return reply(res,401,{error:'Оқушыны тіркеу қажет. Файлды қайта жіберіп көріңіз.'});
  const rows=await db(`ai_students_secure?id=eq.${id}&select=id,display_name`);if(!rows.length)return reply(res,401,{error:'Оқушы аккаунты табылмады'});
  if(typeof v.name==='string'&&rows[0].display_name.trim().toLocaleLowerCase('kk')!==v.name.trim().toLocaleLowerCase('kk'))return reply(res,403,{error:'Бұл құрылғы басқа оқушыға тіркелген'});
  const m=Number(v.month),w=Number(v.week);if(!validPosition(m,w))return reply(res,400,{error:'Ай немесе апта қате'});
  if(action==='student_status'){
   const items=await db(`ai_recitations?student_id=eq.${id}&select=month_id,week,status,media_type,created_at`);
   return reply(res,200,{name:rows[0].display_name,items});
  }
  if(action==='student_sign'){
   const mime=String(v.mime||''),type=String(v.type||''),size=Number(v.size);
   if(!types[type]?.includes(mime)||!size||size>50*1024*1024)return reply(res,400,{error:'50 МБ-қа дейінгі MP3, WAV, M4A, WEBM немесе MP4 файлды таңдаңыз.'});
   const existing=await db(`ai_recitations?student_id=eq.${id}&month_id=eq.${m}&week=eq.${w}&select=status`);
   if(existing[0]&&existing[0].status!=='retry')return reply(res,409,{error:'Бұл аптаға жазба жіберілген. Мұғалім тексергенше күтіңіз.'});
   const ext=({ 'audio/mpeg':'mp3','audio/mp4':'m4a','audio/wav':'wav','audio/ogg':'ogg','audio/webm':'webm','video/mp4':'mp4','video/webm':'webm','video/quicktime':'mov'})[mime];
   const path=`student-${id}/month-${m}-week-${w}-${crypto.randomUUID()}.${ext}`;
   const signed=await storage('POST',`object/upload/sign/ai-book-recitations/${path}`,{upsert:false});
   return reply(res,200,{path,token:signed.token});
  }
  if(action==='student_submit'){
   const path=String(v.path||''),type=String(v.type||'');
   if(!types[type]||!path.startsWith(`student-${id}/month-${m}-week-${w}-`)||path.includes('..'))return reply(res,400,{error:'Файл сәйкес емес'});
   const old=await db(`ai_recitations?student_id=eq.${id}&month_id=eq.${m}&week=eq.${w}&select=id,status,storage_path`);
   if(old.length&&old[0].status!=='retry')return reply(res,409,{error:'Бұл жаттау бұрын жіберілген'});
   // Check that the uploaded object exists before recording the submission.
   const head=await fetch(`${base}/storage/v1/object/info/ai-book-recitations/${path}`,{headers:{apikey:key,Authorization:`Bearer ${key}`}});
   if(!head.ok)return reply(res,400,{error:'Файл серверге әлі жүктелмеген'});
   if(old.length){await db(`ai_recitations?id=eq.${old[0].id}`,'PATCH',{storage_path:path,media_type:type,status:'pending',created_at:new Date().toISOString(),reviewed_at:null});if(old[0].storage_path!==path)await storage('DELETE',`object/ai-book-recitations/${old[0].storage_path}`).catch(()=>{});}
   else await db('ai_recitations','POST',{student_id:id,month_id:m,week:w,storage_path:path,media_type:type,status:'pending'});
   return reply(res,200,{ok:true});
  }
  return reply(res,400,{error:'Белгісіз әрекет'});
 }catch(err){return reply(res,500,{error:err.message||'Сервер қатесі'})}
}
