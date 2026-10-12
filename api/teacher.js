import crypto from 'node:crypto';
const json=(res,status,obj)=>res.status(status).setHeader('Cache-Control','no-store').json(obj);
const eq=(a,b)=>{const x=Buffer.from(String(a)),y=Buffer.from(String(b));return x.length===y.length&&crypto.timingSafeEqual(x,y)};
const base=process.env.SUPABASE_URL;
const key=process.env.SUPABASE_SERVICE_ROLE_KEY;
const secret=process.env.AI_BOOK_SESSION_SECRET;
const pin=process.env.AI_BOOK_TEACHER_PIN;
const configured=()=>base&&key&&secret?.length>=32&&/^\d{4}$/.test(pin||'');
const mac=s=>crypto.createHmac('sha256',secret).update(s).digest('base64url');
const token=()=>{const val=String(Date.now()+8*3600*1000);return `${val}.${mac(val)}`};
const authorized=req=>{const raw=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('ai_teacher='))?.slice(11)||'';const [exp,sig]=raw.split('.');return exp&&sig&&Number(exp)>Date.now()&&Number(exp)<Date.now()+9*3600*1000&&eq(sig,mac(exp))};
const admin=async(path,method='GET',body)=>{const r=await fetch(`${base}/rest/v1/${path}`,{method,headers:{apikey:key,Authorization:`Bearer ${key}`,'Content-Type':'application/json',Prefer:'return=representation,resolution=merge-duplicates'},body:body===undefined?undefined:JSON.stringify(body)});if(!r.ok)throw Error(`Дерекқор қатесі (${r.status})`);const t=await r.text();return t?JSON.parse(t):null};
const validMonth=i=>Number.isInteger(i)&&i>=1&&i<=12;
const mimeTypes={pdf:['application/pdf'],audio:['audio/mpeg','audio/mp4','audio/wav','audio/ogg'],video:['video/mp4','video/webm','video/ogg']};
export default async function handler(req,res){
 try{
  if(!configured())return json(res,503,{error:'Vercel баптауларында серверлік құпиялар орнатылмаған.'});
  if(req.method!=='POST')return json(res,405,{error:'POST ғана'});
  const origin=req.headers.origin;const host=req.headers.host;
  if(origin&&new URL(origin).host!==host)return json(res,403,{error:'Сайттан тыс сұрау қабылданбайды'});
  const {action,...v}=req.body||{};
  if(action==='login'){
    const ip=crypto.createHash('sha256').update((req.headers['x-forwarded-for']||req.socket.remoteAddress||'').split(',')[0]+secret).digest('hex');
    const existing=await admin(`ai_pin_attempts?ip_hash=eq.${ip}&select=attempts,window_start`);
    const now=Date.now();const old=existing?.[0];const within=old&&now-new Date(old.window_start).getTime()<15*60*1000;
    if(within&&old.attempts>=5)return json(res,429,{error:'Тым көп әрекет. 15 минуттан кейін қайталап көріңіз.'});
    if(typeof v.pin!=='string'||!eq(v.pin,pin)){
      await admin('ai_pin_attempts?on_conflict=ip_hash','POST',[{ip_hash:ip,attempts:within?old.attempts+1:1,window_start:within?old.window_start:new Date().toISOString()}]);
      return json(res,401,{error:'Код қате'});
    }
    await admin(`ai_pin_attempts?ip_hash=eq.${ip}`,'DELETE');
    res.setHeader('Set-Cookie',`ai_teacher=${token()}; HttpOnly; Secure; SameSite=Strict; Path=/api/; Max-Age=28800`);
    return json(res,200,{ok:true});
  }
  if(action==='logout'){res.setHeader('Set-Cookie','ai_teacher=; HttpOnly; Secure; SameSite=Strict; Path=/api/; Max-Age=0');return json(res,200,{ok:true})}
  if(!authorized(req))return json(res,401,{error:'Мұғалім сессиясы аяқталды. Кодты қайта енгізіңіз.'});
  if(action==='session')return json(res,200,{ok:true});
  const i=Number(v.month);if(!validMonth(i))return json(res,400,{error:'Ай дұрыс емес'});
  if(action==='save'){
   const patch={updated_at:new Date().toISOString()};
   for(const k of ['title','author','video_url'])if(typeof v[k]==='string')patch[k]=v[k].slice(0,k==='video_url'?2000:150);
   if(Array.isArray(v.poems)&&v.poems.length===4&&v.poems.every(x=>typeof x==='string'))patch.poems=v.poems.map(x=>x.slice(0,5000));
   if(Array.isArray(v.quiz)&&v.quiz.length===5&&v.quiz.every(x=>typeof x.q==='string'&&Array.isArray(x.a)&&x.a.length===3&&x.a.every(t=>typeof t==='string')&&[0,1,2].includes(Number(x.right))))patch.quiz=v.quiz.map(x=>({q:x.q.slice(0,500),a:x.a.map(t=>t.slice(0,300)),right:Number(x.right)}));
   if(Array.isArray(v.media_items)&&v.media_items.length<=100&&v.media_items.every(x=>['pdf','audio','video','link'].includes(x.type)&&typeof x.title==='string'&&typeof x.url==='string'&&/^https:\/\//.test(x.url)&&(!x.path||x.path.startsWith(`month-${i}/`))))patch.media_items=v.media_items.map(x=>({type:x.type,title:x.title.slice(0,150),url:x.url.slice(0,2500),...(x.path?{path:x.path}: {})}));
   await admin(`ai_books?id=eq.${i}`,'PATCH',patch);return json(res,200,{ok:true});
  }
  if(action==='sign'){
   const type=v.type,mime=v.mime,size=Number(v.size),ext=String(v.ext||'').toLowerCase();
   if(!mimeTypes[type]?.includes(mime)||!Number.isFinite(size)||size<=0||size>100*1024*1024||!/^[a-z0-9]{1,5}$/.test(ext))return json(res,400,{error:'Файл түрі немесе көлемі дұрыс емес'});
   const path=`month-${i}/${type}-${crypto.randomUUID()}.${ext}`;
   const r=await fetch(`${base}/storage/v1/object/upload/sign/ai-book-library/${path}`,{method:'POST',headers:{apikey:key,Authorization:`Bearer ${key}`,'Content-Type':'application/json'},body:JSON.stringify({upsert:false})});
   if(!r.ok)return json(res,500,{error:'Жүктеуге рұқсат алу мүмкін болмады'});
   const body=await r.json();return json(res,200,{path,token:body.token,url:`${base}/storage/v1/object/public/ai-book-library/${path}`});
  }
  if(action==='delete_file'){
   const path=String(v.path||'');if(!path.startsWith(`month-${i}/`)||path.includes('..'))return json(res,400,{error:'Файл жолы қате'});
   const r=await fetch(`${base}/storage/v1/object/ai-book-library/${path}`,{method:'DELETE',headers:{apikey:key,Authorization:`Bearer ${key}`}});if(!r.ok)return json(res,500,{error:'Файл өшірілмеді'});return json(res,200,{ok:true});
  }
  return json(res,400,{error:'Белгісіз әрекет'});
 }catch(e){return json(res,500,{error:e.message||'Сервер қатесі'})}
}
