(function(root){
 'use strict';
 const bytes=s=>Uint8Array.from(atob(s.replace(/\s/g,'')),c=>c.charCodeAt(0));
 async function unlock(payload,password,cryptoApi=root.crypto){
  if(!['xsb-monitor-config-1','xsb-monitor-page-1'].includes(payload.format)||payload.iterations!==200000)throw Error('学习记录连接配置格式错误');
  const base=await cryptoApi.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveKey']);
  const key=await cryptoApi.subtle.deriveKey({name:'PBKDF2',salt:bytes(payload.salt),iterations:payload.iterations,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['decrypt']);
  let result;try{const plain=new TextDecoder().decode(await cryptoApi.subtle.decrypt({name:'AES-GCM',iv:bytes(payload.iv)},key,bytes(payload.ciphertext)));if(payload.format==='xsb-monitor-page-1'){const token=plain.match(/const MON_TOKEN="([^"]+)"/),dataKey=plain.match(/const MON_K="([^"]+)"/);if(!token||!dataKey)throw Error('记录接口已变化');result={token:token[1],key:dataKey[1]};}else result=JSON.parse(plain);}catch(e){throw Error('家长看板密码不正确');}
  if(typeof result.token!=='string'||typeof result.key!=='string'||bytes(result.key).length!==32)throw Error('学习记录连接配置不完整');return result;
 }
 async function unlockPage(html,password,cryptoApi=root.crypto){const match=html.match(/const P=(\{.*?\});/s);if(!match)throw Error('原家长看板格式已变化，请联系家长更新连接');let p;try{p=JSON.parse(match[1].replace(/([,{])\s*([a-z]+)\s*:/g,'$1"$2":'));}catch(e){throw Error('原看板加密配置无法读取');}return unlock({format:'xsb-monitor-page-1',salt:p.s,iv:p.i,iterations:p.n,ciphertext:p.c},password,cryptoApi);}
 const day=t=>new Date((t??Date.now())+8*3600000).toISOString().slice(0,10);
 class Monitor {
  constructor(config,fetcher=(...args)=>root.fetch(...args),cryptoApi=root.crypto){this.token=config.token;this.secret=config.key;this.fetch=fetcher;this.crypto=cryptoApi;this.list=[];this.kids={};this.images=new Map();}
  async init(){this.key=await this.crypto.subtle.importKey('raw',bytes(this.secret),'AES-GCM',false,['decrypt']);this.secret='';await this.catalog();return this;}
  async api(path){if(!/^\/gists(?:\/[a-f0-9]+)?(?:\?per_page=100&page=\d+)?$/.test(path))throw Error('记录路径无效');const r=await this.fetch('https://api.github.com'+path,{method:'GET',redirect:'error',cache:'no-store',headers:{Authorization:'Bearer '+this.token,Accept:'application/vnd.github+json'}});if(!r.ok)throw Error(r.status===401?'学习记录钥匙已失效':r.status===403||r.status===429?'学习记录请求受限，请稍后刷新':'读取学习记录失败（'+r.status+'）');return r.json();}
  async decrypt(text){const raw=bytes(text);if(raw.length>15*1024*1024)throw Error('记录文件过大');return JSON.parse(new TextDecoder().decode(await this.crypto.subtle.decrypt({name:'AES-GCM',iv:raw.slice(0,12)},this.key,raw.slice(12))));}
  async file(g,name){const f=g.files?.[name];if(!f)throw Error('记录文件缺失');if(!f.truncated)return f.content;const url=new URL(f.raw_url);if(url.protocol!=='https:'||url.hostname!=='gist.githubusercontent.com')throw Error('记录下载地址无效');const r=await this.fetch(url.href,{redirect:'error',cache:'no-store'});if(!r.ok)throw Error('下载完整记录失败');return r.text();}
  async catalog(){let all=[];for(let p=1;p<=10;p++){const page=await this.api('/gists?per_page=100&page='+p);all.push(...page);if(page.length<100)break;}
   this.list=all.map(g=>{const p=(g.description||'').split('|');return p[0]==='xsb-mon'&&p[1]==='v1'&&['live','log','img'].includes(p[2])&&/^\d{4}-\d{2}-\d{2}$/.test(p[5]||'')?{id:g.id,kind:p[2],kid:p[3],dev:p[4],date:p[5],updated:g.updated_at}:null;}).filter(Boolean);
   const latest={};for(const x of this.list.filter(x=>x.kind==='live'))if(!latest[x.kid]||x.date>latest[x.kid].date||x.date===latest[x.kid].date&&x.updated>latest[x.kid].updated)latest[x.kid]=x;
   this.kids={};for(const kid of new Set(this.list.map(x=>x.kid))){this.kids[kid]={name:'孩子 '+kid};try{if(latest[kid]){const g=await this.api('/gists/'+latest[kid].id),live=await this.decrypt(await this.file(g,'live.txt'));this.kids[kid].name=live.name||this.kids[kid].name;}}catch(e){this.kids[kid].warning=e.message;}}
   return this.kids;
  }
  dates(kid){return [...new Set(this.list.filter(x=>x.kid===kid).map(x=>x.date))].sort().reverse();}
  async load(kid,date){const files=this.list.filter(x=>x.kid===kid&&x.date===date),live={},logs=[],errors=[];
   await Promise.all(files.filter(x=>x.kind==='live'||x.kind==='log').map(async x=>{try{const g=await this.api('/gists/'+x.id);if(x.kind==='live')live[x.dev]=await this.decrypt(await this.file(g,'live.txt'));else for(const n of Object.keys(g.files||{}).filter(n=>/^c\d+\.txt$/.test(n)).sort()){const chunk=await this.decrypt(await this.file(g,n));if(!Array.isArray(chunk))throw Error('记录分段格式错误');logs.push(...chunk.map(e=>({...e,dev:x.dev})));}}catch(e){errors.push(e.message);}}));
   const unique=new Map();for(const e of [...logs,...Object.entries(live).flatMap(([dev,l])=>(l.recent||[]).map(e=>({...e,dev})))])unique.set(JSON.stringify([e.dev,e.t,e.k]),e);
   const act={},stats={ok:0,bad:0,wrong:[]};for(const l of Object.values(live)){for(const [k,v] of Object.entries(l.act||{}))act[k]=(act[k]||0)+Number(v||0);stats.ok+=Number(l.st?.ok||0);stats.bad+=Number(l.st?.bad||0);stats.wrong.push(...(l.st?.wrong||[]));}stats.wrong=[...new Set(stats.wrong)];
   return {kid,date,live,act,stats,events:[...unique.values()].sort((a,b)=>b.t-a.t),errors};
  }
  async image(kid,date,dev,name){const cache=JSON.stringify([kid,date,dev,name]);if(this.images.has(cache))return this.images.get(cache);if(!/^i\d+\.txt$/.test(name))throw Error('手写图片编号无效');const x=this.list.find(x=>x.kind==='img'&&x.kid===kid&&x.date===date&&x.dev===dev);if(!x)throw Error('没有找到这张手写图片');const g=await this.api('/gists/'+x.id),im=await this.decrypt(await this.file(g,name));if(typeof im!=='string'||!/^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/=\r\n]+$/.test(im))throw Error('手写图片格式无效');this.images.set(cache,im);return im;}
  close(){this.token='';this.secret='';this.key=null;this.images.clear();this.list=[];this.kids={};}
 }
 function eventText(e){switch(e.k){case 'open':return '打开 '+(e.w||'小书包');case 'leave':return '离开小书包（切换应用或锁屏）';case 'back':return '回到小书包';case 'go':return '进入 '+(e.w||'');case 'word':return '拼读 '+(e.it||'');case 'ans':return (e.ok===true?'答对':e.ok===false?'答错':'回答')+' · '+(e.it||'')+(e.a!=null&&e.a!==''?' · 孩子回答：'+e.a:'')+(e.w?' · '+e.w:'');case 'card':return (e.ok?(e.sent?'会说了':'认识'):(e.sent?'还不会':'再练练'))+' · '+(e.it||'');case 'spell':return (e.ok===true?'写对':e.ok===false?'写错':'自查答案')+' · 拼写 '+(e.it||'')+(e.a?' · 识别：'+e.a:'')+(e.tip?' · '+e.tip:'');case 'rec':return '跟读 '+(e.it||'')+' · '+(e.sc==null?'未评分':e.sc+' 分');case 'done':return '完成 '+(e.w||'')+' · '+e.sc+'/'+e.n;case 'his':return '问历史小博士：'+(e.q||'');case 'bud':return '和淘淘聊天：'+(e.q||'');case 'bal':return '戳气球得了 '+e.sc+' 分';default:return e.k||'页面操作';}}
 const exported={Monitor,unlock,unlockPage,day,eventText};if(typeof module!=='undefined')module.exports=exported;else root.Learning=exported;
})(globalThis);
