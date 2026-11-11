'use strict';
// Credentials stay in this browser. The encryption key cannot be exported.
globalThis.FamilyCredentials=(()=>{
 const name='study-gate-family-vault',record='connection';
 async function database(){return new Promise((resolve,reject)=>{const r=indexedDB.open(name,1);r.onupgradeneeded=()=>r.result.createObjectStore('vault');r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(Error('浏览器无法保存钥匙，请检查是否使用无痕模式'));});}
 async function access(mode,fn){const db=await database();try{return await new Promise((resolve,reject)=>{const tx=db.transaction('vault',mode),r=fn(tx.objectStore('vault'));let value;r.onsuccess=()=>{value=r.result;};tx.oncomplete=()=>resolve(value);tx.onerror=tx.onabort=()=>reject(Error('本机钥匙保存失败'));});}finally{db.close();}}
 const backend={get:()=>access('readonly',s=>s.get(record)),put:v=>access('readwrite',s=>s.put(v,record)),clear:()=>access('readwrite',s=>s.delete(record))};
 function vault(storage=backend,cryptoApi=globalThis.crypto){return {
  async save(repo,token){const key=await cryptoApi.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']),iv=cryptoApi.getRandomValues(new Uint8Array(12));const encrypted=await cryptoApi.subtle.encrypt({name:'AES-GCM',iv},key,new TextEncoder().encode(token));await storage.put({repo,key,iv,encrypted});},
  async load(){const v=await storage.get();if(!v)return null;const plain=await cryptoApi.subtle.decrypt({name:'AES-GCM',iv:v.iv},v.key,v.encrypted);return {repo:v.repo,token:new TextDecoder().decode(plain)};},
  clear:()=>storage.clear()
 };}
 function parse(text){const match=text.match(/^\s*远程家长控制端[：:]\s*(\S+)/m);if(!match||! /^(github_pat_|ghp_)[A-Za-z0-9_]+$/.test(match[1]))throw Error('文件中未找到“远程家长控制端：”后面的有效钥匙');const section=text.match(/七、GitHub[^\r\n]*仓库\s*([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)/);return {repo:section?section[1]:'chvnfk2pwh-eng/-study-gate-family',token:match[1]};}
 return {vault,parse};
})();
