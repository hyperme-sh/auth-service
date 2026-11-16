const fail=()=>{throw Error('pairing-refused');};
const keys=(o,k)=>{if(!o||typeof o!=='object'||Array.isArray(o)||Object.keys(o).sort().join()!==k.split(' ').sort().join())fail();};
const b64=raw=>btoa(String.fromCharCode(...raw)).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'');
function secret(value){
 if(typeof value!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(value))fail();
 const raw=Uint8Array.from(atob(value.replaceAll('-','+').replaceAll('_','/')+'='),c=>c.charCodeAt(0));
 if(raw.length!==32||b64(raw)!==value)fail();return raw;
}
export async function capabilityHash(value){const raw=secret(value);try{return b64(new Uint8Array(await crypto.subtle.digest('SHA-256',raw)));}finally{raw.fill(0);}}
export const newCapability=()=>b64(crypto.getRandomValues(new Uint8Array(32)));
function publicRequest(r){keys(r,'v session receiverKey expiresAt scope');keys(r.scope,'sourceOrigin destinationOrigin application tenant audience');if(r.v!==1||!Number.isSafeInteger(r.expiresAt)||typeof r.session!=='string'||typeof r.receiverKey!=='string'||!Object.values(r.scope).every(v=>typeof v==='string'))fail();}
function publicPayload(action,p){
 if(action==='create'||action==='admit'){keys(p,action==='admit'?'request joinHash receiverHash':'request joinHash');publicRequest(p.request);}
 else if(action==='join'){keys(p,'request senderKey identity payloadHash');publicRequest(p.request);keys(p.identity,'principal pub epub rotationSeq');}
 else if(action==='send')keys(p,'transcript iv ciphertext');
 else if(action==='complete')keys(p,'transcript mac');
 else keys(p,'');
 for(const [key,value] of Object.entries(p)){if(!['request','identity'].includes(key)&&typeof value!=='string')fail();}
 if(p.identity&&!Object.entries(p.identity).every(([k,v])=>k==='rotationSeq'?Number.isSafeInteger(v):typeof v==='string'))fail();
}
export function createRelay({scope,session,role,capability,request}){
 keys(scope,'sourceOrigin destinationOrigin application tenant audience');secret(session);secret(capability);
 if(!['receiver','sender'].includes(role))fail();scope=structuredClone(scope);let closed=false;
 async function call(action,payload,join){
  try{
   if(closed)fail();publicPayload(action,payload);
   if(JSON.stringify({scope,payload}).length>710000)fail();
   const headers={'X-Pairing-Role':role,'X-Pairing-Capability':capability};
   if(join){secret(join);headers['X-Pairing-Join']=join;}
   const value=await request({session,action,scope:structuredClone(scope),payload:structuredClone(payload),headers});
   if(closed||value.status!==200||value.body?.v!==1)fail();return value.body.result;
  }catch{fail();}
 }
 const sameSession=s=>{if(s!==session)fail();};
 return {
  async admit(r,receiverHash,join){if(role!=='sender')fail();secret(receiverHash);await call('admit',{request:r,receiverHash,joinHash:await capabilityHash(join)});},
  async create(r,join){if(role!=='receiver')fail();const raw=secret(join);const joinHash=b64(new Uint8Array(await crypto.subtle.digest('SHA-256',raw)));raw.fill(0);await call('create',{request:r,joinHash});},
  async join(o,join){if(role!=='sender')fail();await call('join',o,join);},
  async offer(){return call('offer',{});},
  async send(s,e){sameSession(s);await call('send',e);},
  async receive(s){sameSession(s);return call('receive',{});},
  async complete(s,c){sameSession(s);await call('complete',c);},
  async completed(s){sameSession(s);return call('completed',{});},
  async cancel(){await call('cancel',{});},
  close(){closed=true;capability='';},
 };
}
