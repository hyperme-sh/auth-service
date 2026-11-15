import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {Sender,Receiver,reconcile} from 'sea-device-link';
import {createRelay,newCapability} from 'auth-sea-relay';
const child=spawn(process.env.CONTRACT_PYTHON,[process.env.AUTH_SOURCE+'/tests/pairing_contract_driver.py'],{stdio:['pipe','pipe','inherit']});
const lines=createInterface({input:child.stdout})[Symbol.asyncIterator]();
const request=async call=>{
 child.stdin.write(JSON.stringify(call)+'\n');const next=await lines.next();if(next.done)throw Error('driver stopped');return JSON.parse(next.value);
};
try{
 const scope={sourceOrigin:'https://source.example',destinationOrigin:'https://destination.example',application:'unit',tenant:'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',audience:'test'};
 const now=()=>1700000000000;
 // Synthetic identity adapter: relay grants no identity authority.
 const point=newCapability()+'.'+newCapability();
 const identity={principal:point,pub:point,epub:point,rotationSeq:0};
 const bytes=new TextEncoder().encode('synthetic opaque keyring contract bytes');
 const authority={async validateKeyring(b){assert.deepEqual(b,bytes);},async current(b){return {revision:'synthetic-current',validUntil:b.expiresAt};}};
 const receiver=await Receiver.create(scope,{now});
 const join=newCapability();
 const rx=createRelay({scope,session:receiver.request.session,role:'receiver',capability:newCapability(),request});
 await rx.create(receiver.request,join);await rx.create(receiver.request,join);
 const sender=await Sender.create({request:receiver.request,expectedScope:scope,identity,keyring:bytes,authority},{now});
 const tx=createRelay({scope,session:receiver.request.session,role:'sender',capability:newCapability(),request});
 await tx.join(sender.offer,join);await tx.join(sender.offer,join);
 await receiver.bind(await rx.offer());sender.confirm(receiver.comparison);receiver.confirm(sender.comparison);
 let stored;
 const storage={async lookup(){return stored?.completion??null;},async commit(input){await input.beforeCommit();stored={completion:structuredClone(input.completion),bytes:input.keyring.slice()};}};
 await sender.send(tx);
 await assert.rejects(receiver.receive({...rx,async complete(s,c){await rx.complete(s,c);throw Error('lost response');}},authority,storage));
 assert.deepEqual(stored.bytes,bytes);assert.equal(await reconcile(receiver.binding,storage,rx),true);await sender.finish(tx);
 await assert.rejects(rx.cancel());
 await assert.rejects(tx.send(sender.binding.session,{transcript:sender.binding.transcript,iv:newCapability(),ciphertext:newCapability()}));
 await assert.rejects(tx.join({...sender.offer,priv:'do-not-send'},join));
 rx.close();tx.close();console.log('Packed relay + SDK + ASGI handler unit contract passed');
}finally{child.stdin.end();child.kill();}
