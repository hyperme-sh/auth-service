if(process.env.GITHUB_ACTIONS!=='true')throw Error('CI only');
import {execFileSync} from 'node:child_process';
import {mkdtempSync,writeFileSync,copyFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('../../',import.meta.url));
const sdk=process.env.SDK_SOURCE+'/packages/sea-device-link';
const temp=mkdtempSync(join(tmpdir(),'auth-relay-contract-'));
try{
 const packs=[sdk,root+'/browser/sea-relay'].map(cwd=>{
  const p=JSON.parse(execFileSync('npm',['pack','--ignore-scripts','--json','--pack-destination',temp],{cwd,encoding:'utf8'}));return join(temp,p[0].filename);
 });
 writeFileSync(join(temp,'package.json'),JSON.stringify({private:true,type:'module'}));
 execFileSync('npm',['install','--ignore-scripts','--no-audit','--no-fund',...packs,'esbuild@0.25.11'],{cwd:temp,stdio:'inherit'});
 writeFileSync(join(temp,'consumer.ts'),`import {createRelay,newCapability} from 'auth-sea-relay';\nimport type {Transport} from 'sea-device-link';\nexport {newCapability};\nexport const transport:Transport=createRelay({scope:{sourceOrigin:'https://a.example',destinationOrigin:'https://b.example',tenant:'tenant',application:'app',audience:'test'},session:newCapability(),role:'receiver',capability:newCapability(),request:async()=>({status:200,body:{v:1,result:null}})});`);
 execFileSync(process.execPath,[sdk+'/node_modules/typescript/bin/tsc','--strict','--noEmit','--target','ES2022','--module','NodeNext','--moduleResolution','NodeNext','consumer.ts'],{cwd:temp,stdio:'inherit'});
 const {build}=await import(join(temp,'node_modules/esbuild/lib/main.js'));
 await build({entryPoints:[join(temp,'consumer.ts')],bundle:true,platform:'browser',format:'esm',write:false});
 copyFileSync(root+'/browser/sea-relay/contract.mjs',join(temp,'contract.mjs'));
 execFileSync(process.execPath,['contract.mjs'],{cwd:temp,stdio:'inherit',env:{...process.env,AUTH_SOURCE:root}});
}finally{rmSync(temp,{recursive:true,force:true});}
