import {readFile,writeFile,appendFile,mkdir} from 'node:fs/promises';
import {dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {isIP} from 'node:net';
import {decide} from './decide.mjs';
import {checkAccess} from '../../ztna/check.mjs';
const denyFile=new URL('../temporary-deny.json',import.meta.url);
const logFile=new URL('../alerts.log',import.meta.url);
const safeId=x=>/^[a-zA-Z0-9_.:-]{1,96}$/.test(String(x??''))?String(x):null;
const safeAccount=x=>typeof x==='string' && /^[a-zA-Z0-9_.@-]{1,80}$/.test(x.trim())?x.trim():null;
const safeIp=x=>typeof x==='string'&&isIP(x.trim())?x.trim():null;
async function readRules() {
  try {
    const rules=JSON.parse(await readFile(denyFile,'utf8'));
    if(!Array.isArray(rules))throw new Error('Expected array of temporary rules');
    return rules;
  }catch(error){if(error.code==='ENOENT')return [];throw error;}
}
export async function respond(alert,decision,{now=new Date(),persist=true}={}) {
  if(!decision || !['block','alert','record'].includes(decision.action) ||
    !Number.isFinite(decision.confidence) || decision.confidence<0 || decision.confidence>1)
    throw new TypeError('Invalid XDR verdict');
  if(!(now instanceof Date) || Number.isNaN(now.getTime()))
    throw new TypeError('Invalid evaluation time');
  const event=alert?.data??{};
  const id=safeId(alert?.id??alert?.alertId);
  const account=safeAccount(event.srcuser??event.dstuser??event.username??alert?.account);
  const source=safeIp(event.srcip??event.src_ip??event.source_ip??event.client_ip??alert?.srcip);
  const checked=decide(alert);
  const active=(persist?await readRules():[]).filter(rule=>
    rule?.action==='deny' && Number.isFinite(Date.parse(rule.expiresAt)) &&
    Date.parse(rule.expiresAt)>now.getTime());
  // A forged BLOCK decision for a normal account must never install a rule.
  if(decision.action==='block' && decision.confidence>=0.85 &&
     checked.action==='block' && id && account && source) {
    const item={
      id:'xdr05-'+id,action:'deny',scope:'account-source',
      account,source,sessionKey:account+'@'+source,
      alertId:id,reason:checked.reason,createdAt:now.toISOString(),
      expiresAt:new Date(now.getTime()+15*60*1000).toISOString()
    };
    if(!active.some(rule=>rule.id===item.id))active.push(item);
  }
  const notification={
    alertId:id??'unknown',action:checked.action,confidence:checked.confidence,
    reason:checked.reason,at:now.toISOString()
  };
  if(persist){
    await mkdir(dirname(fileURLToPath(denyFile)),{recursive:true});
    await writeFile(denyFile,JSON.stringify(active,null,2)+'\n');
    if(checked.action!=='record')await appendFile(logFile,JSON.stringify(notification)+'\n');
  }
  const session=account&&source?{account,source}:null;
  return {notification:checked.action==='record'?null:notification,rules:active,
    access:session?checkAccess(session,active,now.getTime()):
      {action:'allow',reason:'유효한 계정·출처 없음; 격리 규칙은 생성하지 않음'}};
}
