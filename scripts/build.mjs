import {readFile,writeFile,copyFile,mkdir} from 'node:fs/promises';
import {checkAccess} from '../ztna/check.mjs';
const root=new URL('../',import.meta.url),file=path=>new URL(path,root);
const fixture=JSON.parse(await readFile(file('xdr/fixtures/privilege.json'),'utf8'));
const result=JSON.parse(await readFile(file('xdr/privilege/result.json'),'utf8'));
const deny=JSON.parse(await readFile(file('xdr/temporary-deny.json'),'utf8'));
const baseline=JSON.parse(await readFile(file('ztna/rules.json'),'utf8'));
const logLines=(await readFile(file('xdr/alerts.log'),'utf8')).trim().split('\n').filter(Boolean);
if(fixture.schema!=='aleph.xdr.fixture.v1'||fixture.moduleKey!=='privilege'||
   !Array.isArray(fixture.alerts)||fixture.alerts.length!==26)
  throw new Error('Original privilege fixture contract invalid');
if(result.schema!=='aleph.xdr.result.v1'||result.moduleKey!=='privilege'||
   !Array.isArray(result.decisions)||result.decisions.length!==fixture.alerts.length)
  throw new Error('Official result contract invalid');
if(!Array.isArray(deny) || deny.length!==result.counts.block ||
   !Array.isArray(baseline.deny)||!Array.isArray(baseline.allow)||
   logLines.length!==result.counts.block+result.counts.alert)
  throw new Error('Dynamic deny rules, notifications, or base ZTNA policy invalid');
const samples=fixture.alerts.map(e=>({
  id:e.id,timestamp:e.timestamp,
  rule:{level:e.rule.level,mitre:e.rule.mitre,description:e.rule.description},
  data:{srcuser:e.data.srcuser,srcip:e.data.srcip,group:e.data.group??'',count:e.data.count??null}
}));
const rows=result.decisions.map((a,i)=>{
  const e=samples[i];
  if(e.id!==a.alertId)throw new Error('Result and Wazuh alert IDs disagree');
  return {alertId:a.alertId,action:a.action,confidence:a.confidence,reason:a.reason,
    description:e.rule.description,account:e.data.srcuser,source:e.data.srcip,
    group:e.data.group,level:e.rule.level,attempts:e.data.count,
    normal:!e.rule.mitre.some(t=>t==='T1068'||t==='T1078')&&e.rule.level<=3};
});
const now=Date.parse('2026-10-13T00:00:00.000Z');
let normalBlocked=0;
for(const row of rows){
  const access=checkAccess({account:row.account,source:row.source},deny,now,baseline);
  if(row.normal && (row.action==='block'||access.action==='deny'))normalBlocked++;
  if(access.action!==(row.action==='block'?'deny':'allow'))
    throw new Error('ZTNA account scope mismatch: '+row.alertId);
}
if(normalBlocked)throw new Error('Normal account session blocked');
const report={schema:'aleph.xdr.result.v1',moduleKey:'privilege',generatedAt:'2026-10-13T00:00:00.000Z',
  fixtureCount:samples.length,counts:result.counts,normalBlocked,
  temporaryDenyRules:deny.map(x=>({id:x.id,account:x.account,source:x.source,alertId:x.alertId,expiresAt:x.expiresAt})),
  results:rows};
await mkdir(file('public/'),{recursive:true});
await writeFile(file('public/report.json'),JSON.stringify(report,null,2)+'\n');
await writeFile(file('public/samples.json'),JSON.stringify({alerts:samples},null,2)+'\n');
for(const [from,to] of [
  ['index.html','public/index.html'],['app.js','public/app.js'],
  ['styles.css','public/styles.css'],['xdr/privilege/decide.mjs','public/decide.mjs']
])await copyFile(file(from),file(to));
console.log(JSON.stringify({siteReady:true,fixtureCount:samples.length,
  counts:result.counts,normalBlocked,accountScopedRules:deny.length}));
