import {readFile,writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {runXdr} from '../../scripts/xdr-run.mjs';
import {respond} from './respond.mjs';
import {evaluateAccess} from '../../ztna/evaluate.mjs';
if(process.argv[2]!=='privilege') {
  console.error('Usage: npm run xdr:run -- privilege');
  process.exit(1);
}
const clock=new Date('2026-10-13T00:00:00.000Z');
const fixture=JSON.parse(await readFile(new URL('../fixtures/privilege.json',import.meta.url),'utf8'));
const root=fileURLToPath(new URL('../../',import.meta.url));
const report=await runXdr({root,moduleKey:'privilege'});
const denyFile=new URL('../temporary-deny.json',import.meta.url);
const logFile=new URL('../alerts.log',import.meta.url);
await writeFile(denyFile,'[]\n');
await writeFile(logFile,'');
for(let i=0;i<fixture.alerts.length;i++){
  const event=fixture.alerts[i],verdict=report.decisions[i];
  if(event.id!==verdict.alertId)throw new Error('Official fixture ID mismatch');
  await respond(event,verdict,{now:clock,persist:true});
}
const denies=JSON.parse(await readFile(denyFile,'utf8'));
const logLines=(await readFile(logFile,'utf8')).trim().split('\n').filter(Boolean);
if(denies.length!==report.counts.block ||
   logLines.length!==report.counts.block+report.counts.alert)
  throw new Error('Decision, notification, session deny count mismatch');
let normalBlocked=0;
for(let i=0;i<fixture.alerts.length;i++){
  const alert=fixture.alerts[i],verdict=report.decisions[i];
  const session={account:alert.data.srcuser,source:alert.data.srcip};
  const actual=await evaluateAccess(session,clock);
  const normal=!(alert.rule.mitre??[]).some(t=>t==='T1068'||t==='T1078') &&
    Number(alert.rule.level)<=3;
  if(normal && (verdict.action==='block'||actual.action==='deny'))normalBlocked++;
  if(verdict.action==='block' && actual.action!=='deny')
    throw new Error('Elevated account was not rejected: '+alert.id);
  if(verdict.action!=='block' && actual.action!=='allow')
    throw new Error('Normal or ambiguous session blocked: '+alert.id);
  if(verdict.action==='block' &&
    (await evaluateAccess(session,clock.getTime()+16*60_000)).action!=='allow')
    throw new Error('Expired session denial remains active: '+alert.id);
}
if(normalBlocked)throw new Error('Normal account session was blocked');
console.log(JSON.stringify({schema:report.schema,counts:report.counts,total:fixture.alerts.length,
  normalBlocked,alertsLogged:logLines.length,temporaryDenyRules:denies.length}));
