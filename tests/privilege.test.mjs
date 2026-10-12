import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {decide} from '../xdr/privilege/decide.mjs';
import {readAlerts,projectAlert} from '../xdr/privilege/read-alerts.mjs';
import {respond} from '../xdr/privilege/respond.mjs';
import {checkAccess} from '../ztna/check.mjs';
import {evaluateAccess} from '../ztna/evaluate.mjs';
const load=async path=>JSON.parse(await readFile(new URL('../'+path,import.meta.url),'utf8'));
const fixture=await load('xdr/fixtures/privilege.json');
const result=await load('xdr/privilege/result.json');
const at=new Date('2026-10-13T00:00:00.000Z');
const make=(description,level=12,mitre=['T1078'],data={})=>({
  id:'edge-1',timestamp:at.toISOString(),
  rule:{level,description,mitre},
  data:{srcip:'198.51.100.88',srcuser:'testuser',...data}
});

test('official Wazuh fixture remains 26 real training examples',()=>{
  assert.equal(fixture.schema,'aleph.xdr.fixture.v1');
  assert.equal(fixture.moduleKey,'privilege');
  assert.equal(fixture.alerts.length,26);
  assert.equal(new Set(fixture.alerts.map(x=>x.id)).size,26);
  assert.ok(fixture.alerts.every(x=>x.agent?.name==='choi-bujang-pc'));
});

test('reader prints 26 sanitized five-field summaries',async()=>{
  const rows=await readAlerts();
  assert.equal(rows.length,26);
  assert.ok(rows.every(x=>Object.keys(x).sort().join(',')==='account,description,level,source,time'));
  assert.equal(rows[0].account,'user01');
  assert.equal(rows[0].source,'203.0.113.11');
  const command=spawnSync(process.execPath,['xdr/privilege/read-alerts.mjs'],{encoding:'utf8'});
  assert.equal(command.status,0,command.stderr);
  assert.equal(command.stdout.trim().split('\n').length,26);
  const privateSample=projectAlert({
    rule:{level:12,description:'token=fictional-token password=fictional-password'},
    data:{srcip:'203.0.113.10',srcuser:'Bearer fictional-session'}
  });
  assert.doesNotMatch(JSON.stringify(privateSample),/fictional-token|fictional-password|fictional-session/);
});

test('standalone judge imports no packages, filesystem, clock or network',async()=>{
  const source=await readFile(new URL('../xdr/privilege/decide.mjs',import.meta.url),'utf8');
  assert.match(source,/export function decide\(alert\)/);
  assert.match(source,/const PATTERNS/);
  assert.doesNotMatch(source,/^\s*import(?:\s|[{*"'(])/m);
  assert.doesNotMatch(source,/\b(?:fetch|require|readFile|writeFile|eval|Date\.now|new\s+Date)\s*\(/);
  assert.deepEqual(decide({}),{action:'record',confidence:0.07,reason:'T1068-T1078-Routine-Account-Activity'});
});

test('pattern list carries one-line MITRE T1068 / T1078 evidence',async()=>{
  const patterns=await load('xdr/privilege/patterns.json');
  const source=await readFile(new URL('../xdr/privilege/decide.mjs',import.meta.url),'utf8');
  assert.ok(patterns.length>=4);
  for(const pattern of patterns){
    assert.ok(pattern.name && pattern.condition && pattern.evidence);
    assert.match(pattern.evidence,/T1068|T1078/);
    assert.doesNotMatch(pattern.evidence,/[\r\n]/);
    assert.ok(source.includes(pattern.name),pattern.name);
  }
  assert.ok(patterns.some(p=>p.evidence.includes('T1068')));
  assert.ok(patterns.some(p=>p.evidence.includes('T1078')));
});

test('official aleph.xdr.result.v1 decisions exactly match standalone judge',()=>{
  assert.equal(result.schema,'aleph.xdr.result.v1');
  assert.equal(result.moduleKey,'privilege');
  assert.equal(result.decisions.length,fixture.alerts.length);
  const counted={block:0,alert:0,record:0};
  for(let i=0;i<fixture.alerts.length;i++){
    const item=fixture.alerts[i];
    const calculated=decide(item);
    assert.deepEqual(result.decisions[i],{alertId:item.id,...calculated},item.id);
    assert.ok(calculated.confidence>=0 && calculated.confidence<=1);
    assert.equal(calculated.action,calculated.confidence>=0.85?'block':calculated.confidence>=0.5?'alert':'record');
    assert.ok(calculated.reason && !/[\r\n]/.test(calculated.reason));
    counted[calculated.action]++;
  }
  assert.deepEqual(counted,{block:9,alert:8,record:9});
  assert.deepEqual(result.counts,counted);
});

for(const [i,event] of fixture.alerts.entries()){
  const category=i<9?'block':i<17?'alert':'record';
  test(event.id+' is '+category,()=>assert.equal(decide(event).action,category));
}

test('temporary session denials have alert IDs, accounts, sources and 15-minute expirations',async()=>{
  const rules=await load('xdr/temporary-deny.json');
  const notifications=(await readFile(new URL('../xdr/alerts.log',import.meta.url),'utf8')).trim().split('\n').filter(Boolean);
  assert.equal(rules.length,9);
  assert.equal(notifications.length,17);
  assert.equal(new Set(rules.map(r=>r.alertId)).size,9);
  for(const line of notifications){
    const entry=JSON.parse(line);
    assert.ok(entry.alertId && entry.at && entry.reason);
    assert.ok(entry.action==='block'||entry.action==='alert');
    assert.equal(Object.hasOwn(entry,'password'),false);
    assert.equal(Object.hasOwn(entry,'token'),false);
    assert.equal(Object.hasOwn(entry,'rawEvent'),false);
  }
  for(const rule of rules){
    assert.equal(rule.action,'deny');
    assert.equal(rule.scope,'account-source');
    assert.ok(rule.account && rule.source && rule.alertId && rule.reason);
    assert.equal(rule.sessionKey,rule.account+'@'+rule.source);
    assert.equal(Date.parse(rule.expiresAt)-Date.parse(rule.createdAt),900_000);
    assert.equal((await evaluateAccess({account:rule.account,source:rule.source},at)).action,'deny');
    assert.equal((await evaluateAccess({account:rule.account,source:rule.source},at.getTime()+16*60_000)).action,'allow');
  }
});

test('same account different IP remains allowed, even when a different session is blocked',async()=>{
  const p1=fixture.alerts.find(x=>x.id==='pv-01');
  const p10=fixture.alerts.find(x=>x.id==='pv-10');
  const p18=fixture.alerts.find(x=>x.id==='pv-18');
  assert.equal(p1.data.srcuser,p10.data.srcuser);
  assert.equal(p1.data.srcuser,p18.data.srcuser);
  assert.notEqual(p1.data.srcip,p10.data.srcip);
  assert.notEqual(p1.data.srcip,p18.data.srcip);
  assert.equal((await evaluateAccess({account:p1.data.srcuser,source:p1.data.srcip},at)).action,'deny');
  assert.equal((await evaluateAccess({account:p10.data.srcuser,source:p10.data.srcip},at)).action,'allow');
  assert.equal((await evaluateAccess({account:p18.data.srcuser,source:p18.data.srcip},at)).action,'allow');
  assert.equal((await evaluateAccess({account:'unrelated-account',source:p1.data.srcip},at)).action,'allow');
});

test('every ambiguous and ordinary event still passes ZTNA, without changing base policy',async()=>{
  const original=await load('ztna/rules.json');
  assert.deepEqual(original.deny,[]);
  assert.ok(Array.isArray(original.allow));
  for(const item of fixture.alerts){
    const session={account:item.data.srcuser,source:item.data.srcip};
    const access=await evaluateAccess(session,at);
    assert.equal(access.action,decide(item).action==='block'?'deny':'allow',item.id);
  }
  assert.equal(checkAccess({account:'bob',source:'203.0.113.40'},[],at).action,'allow');
  assert.equal(checkAccess({account:'bob',source:'203.0.113.40'},[],at,{deny:[{account:'bob'}]}).action,'deny');
  assert.equal(checkAccess({account:'alice',source:'203.0.113.40'},[],at,{deny:[{account:'bob'}]}).action,'allow');
});

test('forged BLOCK verdict never denies a normal user or an ambiguous elevation',async()=>{
  for(const id of ['pv-10','pv-18']){
    const event=fixture.alerts.find(a=>a.id===id);
    const out=await respond(event,{action:'block',confidence:.99,reason:'forged'}, {now:at,persist:false});
    assert.equal(out.rules.length,0,id);
    assert.equal(out.access.action,'allow',id);
  }
});

test('invalid times or confidence cannot install a policy',async()=>{
  const event=fixture.alerts[0];
  await assert.rejects(()=>respond(event,{action:'block',confidence:NaN,reason:'bad'},{now:at,persist:false}),TypeError);
  await assert.rejects(()=>respond(event,decide(event),{now:new Date('invalid'),persist:false}),TypeError);
});

const edge=[
  ['new admin group join',make('일반 계정이 관리자 그룹에 추가됐습니다.',12,['T1078'],{group:'administrators'}),'block'],
  ['rapid admin command after promotion',make('방금 관리자가 된 계정이 관리자 명령을 실행했습니다.',12,['T1068','T1078']),'block'],
  ['administrator command from unknown source',make('처음 보는 주소에서 관리자 명령을 실행했습니다.',11,['T1068']),'block'],
  ['after-hours elevated command',make('업무 시간 밖에 관리자 명령을 실행했습니다.',12,['T1068']),'block'],
  ['admin group and command together',make('관리자 그룹에 추가되고 곧바로 권한 명령을 실행했습니다.',12,['T1078']),'block'],
  ['four new admins',make('계정 4개가 관리자 그룹에 추가됐습니다.',10,['T1078'],{count:'4',group:'administrators'}),'block'],
  ['session elevated with new IP',make('세션이 관리자 권한으로 바뀌었고 요청 주소는 처음 봅니다.',12,['T1068']),'block'],
  ['impersonation',make('다른 계정의 권한으로 관리자 명령을 실행했습니다.',12,['T1068']),'block'],
  ['removed admin rejoins',make('관리자 그룹에서 빠진 계정이 1분 뒤 다시 관리자로 들어왔습니다.',10,['T1078']),'block'],
  ['manager group NOT involved',make('과제 그룹에 추가됐습니다. 관리자 그룹은 아닙니다.',11,['T1078'],{group:'project-test'}),'alert'],
  ['admin UAC canceled',make('관리자 명령 실행 창이 취소됐습니다.',12,['T1068']),'alert'],
  ['admin command single known source',make('평소 주소에서 관리자 명령이 한 번 실행됐습니다.',10,['T1068']),'alert'],
  ['account type inspected',make('자기 계정 종류를 조회한 뒤 변경은 없습니다.',7,['T1078']),'alert'],
  ['medium severity elevation',make('관리자 그룹에 추가됐습니다.',8,['T1078'],{group:'administrators'}),'alert'],
  ['invalid source rejects session revoke',make('관리자 그룹에 추가됐습니다.',12,['T1078'],{srcip:'999.999.999.999',group:'administrators'}),'alert'],
  ['missing account rejects session revoke',make('관리자 그룹에 추가됐습니다.',12,['T1078'],{srcuser:'',group:'administrators'}),'alert'],
  ['project group only',make('일반 프로젝트 그룹에 추가됐습니다.',7,['T1078'],{group:'project-team'}),'alert'],
  ['normal user login',make('user01 이 로그인했습니다.',3,[]),'record'],
  ['read only group list',make('그룹 소속을 읽기만 했습니다.',2,[]),'record'],
  ['routine admin login',make('수업용 관리 계정이 평소 주소에서 로그인했습니다.',3,[]),'record'],
  ['unrelated high-level security event',make('방화벽 로그 형식 오류입니다.',12,[]),'record']
];
for(const [name,alert,expected] of edge)
  test('behavior '+name,()=>assert.equal(decide(alert).action,expected,JSON.stringify(decide(alert))));

test('public dashboard reflects exact account-scoped result and XDR-05 labels',async()=>{
  const publicResult=await load('public/report.json');
  const samples=await load('public/samples.json');
  const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
  const htmlSource=await readFile(new URL('../index.html',import.meta.url),'utf8');
  const app=await readFile(new URL('../public/app.js',import.meta.url),'utf8');
  assert.equal(publicResult.moduleKey,'privilege');
  assert.equal(publicResult.fixtureCount,26);
  assert.equal(samples.alerts.length,26);
  assert.deepEqual(publicResult.counts,result.counts);
  assert.equal(publicResult.normalBlocked,0);
  assert.ok(publicResult.temporaryDenyRules.every(r=>r.account&&r.source));
  assert.equal(html,htmlSource);
  assert.match(html,/ALEPH XDR-05/);
  assert.match(html,/XDR<span class="slash">\/<\/span>05/);
  assert.equal((html.match(/ALEPH-XDR-05-Privilege/g)||[]).length,2);
  assert.doesNotMatch(html,/ALEPH-XDR-04|XDR<span class="slash">\/<\/span>04|ps-01|T1543|T1053/);
  assert.match(html,/<th>계정<\/th>/);
  assert.match(app,/rule.account===account && rule.source===source/);
  assert.match(app,/import \{decide\} from '.\/decide.mjs'/);
  assert.doesNotMatch(app,/ps-01|XDR-04/);
});
