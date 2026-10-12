import {decide} from './decide.mjs';

const $=id=>document.getElementById(id);
const view={
  all:$('events-body'),search:$('search'),shown:$('shown'),
  desc:$('d-description'),ip:$('d-ip'),count:$('d-count'),level:$('d-level'),
  id:$('d-id'),badge:$('d-badge'),explain:$('d-explain'),
  confidence:$('d-confidence'),bar:$('d-bar'),
  pattern:$('d-pattern'),access:$('d-access'),replayStatus:$('replay-status'),account:$('d-account'),group:$('d-group')
};
let samples=[], report=null, filter='all', selected='pv-01';
const explain={
  block:'관리자 그룹 편입이나 낯선 권한 사용이 확인되어 해당 계정·접속 출처 세션을 임시 거부합니다.',
  alert:'단일 권한 요청이나 일반 그룹 변경만으로는 탈취를 확정할 수 없어 알림만 남깁니다.',
  record:'일반 로그인·로그아웃·조회처럼 권한 상승 악용 근거가 없는 정상 계정 이벤트입니다.'
};
const actionNames={block:'BLOCK',alert:'ALERT',record:'RECORD'};
function safeText(element,value){element.textContent=String(value??'–');}
function policyStatus(account,source){
  const time=Date.parse(report.generatedAt);
  return report.temporaryDenyRules.some(rule=>
    rule.account===account && rule.source===source && Date.parse(rule.expiresAt)>time) ? 'DENY' : 'ALLOW';
}
function choose(id,isReplay=false){
  const original=samples.find(a=>a.id===id);
  if(!original)return;
  selected=id;
  const decision=decide(original);
  safeText(view.id,id);
  safeText(view.desc,original.rule.description);
  safeText(view.ip,original.data.srcip);
  safeText(view.account,original.data.srcuser);
  safeText(view.group,original.data.group||'그룹 변경 없음');
  safeText(view.level,original.rule.level);
  safeText(view.badge,actionNames[decision.action]);
  view.badge.className='decision-badge is-'+decision.action;
  safeText(view.explain,explain[decision.action]);
  safeText(view.confidence,Math.round(decision.confidence*100)+'%');
  view.bar.style.width=(decision.confidence*100)+'%';
  safeText(view.pattern,decision.reason);
  const access=policyStatus(original.data.srcuser,original.data.srcip);
  safeText(view.access,access);
  view.access.className=access==='DENY'?'denied':'allowed';
  for(const button of document.querySelectorAll('[data-case]')){
    const active=button.dataset.case===id;
    button.classList.toggle('active',active);
    button.setAttribute('aria-pressed',String(active));
  }
  if(isReplay) safeText(view.replayStatus,'✓ 동일한 독립 판정기를 재실행했습니다. 실제 로그인 세션은 종료되지 않았습니다.');
  else safeText(view.replayStatus,'');
  drawTable();
}
function textCell(row,value,cls){
  const cell=document.createElement('td');
  const item=cls?document.createElement('span'):null;
  if(item){item.className=cls;item.textContent=String(value);cell.append(item);}
  else cell.textContent=String(value);
  row.append(cell);
}
function drawTable(){
  if(!report)return;
  const query=view.search.value.trim().toLowerCase();
  const filtered=report.results.filter(a=>
    (filter==='all'||a.action===filter) &&
    (!query||a.alertId.toLowerCase().includes(query)||
      a.source.toLowerCase().includes(query)||a.account.toLowerCase().includes(query)||a.description.toLowerCase().includes(query)));
  view.all.replaceChildren();
  if(!filtered.length){
    const row=document.createElement('tr');
    const cell=document.createElement('td');cell.colSpan=7;cell.className='empty-state';cell.textContent='해당 조건에 맞는 경보가 없습니다.';
    row.append(cell);view.all.append(row);
  }
  for(const item of filtered){
    const row=document.createElement('tr');
    row.tabIndex=0;row.title='이 계정 경보 분석 보기';row.className=selected===item.alertId?'selected-row':'';
    textCell(row,item.alertId,'row-id');
    textCell(row,item.account);
    textCell(row,item.description);
    textCell(row,item.source);
    textCell(row,item.level);
    textCell(row,Math.round(item.confidence*100)+'%');
    textCell(row,actionNames[item.action],'action-chip '+item.action);
    const activate=()=>{
      choose(item.alertId);
      document.getElementById('lab').scrollIntoView({behavior:'smooth',block:'start'});
    };
    row.addEventListener('click',activate);
    row.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();activate();}});
    view.all.append(row);
  }
  safeText(view.shown,filtered.length+' / '+report.fixtureCount+'건 표시');
}
for(const b of document.querySelectorAll('[data-case]'))
  b.addEventListener('click',()=>choose(b.dataset.case));
for(const b of document.querySelectorAll('[data-filter]'))
  b.addEventListener('click',()=>{
    filter=b.dataset.filter;
    for(const item of document.querySelectorAll('[data-filter]')){
      const active=item===b;
      item.classList.toggle('selected',active);
      item.setAttribute('aria-pressed',String(active));
    }
    drawTable();
  });
view.search.addEventListener('input',drawTable);
$('replay').addEventListener('click',()=>choose(selected,true));

try{
  const endpoints=['/report.json','/samples.json'];
  const [summary,fixture]=await Promise.all(endpoints.map(async path=>{
    const response=await fetch(path,{cache:'no-store'});
    if(!response.ok)throw new Error('Missing '+path);
    return response.json();
  }));
  if(summary.schema!=='aleph.xdr.result.v1'||!Array.isArray(summary.results)||
      !Array.isArray(fixture.alerts)||summary.results.length!==fixture.alerts.length)
    throw new Error('Invalid training data');
  report=summary;samples=fixture.alerts;
  for(const [id,value] of Object.entries({
    'm-total':summary.fixtureCount,'m-block':summary.counts.block,
    'm-alert':summary.counts.alert,'m-record':summary.counts.record,
    'm-false':summary.normalBlocked
  }))safeText($(id),value);
  choose(samples.some(a=>a.id===selected)?selected:samples[0].id);
}catch(error){
  view.all.replaceChildren();
  const row=document.createElement('tr'),cell=document.createElement('td');
  cell.colSpan=7;cell.className='empty-state';
  cell.textContent='분석 결과를 불러오지 못했습니다. 저장소의 테스트·빌드 결과를 확인해 주세요.';
  row.append(cell);view.all.append(row);
  safeText(view.replayStatus,'정적 결과 파일을 불러오지 못했습니다.');
  console.error('Dashboard initialization failed:',error.message);
}
