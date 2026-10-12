// ALEPH XDR-05 | Privilege abuse | MITRE ATT&CK T1068 / T1078
// Standalone pure judge. No import, filesystem, network, clock or external dependency.
// Pattern names mirror xdr/privilege/patterns.json. Keep all logic in this one file.
const PATTERNS = Object.freeze({
  group:'T1078-Unauthorized-Admin-Group-Membership',
  command:'T1068-Privileged-Command-Unusual-Context',
  session:'T1068-Admin-Session-Privilege-Change',
  reentry:'T1078-Rapid-Admin-Reentry',
  combined:'T1068-T1078-Group-Command-Correlation',
  uncertain:'T1068-T1078-Ambiguous-Privilege-Activity',
  normal:'T1068-T1078-Routine-Account-Activity'
});
const object = x => x && typeof x==='object' && !Array.isArray(x) ? x : {};
const str = x => typeof x==='string' ? x : '';
const first = (...items) => items.find(x=>x!==undefined && x!==null && x!=='') ?? null;
function number(value) {
  if(typeof value==='number')return Number.isFinite(value)&&value>=0&&value<=1e6?value:null;
  if(typeof value==='string' && /^\s*\d{1,6}\s*$/.test(value))return Number(value);
  return null;
}
function sourceValid(x) {
  if(typeof x!=='string')return false;
  const s=x.trim();
  if(/^(?:\d{1,3}\.){3}\d{1,3}$/.test(s))
    return s.split('.').every(n=>Number(n)>=0 && Number(n)<=255);
  return /^[0-9a-f:]{2,45}$/i.test(s) && s.includes(':');
}
function examine(alert) {
  const a=object(alert),data=object(a.data),rule=object(a.rule);
  const event=object(data.event),win=object(data.win),extra=object(win.eventdata);
  const desc=[rule.description,a.description,data.description,event.description,
    data.message,event.action].filter(x=>typeof x==='string').join(' ').toLowerCase();
  const account=first(data.srcuser,data.dstuser,data.username,data.user,a.account,extra.targetUserName);
  const source=first(data.srcip,data.src_ip,data.source_ip,data.client_ip,a.srcip,a.source_ip);
  const group=str(first(data.group,data.groupName,extra.targetGroupName,a.group)).toLowerCase();
  const level=number(first(rule.level,a.level,data.level)) ?? 0;
  const count=number(first(data.count,data.frequency,rule.frequency,a.count)) ?? 0;
  const tags=Array.isArray(rule.mitre)?rule.mitre.map(x=>typeof x==='string'?x:str(object(x).id)):[];
  const tagged=tags.includes('T1068')||tags.includes('T1078');
  const negatedAdmin=/관리자\s*그룹(?:은|이)?\s*아닙|관리자\s*그룹.*아닙|not\s+(?:an?\s+)?admin(?:istrator)?\s+group|non.admin\s+group/.test(desc);
  const highGroup=/^(?:administrators|administrators group|domain admins|local administrators|sudo|wheel|enterprise admins)$/i.test(group);
  const adminGroupText=/관리자\s*그룹|administrators?\s+group|domain\s+admins/.test(desc);
  const promoted=/추가됐|추가되|추가했|들어갔|들어가고|들어왔|가입|승격|재가입|다시\s*관리자|group\s+added|added\s+to|promoted|elevated/.test(desc)
    || /^(?:add|added|join|joined|promoted)$/i.test(str(data.action));
  const groupEntry=!negatedAdmin && (adminGroupText || highGroup) && promoted;
  const adminCommand=/관리자\s*명령|관리자\s*권한.{0,16}명령|권한\s*명령|privileged\s+command|elevated\s+command|runas|sudo\b/.test(desc);
  const commandRan=adminCommand && /실행|사용|시도|run|executed|invoke/.test(desc);
  const newSource=/처음\s*보는\s*(?:주소|ip)|낯선\s*(?:ip|주소)|알려지지\s*않는\s*(?:주소|ip)|unknown\s+source|unrecognized\s+(?:ip|source)|new\s+ip/.test(desc);
  const offHours=/수업\s*시간\s*밖|업무\s*시간\s*밖|업무처럼\s*보이지\s*않는\s*시각|야간|after.hours|off.hours|outside\s+business\s+hours/.test(desc);
  const freshAdmin=/방금\s*관리자가|곧바로|직후|바로\s*권한|just\s+elevated|immediately\s+after/.test(desc);
  const otherAccount=/다른\s*계정의\s*권한|다른\s*사용자.*권한|another\s+account|impersonat|different\s+account/.test(desc);
  const changedSession=/세션이\s*관리자\s*권한으로\s*바뀌|세션.{0,24}관리자\s*권한.{0,16}(?:변경|전환|상승)|session.{0,30}(?:promot|elevat|admin)/.test(desc);
  const reentry=/관리자\s*그룹에서\s*빠진.{0,45}다시\s*관리자|(?:제외|삭제|제거).{0,35}(?:재가입|재추가|다시\s*관리자)|re.?added.{0,15}admin/.test(desc);
  const groupMass=groupEntry && count>=3;
  const readOnly=/읽기만|조회|확인|설명만\s*바뀌|변경은\s*없|목록을\s*읽|read.only|view.only/.test(desc);
  const canceled=/취소됐|취소되|실패\s*1건|실패했|failed|canceled|cancelled|not\s+executed|명령은\s*없/.test(desc);
  const classActivity=/수업\s*시간|수업\s*중|과제\s*그룹|수업\s*그룹|평소\s*주소|평소\s*(?:예약|접속)/.test(desc);
  const accountValid=typeof account==='string' && /^[A-Za-z0-9._@-]{1,80}$/.test(account);
  return {desc,sourceValid:sourceValid(source),accountValid,level,tagged,
    groupEntry,adminCommand,commandRan,newSource,offHours,freshAdmin,
    otherAccount,changedSession,reentry,groupMass,readOnly,canceled,classActivity};
}
export function decide(alert) {
  const s=examine(alert);
  const finish=(confidence,reason)=>({
    action:confidence>=0.85?'block':confidence>=0.5?'alert':'record',
    confidence,reason
  });
  if(!s.tagged)return finish(0.07,PATTERNS.normal);
  const canBlock=s.level>=10 && s.sourceValid && s.accountValid && !s.canceled && !s.readOnly;
  if(canBlock) {
    if(s.reentry)return finish(0.97,PATTERNS.reentry);
    if(s.groupEntry && s.commandRan)return finish(0.99,PATTERNS.combined);
    if(s.groupMass)return finish(0.98,PATTERNS.group);
    if(s.groupEntry)return finish(0.96,PATTERNS.group);
    if(s.changedSession && s.newSource)return finish(0.97,PATTERNS.session);
    if(s.commandRan && (s.newSource || s.offHours || s.freshAdmin || s.otherAccount))
      return finish(s.otherAccount?0.96:0.95,PATTERNS.command);
  }
  // A T1068/T1078-tagged medium/high-level event without corroboration is
  // review-only, including canceled prompts, classroom tasks and non-admin groups.
  if(s.level>=5)return finish(0.64,PATTERNS.uncertain);
  return finish(0.07,PATTERNS.normal);
}
