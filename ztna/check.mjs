// ALEPH XDR-05 local ZTNA policy evaluator (educational simulation only).
// Session identity = account + source. Never deny on IP alone or on username alone.
const object = x => x && typeof x==='object' && !Array.isArray(x) ? x : {};
export function checkAccess(session,dynamicRules=[],at=Date.now(),basePolicy={}) {
  const s=object(session),current=at instanceof Date?at.getTime():Number(at);
  if(!Number.isFinite(current))throw new TypeError('Invalid evaluation time');
  if(typeof s.account!=='string' || typeof s.source!=='string' ||
    !s.account.trim() || !s.source.trim())
    return {action:'deny',reason:'세션 계정·접속 출처를 확인할 수 없음'};
  const eligible=rule=>!rule.expiresAt || Number.isFinite(Date.parse(rule.expiresAt)) && Date.parse(rule.expiresAt)>current;
  const staticMatch=rule=>{
    if(!rule || typeof rule!=='object' || !eligible(rule))return false;
    // Existing policies may target account, source, or a more specific session.
    const specified=typeof rule.account==='string'||typeof rule.source==='string'||typeof rule.sessionId==='string';
    return specified &&
      (rule.account===undefined||rule.account===s.account) &&
      (rule.source===undefined||rule.source===s.source) &&
      (rule.sessionId===undefined||rule.sessionId===s.sessionId);
  };
  if(Array.isArray(basePolicy.deny)&&basePolicy.deny.some(staticMatch))
    return {action:'deny',reason:'기존 ZTNA 거부 정책'};
  const isolated=Array.isArray(dynamicRules)&&dynamicRules.some(rule=>
    rule && rule.action==='deny' && rule.scope==='account-source' &&
    typeof rule.account==='string' && typeof rule.source==='string' &&
    rule.account===s.account && rule.source===s.source &&
    typeof rule.expiresAt==='string' &&
    Number.isFinite(Date.parse(rule.expiresAt)) && Date.parse(rule.expiresAt)>current);
  return isolated
    ? {action:'deny',reason:'XDR-05 임시 계정 세션 거부'}
    : {action:'allow',reason:'활성 계정 세션 거부 규칙 없음'};
}
