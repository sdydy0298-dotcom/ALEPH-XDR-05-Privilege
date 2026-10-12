import {readFile} from 'node:fs/promises';
import {isIP} from 'node:net';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
const source=new URL('../fixtures/privilege.json',import.meta.url);
export function redact(value) {
  return String(value??'').replace(/[\r\n\t]/g,' ')
    .replace(/\b(?:password|passwd|pwd|token|secret|cookie|authorization|api[_-]?key)\b\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s&,;]+)/gi,'[REDACTED]')
    .replace(/\bBearer\s+\S+/gi,'Bearer [REDACTED]')
    .replace(/\b[A-Za-z0-9_-]{48,}\b/g,'[REDACTED]').slice(0,200);
}
export function projectAlert(alert) {
  const data=alert?.data??{};
  const raw=String(data.srcip??data.src_ip??data.source_ip??alert?.srcip??'');
  const level=Number(alert?.rule?.level??0);
  return {time:redact(alert?.timestamp),source:isIP(raw)?raw:'',
    account:redact(data.srcuser??data.dstuser??data.username??alert?.account),
    level:Number.isFinite(level)?level:0,
    description:redact(alert?.rule?.description)};
}
export async function readAlerts() {
  const fixture=JSON.parse(await readFile(source,'utf8'));
  if(fixture.schema!=='aleph.xdr.fixture.v1' || fixture.moduleKey!=='privilege' ||
    !Array.isArray(fixture.alerts))throw new Error('Unexpected official privilege fixture');
  return fixture.alerts.map(projectAlert);
}
if(process.argv[1] && import.meta.url===pathToFileURL(resolve(process.argv[1])).href)
  for(const line of await readAlerts())console.log(JSON.stringify(line));
