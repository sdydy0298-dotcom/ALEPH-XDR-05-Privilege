import {readFile} from 'node:fs/promises';
import {checkAccess} from './check.mjs';
// Existing ZTNA rules are loaded read-only. Dynamic account/session rules are additive.
export async function evaluateAccess(session,at=Date.now()) {
  const [original,temporary]=await Promise.all([
    readFile(new URL('./rules.json',import.meta.url),'utf8'),
    readFile(new URL('../xdr/temporary-deny.json',import.meta.url),'utf8')
  ]);
  const policy=JSON.parse(original),dynamic=JSON.parse(temporary);
  if(!Array.isArray(dynamic))throw new Error('Invalid dynamic account deny rules');
  return checkAccess(session,dynamic,at,policy);
}
