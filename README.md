# ALEPH XDR-05 · 권한 가로채기를 잡아 냅니다

일반 계정이 갑자기 **관리자 그룹에 추가**되거나, **낯선 출처·시각에서 관리자 명령을 실행**하는 경보를 분류하고 **명확한 탈취 세션만** 로컬 ZTNA 판정기에 임시 거부하는 보너스 과제입니다.

**공개 결과물:** https://sdy-xdr-05.vercel.app  
**공개 GitHub:** https://github.com/sdydy0298-dotcom/ALEPH-XDR-05-Privilege

> 실제 Wazuh 서버나 운영 인증 시스템과 연결하지 않았습니다. 수업용 가상 경보로 `decide(alert)`, 알림 파일, 파일 기반 **계정·IP 조합의 모의 세션 거부**를 검증합니다. 실제 세션 토큰 철회나 사용자의 강제 로그아웃을 수행하지 않습니다.

## 원본과 심판 실행 계약

- **원본 변경 없음:** [ChoiTimo 공식 `xdr/fixtures/privilege.json`](https://github.com/ChoiTimo/aleph-defense-starter/blob/main/xdr/fixtures/privilege.json), 26건의 가상 Wazuh 경보
- **원본 실행기 변경 없음:** [`scripts/xdr-run.mjs`](https://github.com/ChoiTimo/aleph-defense-starter/blob/main/scripts/xdr-run.mjs)
- 입력 스키마: `aleph.xdr.fixture.v1` → 결과 스키마: `aleph.xdr.result.v1`
- MITRE ATT&CK **T1068 (권한 상승 악용), T1078 (정상 계정 도용)**
- **BLOCK 9 / ALERT 8 / RECORD 9** (공식 연습 경보에 대한 자체 분류), 정상 이벤트 오차단 **0건**
- **알림 17건**, **임시 세션 거부 정책 9건**, 정책 만료 **15분**
- 심판의 비공개 정답표는 제공되지 않아 채점 일치 여부는 재제출 후 확인 필요

## 실행

```bash
npm run xdr:run -- privilege
npm test
npm run build
```

`npm run xdr:run -- privilege`는 공식 실행기로 모든 경보를 독립 분류한 다음 `respond.mjs`로 알림 로그와 임시 정책을 저장합니다. 테스트는 실제 판정 결과 재계산, 정상 사용자 보호, 정책 만료, UI 표기, 결과 재현성을 검사합니다.

## 제작 단계별 결과 확인

| 단계 | 파일 | 요구사항 구현 |
|---|---|---|
| 1 · 경보 읽기 | `xdr/privilege/read-alerts.mjs` | **26건 → 26줄**, 시각·출발 IP·계정·규칙 수준·설명 5개만 추출, 토큰·비밀번호 마스킹 |
| 2 · 패턴 | `xdr/privilege/patterns.json` | 관리자 그룹 추가, 관리자 명령, 시간 외/낯선 출처, 급격한 세션 권한 상승 등 T1068/T1078 근거 |
| 3 · 독립 판단기 | `xdr/privilege/decide.mjs` | **import 없이 단독 실행**, 외부 네트워크·파일 접근 없음, 0.85 이상 BLOCK, 0.5 이상 ALERT, 미만 RECORD |
| 4 · 알림·세션 거부 | `xdr/privilege/respond.mjs` | 확인된 BLOCK만 `account+source` 조합에 15분 만료 거부 규칙·경보 ID 추가, ALERT는 알림 로그만 |
| 5 · 시험 경보 | `xdr/privilege/run.mjs` | 공식 26건 재생, 정상 세션 오차단 0, 만료 후 허용 |
| 검증 | `.github/workflows/check.yml` | 재실행 → 테스트 → 재실행 → Vercel 사이트 빌드 → 결과 파일 일치 검증 |

### 보안 원칙: IP 또는 사용자 이름만으로 차단하지 않음

XDR-05는 보너스 XDR-01~04와 달리 **사용자 계정의 세션**에 관한 과제입니다.

로컬 판정기의 임시 규칙은 `{action:'deny',scope:'account-source',account,source,alertId,createdAt,expiresAt}` 구조입니다.

- 공격 경보 `pv-01`: `user01` + `203.0.113.11` 세션 **DENY**
- 같은 계정의 정상 경보 `pv-18`: `user01` + `192.0.2.76` 세션 **ALLOW**
- 같은 IP를 쓰는 **다른 계정**도 허용됩니다.
- 기본 `ztna/rules.json`은 수정하지 않고, `ztna/evaluate.mjs`에서 임시 규칙을 **추가 게이트로 평가**합니다.
- 고확신도라도 실제 계정·출처가 불명확하면 거부 규칙을 생성하지 않습니다. 위조 BLOCK 결과도 `respond.mjs`가 독립 재검증합니다.

**중요한 한계:** 교육용 경보에는 실제 세션 ID가 없어 `계정 + 접속 IP`를 세션 대용으로 사용합니다. 실제 운영에서는 인증 제공자의 고유 세션 ID를 연동해 토큰/세션 폐기를 해야 하며 NAT 공유 IP, VPN, 동적 주소 등을 고려해야 합니다. 브라우저의 DENY/ALLOW는 이 시뮬레이션 결과일 뿐 실제 사용자 세션을 끊지 않습니다.

## 대시보드 사용

사이트에서 **관리자 그룹 편입 → 취소된 권한 상승 → 같은 계정의 정상 로그인** 시나리오를 선택하면 브라우저가 같은 `decide(alert)` 함수를 오프라인으로 다시 호출합니다. 전체 26건을 판정·계정·출발 IP로 검색/필터링할 수 있습니다.

## 프로젝트 분리

이 GitHub 저장소는 XDR-01·02·03·04와 **완전히 독립**되어 있으며 다른 과제의 GitHub 커밋, Vercel 사이트, 원본 로그를 변경하지 않습니다.

실제 비밀번호·세션 토큰·개인키를 저장하거나 공개하지 않으며 교육용 문서 IP 및 가상 계정만 사용합니다. 결과 파일의 고정 점검 시각은 `2026-10-13T00:00:00Z`입니다.
