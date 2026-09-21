from __future__ import annotations
from cases import CASES

def main() -> int:
    print('EDDRR intentional-failure PoC suite')
    print('=' * 72)
    failures=0
    for case in CASES:
        engine,events=case.event_factory()
        alerts=[]
        for event in events:
            alerts.extend(engine.detect(event))
        observed=[a.rule_id for a in alerts]
        missed=case.rule_id not in observed
        status='PASS' if missed else 'FAIL'
        print(f'[{status}] {case.number:02d} {case.title}')
        print(f'       expected: {case.expected}')
        print(f'       expected rule: {case.rule_id}')
        print(f'       observed alerts: {observed}')
        if not missed: failures += 1
    print()
    if failures:
        print(f'{failures} intentionally vulnerable cases did not reproduce.')
        return 1
    print('All 10 false-negative cases reproduced against the vulnerable engine.')
    print('These PoCs operate only on synthetic Event objects.')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
