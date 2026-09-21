from __future__ import annotations

from dataclasses import dataclass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine import VulnerableEDR
from models import Event

@dataclass(frozen=True)
class Case:
    number: int
    rule_id: str
    title: str
    expected: str
    event_factory: object

def c1():
    return VulnerableEDR(), [Event(event_type='ProcessStart', timestamp=1.0, pid=100, image=r'C:\Windows\System32\PowerShell.EXE')]

def c2():
    return VulnerableEDR(), [Event(event_type='ProcessStart', timestamp=2.0, pid=101, image=r'C:\Windows\Temp\..\System32\cmd.exe', metadata={'actual_resolves_to': r'C:\Windows\System32\cmd.exe'})]

def c3():
    e=VulnerableEDR()
    return e, [
        Event(event_type='ProcessStart', timestamp=3.0, pid=102, image=r'C:\Windows\System32\notepad.exe', metadata={'process_generation':1}),
        Event(event_type='Behavior', timestamp=3.5, pid=102, metadata={'process_generation':2,'previous_generation_same_pid':True,'known_bad_behavior':True})
    ]

def c4():
    return VulnerableEDR(), [Event(event_type='Behavior', timestamp=4.2, pid=103, metadata={'correlation':{'related_delta_ms':120},'known_bad_behavior':True})]

def c5():
    return VulnerableEDR(), [Event(event_type='Behavior', timestamp=5.0, pid=104, parent_pid=5000, metadata={'requires_trusted_parent':True,'reported_parent_image':r'C:\Windows\System32\svchost.exe','actual_parent_image':r'C:\Temp\untrusted-parent.exe','known_bad_behavior':True})]

def c6():
    return VulnerableEDR(), [Event(event_type='ProcessStart', timestamp=6.0, pid=105, image=r'C:\Windows\System32\powershell.exe', command_line='PowerShell   -ENC   TEST')]

def c7():
    e=VulnerableEDR(); e.events_lost=1
    return e, [Event(event_type='Behavior', timestamp=7.0, pid=106, metadata={'known_bad_behavior':True})]

def c8():
    return VulnerableEDR(), [
        Event(event_type='Behavior', timestamp=8.0, pid=107, metadata={'note':'first benign event'}),
        Event(event_type='Behavior', timestamp=8.1, pid=107, metadata={'known_bad_behavior':True})
    ]

def c9():
    return VulnerableEDR(), [Event(event_type='Behavior', timestamp=9.0, pid=108, metadata={'first_match_benign':True,'known_bad_behavior':True})]

def c10():
    return VulnerableEDR(), [Event(event_type='Behavior', timestamp=10.0, pid=109, signature_status=None, metadata={'review_signature':True,'known_bad_behavior':True})]

CASES=[
    Case(1,'EDR-001','Case-sensitive image matching','PowerShell image should be recognized case-insensitively',c1),
    Case(2,'EDR-002','Path canonicalization','Equivalent path aliases should resolve before policy comparison',c2),
    Case(3,'EDR-010','PID-only process identity','A new process generation must not inherit suppression state from a prior PID owner',c3),
    Case(4,'EDR-010','Narrow correlation window','Related events outside 10 ms should remain correlatable',c4),
    Case(5,'EDR-010','Unverified parent identity','A reported trusted parent must not override independent parent evidence',c5),
    Case(6,'EDR-006','Exact command-line string','Semantically equivalent command syntax should be normalized',c6),
    Case(7,'EDR-010','Fail-open event loss','Telemetry loss should raise degraded-visibility state instead of suppressing behavior alerts',c7),
    Case(8,'EDR-010','Weak deduplication key','Two distinct events for one PID must not collide',c8),
    Case(9,'EDR-010','Early benign short-circuit','Low-confidence classification must not suppress higher-confidence rules',c9),
    Case(10,'EDR-010','Missing signature fail-open','Unknown signature state must not be treated as trusted',c10),
]
