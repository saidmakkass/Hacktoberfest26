"""Validated, immutable-for-a-session review policy."""
from dataclasses import dataclass, field
from typing import Any
import hashlib
import json


@dataclass
class ReviewPolicy:
    raw: dict = field(default_factory=dict)
    dismissal: dict = field(default_factory=dict)
    engine: str = 'cloud_fast'
    preset: str = 'all'
    offline: bool = False
    allow_fallback: bool = False
    incomplete: str = 'block'
    open_browser: bool = True
    timeout_seconds: int = 1800
    max_file_bytes: int = 1_000_000

    @classmethod
    def from_raw(cls, raw: dict):
        if not isinstance(raw, dict):
            raise ValueError('Policy must be a mapping')
        r = raw.get('review', {})
        if not isinstance(r, dict):
            raise ValueError('review must be a mapping')
        allowed = {'dismissal', 'engine', 'preset', 'offline', 'allow_fallback', 'incomplete',
                   'open_browser', 'timeout_seconds', 'max_file_bytes'}
        if set(r) - allowed:
            raise ValueError('Unknown review settings: ' + ', '.join(set(r) - allowed))
        d = r.get('dismissal', {'default': True, 'severity': {
            s: False for s in raw.get('block_on', ['CRITICAL', 'HIGH'])}})
        if not isinstance(d, dict) or set(d) - {'default', 'severity', 'category', 'rule'}:
            raise ValueError('Invalid review.dismissal settings')
        if type(d.get('default', True)) is not bool:
            raise ValueError('dismissal.default must be boolean')
        for key in ('severity', 'category', 'rule'):
            values = d.get(key, {})
            if not isinstance(values, dict) or any(type(v) is not bool for v in values.values()):
                raise ValueError(f'dismissal.{key} must map names to booleans')
        for name in ('offline', 'allow_fallback', 'open_browser'):
            if name in r and type(r[name]) is not bool:
                raise ValueError(f'review.{name} must be boolean')
        for name in ('timeout_seconds', 'max_file_bytes'):
            if name in r and (type(r[name]) is not int or r[name] <= 0):
                raise ValueError(f'review.{name} must be a positive integer')
        if r.get('incomplete', 'block') not in ('block', 'warn'):
            raise ValueError('review.incomplete must be block or warn')
        engine = r.get('engine', raw.get('default_engine', 'cloud_fast'))
        if engine not in ('cloud_fast', 'cloud_deep', 'local_edge', 'hybrid_smart'):
            raise ValueError('Invalid review engine')
        return cls(raw=json.loads(json.dumps(raw)), dismissal=d, engine=engine,
                   preset=r.get('preset', raw.get('default_preset', 'all')),
                   **{k: v for k, v in r.items() if k not in ('dismissal', 'engine', 'preset')})

    def can_dismiss(self, finding):
        for key, value in (('rule', finding.rule_id), ('category', finding.category.value),
                           ('severity', finding.severity.value)):
            if value in self.dismissal.get(key, {}):
                return self.dismissal[key][value]
        return self.dismissal.get('default', True)

    @property
    def fingerprint(self):
        return hashlib.sha256(json.dumps(self.raw, sort_keys=True).encode()).hexdigest()

    def public(self):
        return {'engine': self.engine, 'preset': self.preset, 'offline': self.offline,
                'dismissal': self.dismissal, 'incomplete': self.incomplete,
                'timeout_seconds': self.timeout_seconds}
