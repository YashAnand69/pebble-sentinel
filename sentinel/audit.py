from pathlib import Path
import hashlib
import json
import threading

ZERO = '0' * 64

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)

def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()

class AuditLog:
    def __init__(self, path):
        self.path=Path(path)
        self.lock=threading.Lock()
        self.path.parent.mkdir(parents=True,exist_ok=True)
        if self.path.exists(): self.verify()
        rows=self.read()
        self.previous_hash=rows[-1]['hash'] if rows else ZERO
        self.expected_size=self.path.stat().st_size if self.path.exists() else 0

    def append(self, record):
        with self.lock:
            actual_size=self.path.stat().st_size if self.path.exists() else 0
            if actual_size!=self.expected_size: raise ValueError('Audit log changed outside this writer')
            entry={**record,'prev_hash':self.previous_hash}
            entry['hash']=digest(entry)
            with self.path.open('a',encoding='utf8') as f:
                f.write(canonical(entry)+'\n')
                f.flush()
            self.previous_hash=entry['hash']
            self.expected_size=self.path.stat().st_size
            return entry

    def read(self):
        if not self.path.exists(): return []
        return [json.loads(line) for line in self.path.read_text().splitlines() if line.strip()]

    def verify(self):
        prev=ZERO
        for row in self.read():
            claimed=row.pop('hash',None)
            if row.get('prev_hash')!=prev or claimed!=digest(row): raise ValueError('Audit hash chain mismatch')
            prev=claimed
        return True
