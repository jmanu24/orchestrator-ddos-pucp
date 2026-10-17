"""Time-limited baseline lease; normal pipeline resumes after expiry."""
import json
import time
from pathlib import Path

LEASE=Path('/run/benign-baseline/lease.json')
STATUS=Path('/run/benign-baseline/status.json')


def baseline_active(orchestrator, lease=LEASE, status=STATUS):
    try:
        request=json.loads(lease.read_text())
        active=time.time()<float(request['expires_at'])
    except (OSError,ValueError,KeyError,TypeError):
        request={};active=False
    result=dict(run_id=request.get('run_id'),active=active,heartbeat=time.time())
    if active:
        try:
            for attr in ('_active_blocks','_active_mobile_blocks'):
                for key in list(getattr(orchestrator,attr,{})):
                    if not orchestrator.force_unblock(*key):
                        raise RuntimeError('Failed to release tracked mitigation')
            result['cleared']=True
        except Exception as exc:
            result.update(cleared=False,error=str(exc))
        result['expires_at']=request['expires_at']
    # Cleanup can take time; acknowledge the current lease after it finishes.
    try:
        current=json.loads(lease.read_text())
        active=active and current.get('run_id')==request.get('run_id') and time.time()<float(current['expires_at'])
    except (OSError,ValueError,KeyError,TypeError):
        active=False
    result.update(active=active,heartbeat=time.time())
    try:
        status.parent.mkdir(parents=True,exist_ok=True)
        temp=status.with_suffix('.tmp');temp.write_text(json.dumps(result));temp.replace(status)
    except OSError:
        pass
    return active
