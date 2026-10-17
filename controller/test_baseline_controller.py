import json,time,importlib.util
from pathlib import Path
import pytest

spec=importlib.util.spec_from_file_location('guard',Path(__file__).parents[1]/'config/baseline.py')
guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)
class Orchestrator:
 def __init__(self):
  self._active_blocks={('a','b',1,'TCP'):True}
  self._active_mobile_blocks={('c','b',2,'UDP'):True}
 def force_unblock(self,*key):
  for d in (self._active_blocks,self._active_mobile_blocks):
   if key in d:del d[key];return True
  return False

def test_active_lease_clears_both_domains(tmp_path):
 lease=tmp_path/'lease.json';status=tmp_path/'status.json';o=Orchestrator()
 lease.write_text(json.dumps(dict(run_id='baseline',expires_at=time.time()+60)))
 assert guard.baseline_active(o,lease,status)
 assert not o._active_blocks and not o._active_mobile_blocks
 assert json.loads(status.read_text())['cleared']

def test_expired_and_missing_leases_enable_normal_pipeline(tmp_path):
 lease=tmp_path/'lease.json';status=tmp_path/'status.json';o=Orchestrator()
 lease.write_text(json.dumps(dict(run_id='old',expires_at=time.time()-1)))
 assert not guard.baseline_active(o,lease,status)
 assert o._active_blocks
 lease.unlink();assert not guard.baseline_active(o,lease,status)

def test_cleanup_failure_keeps_pipeline_suspended_but_reports_failure(tmp_path):
 lease=tmp_path/'lease.json';status=tmp_path/'status.json';o=Orchestrator()
 o.force_unblock=lambda *a:False
 lease.write_text(json.dumps(dict(run_id='x',expires_at=time.time()+60)))
 assert guard.baseline_active(o,lease,status)
 assert json.loads(status.read_text())['cleared'] is False
