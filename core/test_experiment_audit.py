import logging,os
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core.experiment_audit import emit

def test_audit_opt_in_and_no_pipeline_exception(monkeypatch,caplog):
 logger=logging.getLogger('audit-test')
 monkeypatch.setenv('LAB_AUDIT_ENABLED','false')
 with caplog.at_level(logging.INFO):emit(logger,'cycle',pipeline_active=True)
 assert not caplog.records
 monkeypatch.setenv('LAB_AUDIT_ENABLED','true')
 with caplog.at_level(logging.INFO):emit(logger,'cycle',pipeline_active=True)
 assert 'LAB_AUDIT ' in caplog.text
 emit(logger,'cycle',invalid=float('nan'))
 assert 'LAB_AUDIT_WRITE_FAILED' in caplog.text
