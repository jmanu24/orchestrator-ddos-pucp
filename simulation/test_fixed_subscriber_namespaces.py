import importlib.util,sys
from pathlib import Path
from types import SimpleNamespace
root=Path(__file__).resolve().parents[1];sys.path.insert(0,str(root))
spec=importlib.util.spec_from_file_location('subscriber',root/'simulation/bng_subscriber_agent.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

def test_commands_execute_in_the_subscriber_namespace(monkeypatch):
 monkeypatch.setattr(module,'_USE_NAMESPACES',True)
 assert module._subscriber_argv(10,['dhclient'])==['ip','netns','exec','fixed10','dhclient']
 seen=[]
 def run(argv,**kw):seen.append(argv);return SimpleNamespace(stdout='2: macvlan10 inet 10.20.0.174/24')
 monkeypatch.setattr(module.subprocess,'run',run)
 assert module._read_iface_ip('macvlan10')=='10.20.0.174'
 sub=module.Subscriber(10,'10.20.0.1');sub.ip='10.20.0.174';sub._add_source_route()
 assert seen[-1]==['ip','-n','fixed10','route','replace','default','via','10.20.0.1','dev','macvlan10']

def test_dhcp_retry_keeps_the_existing_client(monkeypatch,tmp_path):
 monkeypatch.setattr(module,'_USE_NAMESPACES',True)
 monkeypatch.setattr(module,'_DHCP_RUN_DIR',str(tmp_path))
 monkeypatch.setattr(module,'_dhcp_running',lambda n:True)
 monkeypatch.setattr(module,'_read_iface_ip',lambda iface:'10.20.0.174')
 def reject(*args,**kw):raise AssertionError('A duplicate DHCP client was launched')
 monkeypatch.setattr(module.subprocess,'run',reject)
 sub=module.Subscriber(10,'10.20.0.1');monkeypatch.setattr(sub,'_add_source_route',lambda:None);sub.session_up();assert sub.ip=='10.20.0.174'
