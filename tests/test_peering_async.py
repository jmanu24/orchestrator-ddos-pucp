import unittest
from unittest.mock import patch
from telemetry.bgp_adapter import BGPPeeringAdapter

class Collector:
 def __init__(self):self.calls=0;self.fail=False
 def poll(self):
  self.calls+=1
  if self.fail:raise OSError('decode failure')
  return [dict(src_ip='10.30.0.2',dst_ip='10.55.0.100',dst_port=9001,protocol='TCP',pps=2,bps=100)]

class AsyncPeeringTests(unittest.TestCase):
 def test_pending_poll_never_blocks_or_duplicates_and_result_delivered_once(self):
  c=Collector();a=BGPPeeringAdapter(collector=c,async_poll=True);queue=[]
  with patch('ryu.lib.hub.spawn',side_effect=lambda fn:queue.append(fn)):
   self.assertEqual(a.collect(),[]);self.assertEqual(a.collect(),[])
   self.assertEqual(len(queue),1);self.assertEqual(c.calls,0)
   queue.pop()();self.assertEqual(len(a.collect()),1)
   self.assertEqual(a.collect(),[]);self.assertEqual(len(queue),1)
 def test_failed_poll_releases_slot_and_marks_disconnected(self):
  c=Collector();c.fail=True;a=BGPPeeringAdapter(collector=c,async_poll=True);queue=[]
  with patch('ryu.lib.hub.spawn',side_effect=lambda fn:queue.append(fn)):
   a.collect();queue.pop()();self.assertFalse(a.is_connected());self.assertFalse(a._poll_pending)
   c.fail=False;a.collect();queue.pop()();self.assertTrue(a.is_connected());self.assertEqual(len(a.collect()),1)
 def test_synchronous_mode_retains_contract(self):
  c=Collector();a=BGPPeeringAdapter(collector=c);self.assertEqual(len(a.collect()),1);self.assertEqual(c.calls,1)

if __name__=='__main__':unittest.main()
