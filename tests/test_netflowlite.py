import csv,json,tempfile,unittest
from pathlib import Path
from netflowlite.capture import load_input
from netflowlite.analyzer import analyze_records
from netflowlite.detections import detect_patterns
from netflowlite.reporting import write_json,write_csv
ROOT=Path(__file__).resolve().parents[1]
class NetFlowLiteTests(unittest.TestCase):
    def setUp(self): self.records=load_input(ROOT/'samples'/'lab_capture.json')
    def test_sample_packet_count(self): self.assertEqual(len(self.records),18)
    def test_protocol_and_endpoint_summary(self):
        s=analyze_records(self.records); self.assertEqual(s['packet_count'],18); self.assertEqual(s['unique_source_ips'],4); self.assertEqual(s['unique_destination_ips'],13); self.assertEqual(s['protocol_counts'],{'ICMP':1,'TCP':15,'UDP':2})
    def test_conversation_aggregation(self):
        s=analyze_records(self.records); r=next(x for x in s['conversations'] if x['destination']=='192.168.1.20:443'); self.assertEqual((r['packets'],r['bytes']),(2,1270))
    def test_port_fanout(self): self.assertTrue(any(f['type']=='destination_port_fanout' and f['source_ip']=='192.168.1.10' for f in detect_patterns(self.records,8,100,100)))
    def test_source_burst(self): self.assertTrue(any(f['type']=='source_packet_burst' for f in detect_patterns(self.records,99,10,99)))
    def test_default_thresholds_no_findings(self): self.assertEqual(detect_patterns(self.records),[])
    def test_json_csv_export(self):
        with tempfile.TemporaryDirectory() as d:
            s=analyze_records(self.records); jp=Path(d)/'nested/report.json'; cp=Path(d)/'nested/flows.csv'; write_json({'summary':s},jp); write_csv(s['conversations'],cp); self.assertEqual(json.loads(jp.read_text())['summary']['packet_count'],18)
            with cp.open(newline='') as f: self.assertTrue(list(csv.DictReader(f)))
    def test_invalid_schema(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'bad.json'; p.write_text(json.dumps([{'src_ip':'1.1.1.1'}]))
            with self.assertRaisesRegex(ValueError,'missing required'): load_input(p)
    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError): load_input(ROOT/'samples'/'absent.json')
    def test_bad_threshold(self):
        with self.assertRaises(ValueError): detect_patterns(self.records,0)
if __name__=='__main__': unittest.main()
