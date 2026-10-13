import argparse,sys
from netflowlite.capture import load_input
from netflowlite.analyzer import analyze_records
from netflowlite.detections import detect_patterns
from netflowlite.reporting import write_json,write_csv

def main(argv=None):
    parser=argparse.ArgumentParser(description='Offline network traffic analysis for authorized captures.')
    sub=parser.add_subparsers(dest='command',required=True); p=sub.add_parser('analyze',help='Analyze PCAP/PCAPNG or JSON lab traffic')
    p.add_argument('input'); p.add_argument('--json',dest='json_path',default='reports/netflowlite-report.json'); p.add_argument('--csv',dest='csv_path',default='reports/netflowlite-flows.csv')
    p.add_argument('--port-fanout',type=int,default=12); p.add_argument('--source-packet-limit',type=int,default=1000); p.add_argument('--service-source-limit',type=int,default=20)
    a=parser.parse_args(argv)
    try:
        if min(a.port_fanout,a.source_packet_limit,a.service_source_limit)<1: raise ValueError('detection thresholds must be positive')
        records=load_input(a.input); summary=analyze_records(records,str(a.input)); findings=detect_patterns(records,a.port_fanout,a.source_packet_limit,a.service_source_limit)
        write_json({'tool':'NetFlowLite','version':'1.0.0','summary':summary,'findings':findings,'notice':'Heuristic findings are leads for investigation, not proof of compromise.'},a.json_path); write_csv(summary['conversations'],a.csv_path)
    except (OSError,ValueError,RuntimeError) as e: print(f'error: {e}',file=sys.stderr); return 2
    print('NetFlowLite | Network Traffic Analysis Engine'); print(f'Input: {a.input}'); print(f"Packets analyzed: {summary['packet_count']}"); print(f"Unique source IPs: {summary['unique_source_ips']}"); print(f"Unique destination IPs: {summary['unique_destination_ips']}")
    print('Protocols: '+', '.join(f'{k}={v}' for k,v in sorted(summary['protocol_counts'].items()))); print(f"Conversations: {len(summary['conversations'])}")
    levels={x:sum(f['severity']==x for f in findings) for x in ('HIGH','MEDIUM','LOW')}; print(f"Findings: {len(findings)} (HIGH={levels['HIGH']}, MEDIUM={levels['MEDIUM']}, LOW={levels['LOW']})"); print(f'JSON report: {a.json_path}'); print(f'CSV flows: {a.csv_path}'); return 0
if __name__=='__main__': raise SystemExit(main())
