import json
from pathlib import Path

def validate_records(data):
    if isinstance(data, dict): data = data.get('packets')
    if not isinstance(data, list): raise ValueError("JSON must be a packet list or contain a 'packets' list")
    out=[]
    for i,r in enumerate(data,1):
        if not isinstance(r,dict): raise ValueError(f'packet record {i} must be an object')
        missing={'src_ip','dst_ip','protocol'}-r.keys()
        if missing: raise ValueError(f"packet record {i} missing required field(s): {', '.join(sorted(missing))}")
        try:
            size=int(r.get('bytes',0)); ts=float(r.get('timestamp',i))
            sp=int(r['src_port']) if r.get('src_port') is not None else None
            dp=int(r['dst_port']) if r.get('dst_port') is not None else None
        except (ValueError,TypeError) as e: raise ValueError(f'packet record {i} has invalid numeric fields') from e
        if size<0: raise ValueError(f'packet record {i} bytes cannot be negative')
        out.append({'timestamp':ts,'src_ip':str(r['src_ip']),'dst_ip':str(r['dst_ip']),'protocol':str(r['protocol']).upper(),'src_port':sp,'dst_port':dp,'bytes':size})
    return out

def load_input(path):
    path=Path(path)
    if not path.exists(): raise FileNotFoundError(f'input file not found: {path}')
    if path.suffix.lower()=='.json':
        try: return validate_records(json.loads(path.read_text(encoding='utf-8')))
        except json.JSONDecodeError as e: raise ValueError(f'invalid JSON input: {e}') from e
    if path.suffix.lower() not in {'.pcap','.pcapng','.cap'}: raise ValueError('unsupported input; use .pcap, .pcapng, .cap, or .json')
    try: from scapy.all import IP, IPv6, TCP, UDP, ICMP, rdpcap
    except ImportError as e: raise RuntimeError('Scapy required for PCAP input; install: python -m pip install scapy') from e
    try: packets=rdpcap(str(path))
    except Exception as e: raise ValueError(f'could not read capture: {e}') from e
    out=[]
    for p in packets:
        layer=p.getlayer(IP) or p.getlayer(IPv6)
        if layer is None: continue
        if p.haslayer(TCP): proto,sp,dp='TCP',int(p[TCP].sport),int(p[TCP].dport)
        elif p.haslayer(UDP): proto,sp,dp='UDP',int(p[UDP].sport),int(p[UDP].dport)
        elif p.haslayer(ICMP): proto,sp,dp='ICMP',None,None
        else: proto,sp,dp='OTHER',None,None
        out.append({'timestamp':float(getattr(p,'time',0)),'src_ip':str(layer.src),'dst_ip':str(layer.dst),'protocol':proto,'src_port':sp,'dst_port':dp,'bytes':len(p)})
    return out
