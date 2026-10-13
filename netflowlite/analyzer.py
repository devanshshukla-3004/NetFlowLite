from collections import Counter, defaultdict

def analyze_records(records, source='unknown'):
    protocols,src_counts,dst_counts,src_bytes,ports=Counter(),Counter(),Counter(),Counter(),Counter()
    flows=defaultdict(lambda:{'packets':0,'bytes':0}); times=[]
    for r in records:
        src,dst,proto,size=r['src_ip'],r['dst_ip'],r['protocol'].upper(),int(r.get('bytes',0))
        protocols[proto]+=1; src_counts[src]+=1; dst_counts[dst]+=1; src_bytes[src]+=size
        if r.get('dst_port') is not None: ports[int(r['dst_port'])]+=1
        ts=float(r.get('timestamp',0))
        if ts: times.append(ts)
        a=f"{src}:{r['src_port']}" if r.get('src_port') is not None else src
        b=f"{dst}:{r['dst_port']}" if r.get('dst_port') is not None else dst
        k=(proto,a,b); flows[k]['packets']+=1; flows[k]['bytes']+=size
    conv=[{'protocol':k[0],'source':k[1],'destination':k[2],'packets':v['packets'],'bytes':v['bytes']} for k,v in sorted(flows.items(),key=lambda x:(-x[1]['bytes'],x[0]))]
    return {'input':source,'packet_count':len(records),'total_bytes':sum(int(r.get('bytes',0)) for r in records),'unique_source_ips':len(src_counts),'unique_destination_ips':len(dst_counts),'protocol_counts':dict(sorted(protocols.items())),'time_span_seconds':round(max(times)-min(times),3) if len(times)>1 else 0.0,'top_sources':[{'ip':ip,'packets':n,'bytes':src_bytes[ip]} for ip,n in src_counts.most_common(10)],'top_destinations':[{'ip':ip,'packets':n} for ip,n in dst_counts.most_common(10)],'top_destination_ports':[{'port':p,'packets':n} for p,n in ports.most_common(10)],'conversations':conv}
