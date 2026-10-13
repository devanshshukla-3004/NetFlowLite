from collections import Counter, defaultdict
COMMON_PORTS={22,25,53,80,123,135,139,143,443,445,3306,3389,5432,8080}
def detect_patterns(records,port_fanout=12,source_packet_limit=1000,service_source_limit=20):
    if min(port_fanout,source_packet_limit,service_source_limit)<1: raise ValueError('thresholds must be positive integers')
    src_ports,src_count,service_sources=defaultdict(set),Counter(),defaultdict(set)
    for r in records:
        src=r['src_ip']; src_count[src]+=1; port=r.get('dst_port')
        if port is not None:
            port=int(port); src_ports[src].add(port)
            if port in COMMON_PORTS: service_sources[port].add(src)
    out=[]
    for src,ps in sorted(src_ports.items()):
        if len(ps)>=port_fanout: out.append({'id':f'PORT-FANOUT-{src}','type':'destination_port_fanout','severity':'HIGH','source_ip':src,'observed':len(ps),'threshold':port_fanout,'evidence':f'{src} contacted {len(ps)} unique destination ports.','recommendation':'Validate the source role and destination scope; confirm whether this pattern is expected.'})
    for src,n in sorted(src_count.items()):
        if n>=source_packet_limit: out.append({'id':f'SOURCE-BURST-{src}','type':'source_packet_burst','severity':'MEDIUM','source_ip':src,'observed':n,'threshold':source_packet_limit,'evidence':f'{src} appeared in {n} packets in this capture.','recommendation':'Compare with baseline traffic and review timing, destinations, and application context.'})
    for port,sources in sorted(service_sources.items()):
        if len(sources)>=service_source_limit: out.append({'id':f'SERVICE-CONCENTRATION-{port}','type':'service_source_concentration','severity':'LOW','destination_port':port,'observed':len(sources),'threshold':service_source_limit,'evidence':f'Destination port {port} was contacted by {len(sources)} unique source IPs.','recommendation':'Confirm the service is expected to be reachable and compare against normal client volume.'})
    return out
