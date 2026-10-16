import csv,sys
r=list(csv.DictReader(open(sys.argv[1],encoding='utf-8-sig')))
keys=['t_s','siem-api_cpu','siem-api_mb','wazuh-remoted_cpu','wazuh-remoted_mb','wazuh-analysisd_cpu','wazuh-analysisd_mb','wazuh-db_cpu','loadgen_cpu','tcp_sessions','remoted_queue','remoted_discarded','ana_dropped','ana_winevt_q','ana_event_q','alerts_written','ch_events','ch_alerts','ch_cpu','ch_mem']
print(' '.join(k.replace('wazuh-','')[:10].rjust(10) for k in keys))
for x in r: print(' '.join(str(x.get(k,''))[:10].rjust(10) for k in keys))
