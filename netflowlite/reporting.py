import csv,json
from pathlib import Path
def write_json(report,path):
    p=Path(path); p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n',encoding='utf-8')
def write_csv(conversations,path):
    p=Path(path); p.parent.mkdir(parents=True,exist_ok=True); fields=['protocol','source','destination','packets','bytes']
    with p.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(conversations)
