"""Prepare a provisional phishing-specific evaluation dataset locally."""
import hashlib,json,mailbox,random,shutil,tarfile,urllib.request
from email import policy
from email.parser import BytesParser
from pathlib import Path
B=Path(__file__).resolve().parents[1]; R=B.parent; D=B/'data'/'phishing_specific_corpus'; RAW=D/'raw'; P=D/'prepared'
SEED=20261016; PH='https://monkey.org/~jose/phishing/phishing-2025'; EP='https://www.cs.cmu.edu/~enron/'; EU='https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz'; LABEL='PROVISIONAL: dataset-curator labelled, not human-reviewed'
def hb(x): return hashlib.sha256(x).hexdigest()
def hf(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for c in iter(lambda:f.read(1048576),b''): h.update(c)
 return h.hexdigest()
def usable(raw):
 if not raw or b'\n' not in raw or b':' not in raw.splitlines()[0]: return False
 try:
  m=BytesParser(policy=policy.default).parsebytes(raw); return bool(m.get('From') or m.get('Subject') or m.get('Date'))
 except Exception: return False
def save(raw,folder,prefix):
 if not usable(raw): return None
 p=folder/(prefix+'-'+hb(raw)[:20]+'.eml')
 if not p.exists(): p.write_bytes(raw)
 return p
def oldhash():
 p=B/'data'/'public_email_corpus'/'prepared'/'holdout.jsonl'; out=set()
 if p.exists():
  for line in p.read_text(encoding='utf-8').splitlines():
   if line.strip():
    x=json.loads(line); f=R/x.get('email_path','')
    if f.is_file(): out.add(hf(f))
    if x.get('sha256'): out.add(x['sha256'])
 return out
def phishing():
 RAW.mkdir(parents=True,exist_ok=True); m=RAW/'nazario-phishing-2025.mbox'
 if not m.exists():
  with urllib.request.urlopen(urllib.request.Request(PH,headers={'User-Agent':'MailTrace-AI dataset prep/1.0'}),timeout=90) as r,m.open('wb') as o: shutil.copyfileobj(r,o)
 folder=RAW/'nazario-phishing-2025'; folder.mkdir(parents=True,exist_ok=True); out=[]
 for msg in mailbox.mbox(str(m)):
  try: raw=msg.as_bytes(policy=policy.SMTP)
  except Exception: raw=msg.as_bytes()
  q=save(raw,folder,'nazario2025')
  if q: out.append(q)
 return sorted(set(out))
def enron(limit=2500):
 folder=RAW/'enron-ham'; folder.mkdir(parents=True,exist_ok=True); old=sorted(folder.glob('*.eml'))
 if len(old)>=limit: return old
 req=urllib.request.Request(EU,headers={'User-Agent':'MailTrace-AI dataset prep/1.0','Accept-Encoding':'identity'}); out={hf(q):q for q in old}
 with urllib.request.urlopen(req,timeout=180) as r:
  with tarfile.open(fileobj=r,mode='r|gz') as tf:
   for m in tf:
    if not m.isfile() or m.size<100 or m.size>2000000 or m.name.lower().endswith(('.jpg','.jpeg','.png','.gif','.pdf','.doc','.xls','.zip','.gz')): continue
    src=tf.extractfile(m)
    if src is None: continue
    raw=src.read()
    if not usable(raw): continue
    h=hb(raw)
    if h not in out:
     q=save(raw,folder,'enron')
     if q: out[h]=q
    if len(out)>=limit: break
 return sorted(out.values())
def row(q,split,label):
 name='Nazario phishing corpus 2025' if label=='phishing' else 'CMU Enron Email Dataset (May 2015 archive)'; url=PH if label=='phishing' else EP
 return {'fixture_id':f'R3-{split.upper()}-{label.upper()}-{hf(q)[:12]}','split':split,'email_path':q.relative_to(R).as_posix(),'sha256':hf(q),'expected_label':label,'label_quality':LABEL,'independent_review_status':'not_human_reviewed','provenance':name,'source_url':url,'model_version':None,'policy_version':None}
def main():
 ph=phishing(); print('NAZARIO_2025_PARSEABLE_MESSAGES',len(ph)); hm=enron(); print('ENRON_PARSEABLE_MESSAGES',len(hm))
 old=oldhash(); src={'phishing':[q for q in ph if hf(q) not in old],'ham':[q for q in hm if hf(q) not in old]}
 for k,v in [('phishing',ph),('ham',hm)]: print(k.upper()+'_PREVIOUS_HOLDOUT_SHA256_OVERLAPS_REMOVED',len(v)-len(src[k]))
 n=min(100,len(src['phishing']),len(src['ham']))
 if n<1: raise SystemExit('No balanced phishing/ham sample available')
 rng=random.Random(SEED); splits={'train':[],'dev':[],'holdout':[]}
 for label,paths in src.items():
  paths=list(paths); rng.shuffle(paths); hold=paths[:n]; rest=paths[n:]; nd=max(1,int(len(rest)*.2)) if len(rest)>=4 else 0
  for split,part in [('holdout',hold),('dev',rest[:nd]),('train',rest[nd:])]: splits[split].extend(row(q,split,label) for q in part)
 P.mkdir(parents=True,exist_ok=True)
 for split,rows in splits.items():
  rows.sort(key=lambda x:x['fixture_id']); (P/(split+'.jsonl')).write_text(''.join(json.dumps(x,sort_keys=True)+'\n' for x in rows),encoding='utf-8')
 hh=hf(P/'holdout.jsonl'); (P/'holdout.sha256').write_text(hh+'  holdout.jsonl\n',encoding='ascii')
 report={'schema_version':'1.0','seed':SEED,'label_quality':LABEL,'sources':{'phishing':{'name':'Nazario phishing corpus 2025','url':PH,'license':'CC-BY-4.0; attribution required per source README/LICENSE','parsed_messages':len(ph)},'ham':{'name':'CMU Enron Email Dataset, May 2015 archive','url':EP,'download_url':EU,'license':'No explicit standard corpus-wide license identified; internal evaluation only, legal review pending','parsed_messages':len(hm)}},'split_sizes':{},'class_balance':{},'source_distribution':{},'holdout_frozen':True,'holdout_manifest_sha256':hh,'previous_holdout_overlap_check':{'method':'SHA-256 of raw message bytes','prior_manifest':'backend/data/public_email_corpus/prepared/holdout.jsonl','overlaps_removed':True},'selection_criteria_predeclared':'On dev only: recall >= 0.95, then minimize FPR; tie-break higher recall then simpler/less permissive cap. Holdout only via single-use --final.','limitations':['Labels are provisional and not human-reviewed.','Enron corpus provenance is a ham proxy, not per-message human adjudication.','Public corpus metrics are not production accuracy; domain shift and label noise remain.']}
 for split,rows in splits.items():
  report['split_sizes'][split]=len(rows); report['class_balance'][split]={k:sum(x['expected_label']==k for x in rows) for k in ('ham','phishing')}; report['source_distribution'][split]={'Nazario phishing corpus 2025':sum(x['expected_label']=='phishing' for x in rows),'CMU Enron Email Dataset':sum(x['expected_label']=='ham' for x in rows)}
 (P/'dataset_report.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
 print('SPLIT_SIZES',json.dumps(report['split_sizes'],sort_keys=True)); print('CLASS_BALANCE',json.dumps(report['class_balance'],sort_keys=True)); print('SOURCE_DISTRIBUTION',json.dumps(report['source_distribution'],sort_keys=True)); print('HOLDOUT_SHA256',hh)
if __name__=='__main__': main()
