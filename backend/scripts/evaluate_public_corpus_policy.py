"""Offline public-corpus model/fusion evaluation with dev-only policy selection."""
from __future__ import annotations
import argparse,csv,hashlib,json,sys,codecs,re
from email import policy
from email.parser import BytesParser
from pathlib import Path
BACKEND_ROOT=Path(__file__).resolve().parents[1]
REPO_ROOT=BACKEND_ROOT.parent
sys.path.insert(0,str(BACKEND_ROOT))
from services.email_ai.inference import load_model,_class_probability
from services.email_ai.features import build_email_text
import services.email_ai.intelligence_fusion as fusion
THRESHOLDS=[0.50,0.55,0.60,0.65,0.70,0.75,0.80,0.85,0.90,0.95]
THREAT_PREDICTIONS={'PHISHING','BEC','CREDENTIAL_THEFT','INVOICE_FRAUD','PAYMENT_DIVERSION','EXECUTIVE_IMPERSONATION','MALWARE_DELIVERY'}
PROTECTIVE_PHRASES=('will never ask you to send a password','will never ask you to send a password or one-time code','do not use links in unexpected messages','never ask you to share your password')
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def parse_email(path):
 msg=BytesParser(policy=policy.default).parsebytes(path.read_bytes()); body=''
 part=msg.get_body(preferencelist=('plain','html')) if msg.is_multipart() else msg
 if part is not None:
  raw=part.get_payload(decode=True); charset=part.get_content_charset() or 'utf-8'
  try: codecs.lookup(charset)
  except LookupError: charset='utf-8'
  body=raw.decode(charset,'replace') if raw else str(part.get_payload() or '')
 headers={str(k).lower().replace('-','_'):str(v) for k,v in msg.items()}
 return {'subject':str(msg.get('subject') or ''),'sender':str(msg.get('from') or ''),'from':str(msg.get('from') or ''),'reply_to':str(msg.get('reply-to') or ''),'body':str(body or ''),'headers':headers,'url_evidence':[],'attachments':[]}
def protective_notice(email):
 text=(str(email.get('subject') or '')+'\n'+str(email.get('body') or '')).lower()
 return (any(p in text for p in PROTECTIVE_PHRASES) and not re.search(r'https?://|\bwww\.',text)
         and not any(p in text for p in ('click here','open this','enter your password','submit your password','provide your password','send your password','verify your account')))
def metrics(rows):
 tp=fp=tn=fn=0
 for r in rows:
  actual=r['expected_label']=='spam'; pred=bool(r['high_risk'])
  if actual and pred: tp+=1
  elif actual: fn+=1
  elif pred: fp+=1
  else: tn+=1
 p=tp/(tp+fp) if tp+fp else None; recall=tp/(tp+fn) if tp+fn else None
 f1=2*p*recall/(p+recall) if p is not None and recall is not None and p+recall else None
 return {'n':tp+fp+tn+fn,'precision':p,'recall':recall,'f1':f1,'fpr':fp/(fp+tn) if fp+tn else None,'confusion_matrix':{'tp':tp,'fp':fp,'tn':tn,'fn':fn}}
def score_row(row,threshold,protective_max):
 fusion.ML_ONLY_HIGH_RISK_MIN_PROBABILITY=threshold
 fusion.PROTECTIVE_NOTICE_MAX_PROBABILITY=protective_max
 result=fusion.analyze_email_intelligence(email=row['_email'],ai_result=row['_ai'],forensic={},threat_intelligence={'iocs':[],'matches':{}},ip_intelligence={})
 return {'score':float(result.get('unified_risk_score') or 0),'high_risk':float(result.get('unified_risk_score') or 0)>=50.0,'independent_category_count':int((result.get('fusion_metrics') or {}).get('independent_category_count') or 0),'risk_tier':result.get('risk_tier')}
def main():
 ap=argparse.ArgumentParser(); ap.add_argument('--prepared',type=Path,default=BACKEND_ROOT/'data'/'public_email_corpus'/'prepared'); ap.add_argument('--out',type=Path,default=BACKEND_ROOT/'reports'/'phase4_holdout'/'public_corpus_eval'); args=ap.parse_args()
 model,manifest=load_model(BACKEND_ROOT/'models'/'email_ai')
 if model is None: raise SystemExit(f'MODEL_NOT_READY {manifest}')
 positive=str(manifest.get('positive_class','PHISHING')); dataset={}
 for split in ('dev','holdout'):
  rows=[]
  for line in (args.prepared/f'{split}.jsonl').read_text(encoding='utf-8').splitlines():
   if not line.strip(): continue
   item=json.loads(line); path=REPO_ROOT/item['email_path']
   if not path.exists(): raise SystemExit(f'MISSING_EMAIL_PATH {path}')
   email=parse_email(path); label,prob,probs=_class_probability(model,build_email_text(email),positive)
   ai={'status':'MODEL_READY','model_ready':True,'classification':label,'model_probability':float(prob),'calibrated_probability':float(prob),'positive_class':positive,'probabilities':probs}
   rows.append({**item,'model_prediction':label,'model_probability':float(prob),'protective_context':protective_notice(email),'_email':email,'_ai':ai})
  dataset[split]=rows
 # BEFORE: evaluate existing fusion policy with the ML-only cap disabled.
 before={}
 for split,rows in dataset.items():
  for row in rows:
   scored=score_row(row,0.0,0.0); row['before_score']=scored['score']; row['before_high_risk']=scored['high_risk']; row['independent_category_count']=scored['independent_category_count']
  before[split]=metrics([{**r,'high_risk':r['before_high_risk']} for r in rows])
 # Select only on dev; do not inspect holdout outcomes during threshold selection.
 candidates=[]
 for threshold in THRESHOLDS:
  scored_rows=[]
  for row in dataset['dev']:
   score=score_row(row,threshold,0.70)
   scored_rows.append({**row,'high_risk':score['high_risk'],'candidate_score':score['score']})
  m=metrics(scored_rows)
  candidates.append({'policy':f'ml_only_probability_threshold_{threshold:.2f}','threshold':threshold,**m,'recall_constraint_met':m['recall'] is not None and m['recall']>=0.95})
 eligible=[c for c in candidates if c['recall_constraint_met']]
 selected=min(eligible,key=lambda c:(c['fpr'] if c['fpr'] is not None else 1.0,-(c['recall'] or 0),c['threshold'])) if eligible else None
 if selected is None: raise SystemExit('NO_POLICY_MEETS_DEV_RECALL_CONSTRAINT; leave production policy unchanged')
 # AFTER: apply the selected dev policy once to holdout.
 threshold=float(selected['threshold']); after={}
 for split,rows in dataset.items():
  if split=='dev':
   scored_rows=[]
   for row in rows:
    score=score_row(row,threshold,0.70); row['after_score']=score['score']; row['after_high_risk']=score['high_risk']
    scored_rows.append({**row,'high_risk':score['high_risk']})
   after[split]=metrics(scored_rows)
  else:
   scored_rows=[]
   for row in rows:
    score=score_row(row,threshold,0.70); row['after_score']=score['score']; row['after_high_risk']=score['high_risk']
    scored_rows.append({**row,'high_risk':score['high_risk']})
   after[split]=metrics(scored_rows)
 # Restore production constants in this process and persist aggregate evidence only.
 fusion.ML_ONLY_HIGH_RISK_MIN_PROBABILITY=0.60; fusion.PROTECTIVE_NOTICE_MAX_PROBABILITY=0.70
 report={'status':'PROVISIONAL_EVALUATION','model_artifact_kind':manifest.get('_artifact_kind'),'model_version':manifest.get('model_version'),'positive_class':positive,'label_quality':'PROVISIONAL: dataset-curator labelled, not human-reviewed by project team','dev_size':len(dataset['dev']),'holdout_size':len(dataset['holdout']),'holdout_sha256':digest(args.prepared/'holdout.jsonl'),'selection_criteria':'Select among dev-only candidates with recall >= 0.95; minimize FPR; tie-break by higher recall then lower threshold. Holdout is not used for selection.','selected_policy':selected,'before':before,'after':after,'candidate_policies_dev':candidates,'limitations':['Source-folder labels are provisional and not human-reviewed by the project team.','Single source family; all messages originate from SpamAssassin.','Holdout has 200 messages (100 per class), so estimates are noisy and should not be treated as a verified benchmark.','Offline fusion evaluation uses model plus content/header fusion only; it omits live provider lookups and the complete production forensics path.']}
 args.out.parent.mkdir(parents=True,exist_ok=True)
 (args.out.with_suffix('.json')).write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
 (args.out.parent/'model_metrics_before_after.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
 with (args.out.parent/'model_metrics_before_after.csv').open('w',newline='',encoding='utf-8') as f:
  w=csv.DictWriter(f,fieldnames=['phase','split','n','precision','recall','f1','fpr','tp','fp','tn','fn','label_quality']);w.writeheader()
  for phase,collection in [('BEFORE',before),('AFTER',after)]:
   for split,m in collection.items():
    cm=m['confusion_matrix'];w.writerow({'phase':phase,'split':split,'n':m['n'],'precision':m['precision'],'recall':m['recall'],'f1':m['f1'],'fpr':m['fpr'],'tp':cm['tp'],'fp':cm['fp'],'tn':cm['tn'],'fn':cm['fn'],'label_quality':report['label_quality']})
 with (args.out.parent/'dev_policy_candidates.csv').open('w',newline='',encoding='utf-8') as f:
  w=csv.DictWriter(f,fieldnames=['policy','threshold','n','precision','recall','f1','fpr','tp','fp','tn','fn','recall_constraint_met']);w.writeheader()
  for c in candidates:
   cm=c['confusion_matrix'];w.writerow({**{k:v for k,v in c.items() if k!='confusion_matrix'},**cm})
 with args.out.with_suffix('.csv').open('w',newline='',encoding='utf-8') as f:
  fields=['split','fixture_id','expected_label','label_quality','model_prediction','model_probability','protective_context','independent_category_count','before_score','before_high_risk','after_score','after_high_risk','sha256']
  w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
  for split,rows in dataset.items():
   for r in rows: w.writerow({'split':split,**{k:r.get(k) for k in fields if k!='split'}})
 print(json.dumps({'dev_size':len(dataset['dev']),'holdout_size':len(dataset['holdout']),'before':before,'selected_policy':selected,'after':after,'holdout_sha256':report['holdout_sha256']},indent=2))
if __name__=='__main__': main()
