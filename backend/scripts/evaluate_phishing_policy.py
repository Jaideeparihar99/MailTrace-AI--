"""Dev-only policy comparison and single-use final evaluation for phishing-specific data."""
from __future__ import annotations
import argparse,csv,hashlib,json,math,sys,codecs,re
from pathlib import Path
from email import policy
from email.parser import BytesParser
B=Path(__file__).resolve().parents[1]; R=B.parent; sys.path.insert(0,str(B))
from services.email_ai.inference import load_model,_class_probability
from services.email_ai.features import build_email_text
import services.email_ai.intelligence_fusion as fusion
THRESHOLDS=[.05,.10,.15,.20,.25,.30,.35,.40,.45,.50,.55,.60]
THREATS={'PHISHING','BEC','CREDENTIAL_THEFT','INVOICE_FRAUD','PAYMENT_DIVERSION','EXECUTIVE_IMPERSONATION','MALWARE_DELIVERY'}
PROTECTIVE=('will never ask you to send a password','will never ask you to send a password or one-time code','do not use links in unexpected messages','never ask you to share your password')
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def parse_email(p):
 m=BytesParser(policy=policy.default).parsebytes(p.read_bytes()); part=m.get_body(preferencelist=('plain','html')) if m.is_multipart() else m; body=''
 if part is not None:
  raw=part.get_payload(decode=True); charset=part.get_content_charset() or 'utf-8'
  try: codecs.lookup(charset)
  except LookupError: charset='utf-8'
  body=raw.decode(charset,'replace') if raw else str(part.get_payload() or '')
 return {'subject':str(m.get('subject') or ''),'sender':str(m.get('from') or ''),'from':str(m.get('from') or ''),'reply_to':str(m.get('reply-to') or ''),'body':body,'headers':{str(k).lower().replace('-','_'):str(v) for k,v in m.items()},'url_evidence':[],'attachments':[]}
def protective(e):
 t=(e.get('subject','')+'\n'+e.get('body','')).lower()
 return any(x in t for x in PROTECTIVE) and not re.search(r'https?://|\bwww\.',t) and not any(x in t for x in ('click here','open this','enter your password','submit your password','provide your password','send your password','verify your account'))
def wilson(k,n,z=1.959963984540054):
 if n<=0:return None
 p=k/n; d=1+z*z/n; c=(p+z*z/(2*n))/d; h=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/d
 return [max(0,c-h),min(1,c+h)]
def metrics(rows,pred_key='pred'):
 tp=fp=tn=fn=0
 for r in rows:
  actual=r['expected_label']=='phishing'; pred=bool(r[pred_key])
  if actual and pred:tp+=1
  elif actual:fn+=1
  elif pred:fp+=1
  else:tn+=1
 p=tp/(tp+fp) if tp+fp else 0; rec=tp/(tp+fn) if tp+fn else 0; f1=2*p*rec/(p+rec) if p+rec else 0; fpr=fp/(fp+tn) if fp+tn else 0
 return {'n':tp+fp+tn+fn,'precision':p,'precision_wilson_95':wilson(tp,tp+fp),'recall':rec,'recall_wilson_95':wilson(tp,tp+fn),'f1':f1,'fpr':fpr,'fpr_wilson_95':wilson(fp,fp+tn),'confusion_matrix':{'tp':tp,'fp':fp,'tn':tn,'fn':fn}}
def make_ai_signal(ai,remove_floor):
 prob=fusion._probability_from_ai(ai); cls=fusion._upper(ai.get('classification'))
 if fusion._upper(ai.get('status')) in {'MODEL_NOT_READY','UNAVAILABLE','ERROR','SKIPPED'}:return None
 if prob<=0 and not cls:return None
 score=prob*100.0
 if not remove_floor and cls in THREATS: score=max(score,82.0)
 return fusion._make_signal('ml','calibrated_ml_probability',score,max(.5,min(.99,prob)),f'AI classification={cls or "UNKNOWN"}; calibrated_probability={prob:.4f}',score>=85.0,'email_ai',.70)
def score(row,policy,threshold=.60):
 original=fusion._ai_signal
 remove_floor=policy in {'proportional','proportional_cap'}
 if policy in {'proportional','proportional_cap'}:
  fusion._ai_signal=lambda ai:make_ai_signal(ai,True)
 else:
  fusion._ai_signal=original
 if policy=='current': cap=.60; pmax=.70
 elif policy=='proportional': cap=0.; pmax=0.
 elif policy=='proportional_cap': cap=.60; pmax=.70
 elif policy=='sweep': cap=threshold; pmax=.70
 else: raise ValueError(policy)
 fusion.ML_ONLY_HIGH_RISK_MIN_PROBABILITY=cap; fusion.PROTECTIVE_NOTICE_MAX_PROBABILITY=pmax
 out=fusion.analyze_email_intelligence(email=row['_email'],ai_result=row['_ai'],forensic={},threat_intelligence={'iocs':[],'matches':{}},ip_intelligence={})
 fusion._ai_signal=original
 return {'score':float(out.get('unified_risk_score') or 0),'pred':float(out.get('unified_risk_score') or 0)>=50,'independent':int((out.get('fusion_metrics') or {}).get('independent_category_count') or 0)}
def load_rows(path,model,manifest,limit=None):
 positive=str(manifest.get('positive_class','PHISHING')); rows=[]
 for line in path.read_text(encoding='utf-8').splitlines():
  if not line.strip():continue
  item=json.loads(line); emailpath=R/item['email_path']
  if not emailpath.exists():raise RuntimeError('Missing email file: '+str(emailpath))
  email=parse_email(emailpath); label,prob,probs=_class_probability(model,build_email_text(email),positive)
  ai={'status':'MODEL_READY','model_ready':True,'classification':label,'model_probability':float(prob),'calibrated_probability':float(prob),'positive_class':positive,'probabilities':probs}
  rows.append({**item,'model_prediction':label,'model_probability':float(prob),'protective_context':protective(email),'_email':email,'_ai':ai})
  if limit and len(rows)>=limit:break
 return rows
def eval_policy(rows,policy,threshold=.60):
 scored=[]
 for r in rows:
  s=score(r,policy,threshold); scored.append({**r,'pred':s['pred'],'risk_score':s['score'],'independent_category_count':s['independent']})
 return metrics(scored),scored
def main():
 ap=argparse.ArgumentParser(); g=ap.add_mutually_exclusive_group(required=True);g.add_argument('--dev',action='store_true');g.add_argument('--smoke',action='store_true');g.add_argument('--final',action='store_true')
 ap.add_argument('--prepared',type=Path,default=B/'data'/'phishing_specific_corpus'/'prepared');args=ap.parse_args(); prep=args.prepared; lock=prep/'final_holdout_run.json'
 model,manifest=load_model(B/'models'/'email_ai')
 if model is None:raise SystemExit('MODEL_NOT_READY')
 if args.final:
  selection=prep/'dev_policy_selection.json'
  if not selection.exists():raise SystemExit('BLOCKED: run --dev and review selection first')
  if lock.exists():raise SystemExit('REPEATED RUN: final holdout already attempted; result must not be rerun or treated as fresh')
  # Atomically claim the one allowed final run before opening holdout rows.
  try:
   with lock.open('x',encoding='utf-8') as f:json.dump({'status':'RUNNING','holdout_sha256':sha(prep/'holdout.jsonl'),'model_version':manifest.get('model_version')},f)
  except FileExistsError:raise SystemExit('REPEATED RUN: final holdout lock exists')
  try:
   chosen=json.loads(selection.read_text(encoding='utf-8')); rows=load_rows(prep/'holdout.jsonl',model,manifest)
   before,br=eval_policy(rows,'current'); policy=chosen['selected_policy']; th=float(chosen.get('selected_threshold',.60)); after,ar=eval_policy(rows,policy,th)
   report={'status':'FINAL_SINGLE_USE_COMPLETED','holdout_sha256':sha(prep/'holdout.jsonl'),'holdout_size':len(rows),'label_quality':'PROVISIONAL: dataset-curator labelled, not human-reviewed','model_version':manifest.get('model_version'),'selected_policy':policy,'selected_threshold':th,'before_current_policy':before,'after_selected_policy':after,'holdout_run_count':1,'limitations':['Provisional corpus provenance labels are not human adjudications.','Public corpus metrics are not production accuracy; domain shift and source-label noise remain.','Wilson intervals quantify binomial sampling uncertainty only, not label or domain uncertainty.']}
   (prep/'final_holdout_metrics.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
   lock.write_text(json.dumps({'status':'COMPLETED','holdout_sha256':report['holdout_sha256'],'model_version':manifest.get('model_version'),'selected_policy':policy,'metrics_file':'final_holdout_metrics.json'},indent=2)+'\n',encoding='utf-8')
   print(json.dumps(report,indent=2))
  except Exception as e:
   lock.write_text(json.dumps({'status':'FAILED_INVALID_SINGLE_USE','error_type':type(e).__name__,'holdout_sha256':sha(prep/'holdout.jsonl')},indent=2)+'\n',encoding='utf-8');raise
  return

 if args.smoke:
  rows=load_rows(prep/'dev.jsonl',model,manifest,limit=10); m,sc=eval_policy(rows,'current'); print(json.dumps({'mode':'DEV_SMOKE_ONLY','n':len(rows),'metrics':m},indent=2));return
 rows=load_rows(prep/'dev.jsonl',model,manifest); candidates=[]
 m,sc=eval_policy(rows,'current'); candidates.append({'policy':'current','threshold':.60,**m,'recall_constraint_met':m['recall']>=.95})
 m,sc=eval_policy(rows,'proportional'); candidates.append({'policy':'proportional','threshold':0.,**m,'recall_constraint_met':m['recall']>=.95})
 m,sc=eval_policy(rows,'proportional_cap'); candidates.append({'policy':'proportional_cap','threshold':.60,**m,'recall_constraint_met':m['recall']>=.95})
 for th in THRESHOLDS:
  m,sc=eval_policy(rows,'sweep',th);candidates.append({'policy':'sweep','threshold':th,**m,'recall_constraint_met':m['recall']>=.95})
 eligible=[c for c in candidates if c['recall_constraint_met']]
 selected=min(eligible,key=lambda c:(c['fpr'],-c['recall'],c['threshold'])) if eligible else None
 report={'status':'DEV_ONLY_POLICY_SELECTION','dev_size':len(rows),'label_quality':'PROVISIONAL: dataset-curator labelled, not human-reviewed','selection_criteria':'Require recall >= 0.95; minimize FPR; tie-break higher recall then lower threshold. Holdout is not opened.','candidates':candidates,'selected_policy':selected['policy'] if selected else None,'selected_threshold':selected['threshold'] if selected else None,'holdout_opened':False}
 prep.mkdir(parents=True,exist_ok=True);(prep/'dev_policy_selection.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
 with (prep/'dev_policy_candidates.csv').open('w',newline='',encoding='utf-8') as f:
  fields=['policy','threshold','n','precision','precision_wilson_95','recall','recall_wilson_95','f1','fpr','fpr_wilson_95','tp','fp','tn','fn','recall_constraint_met'];w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
  for c in candidates:w.writerow({**{k:v for k,v in c.items() if k!='confusion_matrix'},**c['confusion_matrix']})
 print(json.dumps(report,indent=2))
if __name__=='__main__':main()
