"""SQLite-backed bounded-memory Step 27 leakage audit; emits metadata only."""
from __future__ import annotations
import argparse, collections, datetime, gc, hashlib, itertools, json, os, re, sqlite3, tempfile, time, unicodedata
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
DATA=ROOT/'backend/data/email_ai/normalized/meajor_phishing_binary.jsonl'
OUTJ=ROOT/'backend/data/email_ai/metadata/step27_full_dataset_leakage_audit.v1.json'
OUTM=ROOT/'backend/data/email_ai/metadata/step27_full_dataset_leakage_audit.v1.md'
VERSION='mailtrace-step27-sqlite-leakage-v1'; THRESHOLD=.80; BUCKET_CAP=250

def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
 return h.hexdigest()
def exact_norm(s): return re.sub(r'\s+',' ',s).strip().casefold()
def near_norm(s): return re.sub(r'\s+',' ',''.join(c for c in unicodedata.normalize('NFKC',s) if unicodedata.category(c)!='Cf')).strip().casefold()
def toks(s): return sorted(set(re.findall(r'[a-z0-9]+',s)))
def simhash(ts):
 if len(ts)<4:return None
 w=[0]*64
 for t in ts:
  v=int.from_bytes(hashlib.blake2b(t.encode(),digest_size=8).digest(),'big')
  for i in range(64):w[i]+=1 if (v>>i)&1 else -1
 return sum(1<<i for i,x in enumerate(w) if x>=0)
def canon(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True)
def run(dataset,outj,outm,pair_cap,max_seconds,max_db_bytes,cache_kib):
 started=time.monotonic(); utc=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds').replace('+00:00','Z'); dataset=dataset.resolve(); h0=sha(dataset); size=dataset.stat().st_size
 src=collections.Counter(); cls=collections.defaultdict(collections.Counter); empty=malformed=invalid=processed=0; expected_records=sum(1 for line in dataset.open(encoding='utf-8-sig') if line.strip()); err=None; timehit=diskhit=pairhit=False; overs=[]; bucketdist=collections.Counter(); candidates=comparisons=failed=confirmed=cross=0; affected=collections.Counter()
 td=tempfile.TemporaryDirectory(prefix='mailtrace-step27-'); dbpath=Path(td.name)/'audit.sqlite3'; db=None
 try:
  db=sqlite3.connect(str(dbpath)); db.execute('PRAGMA journal_mode=OFF'); db.execute('PRAGMA synchronous=OFF'); db.execute('PRAGMA temp_store=FILE'); db.execute(f'PRAGMA cache_size=-{cache_kib}'); db.execute('PRAGMA mmap_size=0')
  db.executescript('CREATE TABLE r(id INTEGER PRIMARY KEY,source TEXT,label TEXT,ex TEXT,nh TEXT,tokens TEXT,sig TEXT); CREATE INDEX rex ON r(ex); CREATE TABLE reps(id INTEGER PRIMARY KEY,nh TEXT,tokens TEXT,sig TEXT,sources TEXT,labels TEXT,n INTEGER); CREATE TABLE b(band INTEGER,val INTEGER,rid INTEGER); CREATE INDEX bb ON b(band,val,rid); CREATE TABLE c(a INTEGER,b INTEGER,PRIMARY KEY(a,b));')
  if max_seconds <= 0:timehit=True;err='runtime limit is zero or negative'
  with dataset.open(encoding='utf-8-sig') as f:
   for line_no,line in enumerate(f,1):
    if err is not None:break
    if time.monotonic()-started>max_seconds:timehit=True;err='runtime limit during ingest';break
    if not line.strip():empty+=1;continue
    try: row=json.loads(line)
    except json.JSONDecodeError:malformed+=1;err=f'malformed JSONL at line {line_no}';break
    if not isinstance(row,dict):invalid+=1;err=f'non-object JSONL at line {line_no}';break
    text=row.get('text'); label=str(row.get('label') or '').strip().upper(); source=str(row.get('source_group') or row.get('source') or '').strip().casefold()
    if not isinstance(text,str) or not text.strip() or label not in ('LEGITIMATE','PHISHING') or not source:invalid+=1;err=f'invalid required fields at line {line_no}';break
    ex=hashlib.sha256(exact_norm(text).encode()).hexdigest(); norm=near_norm(text); ts=toks(norm); sh=simhash(ts); rid=processed+1
    db.execute('INSERT INTO r VALUES(?,?,?,?,?,?,?)',(rid,source,label,ex,hashlib.sha256(norm.encode()).hexdigest(),json.dumps(ts,separators=(',',':')),None if sh is None else f'{sh:016x}'))
    processed+=1;src[source]+=1;cls[source][label]+=1
    if processed%500==0:
     db.commit()
     if sum(p.stat().st_size for p in dbpath.parent.glob(dbpath.name+'*') if p.is_file())>max_db_bytes:diskhit=True;err='SQLite size limit during ingest';break
  db.commit()
  if err is None and sum(p.stat().st_size for p in dbpath.parent.glob(dbpath.name+'*') if p.is_file())>max_db_bytes:diskhit=True;err='SQLite size limit during ingest'
  exgroups=exexcess=exconf=excros=excrossex=0
  if err is None:
   db.execute('INSERT INTO reps SELECT r.id,r.nh,r.tokens,r.sig,(SELECT json_group_array(source) FROM (SELECT DISTINCT source FROM r q WHERE q.nh=r.nh ORDER BY source)),(SELECT json_group_array(label) FROM (SELECT DISTINCT label FROM r q WHERE q.nh=r.nh ORDER BY label)),g.n FROM r JOIN (SELECT nh,MIN(id) minid,COUNT(*) n FROM r GROUP BY nh) g ON g.minid=r.id')
   db.commit()
   for rid,sig in db.execute('SELECT id,sig FROM reps WHERE sig IS NOT NULL ORDER BY id'):
    value=int(sig,16)
    for band in range(8):db.execute('INSERT INTO b VALUES(?,?,?)',(band,(value>>(band*8))&255,rid))
   db.commit()
   q=db.execute('SELECT SUM(n>1),SUM(CASE WHEN n>1 THEN n-1 ELSE 0 END),SUM(CASE WHEN n>1 AND labels>1 THEN 1 ELSE 0 END),SUM(CASE WHEN n>1 AND sources>1 THEN 1 ELSE 0 END),SUM(CASE WHEN n>1 AND sources>1 THEN n-1 ELSE 0 END) FROM (SELECT ex,COUNT(*) n,COUNT(DISTINCT label) labels,COUNT(DISTINCT source) sources FROM r GROUP BY ex)').fetchone()
   exgroups,exexcess,exconf,excros,excrossex=[int(x or 0) for x in q]
   # Every primary bucket is counted. Oversized primary buckets are subdivided by a second band in SQL.
   buckets=db.execute('SELECT band,val,COUNT(*) n FROM b GROUP BY band,val ORDER BY band,val')
   for band,val,n in buckets:
    if time.monotonic()-started>max_seconds:timehit=True;err='runtime limit during candidate generation';break
    bucketdist[n]+=1
    if n<2:continue
    if n<=BUCKET_CAP:
     groups=[(None,n)]
    else:
     second=(band+4)%8
     groups=list(db.execute('SELECT b2.val,COUNT(*) n FROM b b1 JOIN b b2 ON b2.rid=b1.rid AND b2.band=? WHERE b1.band=? AND b1.val=? GROUP BY b2.val ORDER BY b2.val',(second,band,val)))
    for subval,subn in groups:
     if subn>BUCKET_CAP:
      overs.append({'primary_band':band,'primary_value':val,'refinement_band':None if subval is None else (band+4)%8,'refinement_value':subval,'members':subn,'potential_pairs_not_compared':subn*(subn-1)//2});continue
     if subn<2:continue
     if subval is None: ids=[x[0] for x in db.execute('SELECT rid FROM b WHERE band=? AND val=? ORDER BY rid',(band,val))]
     else: ids=[x[0] for x in db.execute('SELECT b1.rid FROM b b1 JOIN b b2 ON b2.rid=b1.rid AND b2.band=? WHERE b1.band=? AND b1.val=? AND b2.val=? ORDER BY b1.rid',((band+4)%8,band,val,subval))]
     for a,b in itertools.combinations(ids,2):
      if candidates>=pair_cap and not db.execute('SELECT 1 FROM c WHERE a=? AND b=?',(a,b)).fetchone():
       pairhit=True;err='candidate pair cap reached';break
      curins=db.execute('INSERT OR IGNORE INTO c VALUES(?,?)',(a,b))
      if curins.rowcount>0:candidates+=1
      if time.monotonic()-started>max_seconds:timehit=True;err='runtime limit during candidate pair insertion';break
     db.commit()
     if sum(p.stat().st_size for p in dbpath.parent.glob(dbpath.name+'*') if p.is_file())>max_db_bytes:diskhit=True;err='SQLite size limit during candidate generation';break
     if pairhit or timehit:break
    if pairhit or timehit or diskhit:break
    if sum(p.stat().st_size for p in dbpath.parent.glob(dbpath.name+'*') if p.is_file())>max_db_bytes:diskhit=True;err='SQLite size limit during candidate generation';break
   candidates=db.execute('SELECT COUNT(*) FROM c').fetchone()[0]
  if err is None:
   cur=db.execute('SELECT c.a,c.b,ra.tokens,rb.tokens,ra.sources,rb.sources FROM c JOIN reps ra ON ra.id=c.a JOIN reps rb ON rb.id=c.b ORDER BY c.a,c.b')
   while True:
    if time.monotonic()-started>max_seconds:timehit=True;err='runtime limit during pair comparison';break
    batch=cur.fetchmany(500)
    if not batch:break
    for a,b,ta,tb,sa,sb in batch:
     try:
      A=set(json.loads(ta));B=set(json.loads(tb));u=A|B;score=len(A&B)/len(u) if u else 0.0;comparisons+=1
      if score>=THRESHOLD:
       confirmed+=1
       source_set=sorted(set(json.loads(sa)+json.loads(sb)))
       if len(source_set)>1:
        cross+=1
        for family in source_set:affected[family]+=1
     except Exception:failed+=1
    if failed:err='candidate comparison failed';break
  h1=sha(dataset)
  if h0!=h1:err='dataset changed during audit'
  unprocessed=max(0,expected_records-processed)
  families=sorted(src);parts=[]
  for held in families:
   tr={lab:sum(cls[s][lab] for s in families if s!=held) for lab in ('LEGITIMATE','PHISHING')};ho=dict(cls[held]);trn=sum(src[s] for s in families if s!=held);hon=src[held]
   valid=bool(trn and hon and all(tr[k]>0 for k in tr) and all(ho.get(k,0)>0 for k in ('LEGITIMATE','PHISHING')) and held not in [s for s in families if s!=held])
   parts.append({'holdout_source':held,'training_sources':[s for s in families if s!=held],'training_rows':trn,'training_class_counts':tr,'holdout_rows':hon,'holdout_class_counts':ho,'valid':valid})
  status='COMPLETE' if err is None and malformed==0 and invalid==0 and unprocessed==0 and failed==0 and not overs and h0==h1 and parts and all(p['valid'] for p in parts) else ('FAILED' if malformed or invalid or failed or h0!=h1 else 'INCOMPLETE')
  evidence={'schema_version':'1.0.0','audit_version':VERSION,'status':status,'generated_at_utc':utc,'configuration':{'exact_normalization':'strip; collapse whitespace; casefold; preserve punctuation','near_normalization':'NFKC; remove Unicode Cf; collapse whitespace; strip; casefold; exact near-text copies collapsed to first row representative','tokenizer':'unique ASCII alphanumeric tokens [a-z0-9]+','simhash':'64-bit; BLAKE2b digest_size=8; sorted unique tokens','bands':8,'bits_per_band':8,'refinement':'second band (band+4)%8 for primary buckets >250','bucket_cap':BUCKET_CAP,'jaccard_threshold':THRESHOLD,'candidate_pair_cap':pair_cap,'max_runtime_seconds':max_seconds,'max_sqlite_bytes':max_db_bytes,'sqlite_cache_kib':cache_kib,'deterministic_order':'record ID, band, bucket, pair ascending'},'dataset':{'path':str(dataset.relative_to(ROOT)) if dataset.is_relative_to(ROOT) else str(dataset),'size_bytes':size,'sha256_before':h0,'sha256_after':h1,'hash_stable':h0==h1,'records_processed':processed,'record_count':expected_records,'empty_lines':empty,'malformed_records':malformed,'invalid_records':invalid,'unprocessed_records':unprocessed},'source_family_class_counts':{s:{'rows':src[s],'class_counts':dict(sorted(cls[s].items()))} for s in families},'exact_duplicate_audit':{'duplicate_groups':exgroups,'excess_rows':exexcess,'conflicting_label_groups':exconf,'cross_source_duplicate_groups':excros,'cross_source_excess_rows':excrossex,'normalization':'strip + collapse whitespace + casefold; preserve punctuation'},'near_duplicate_audit':{'status':'COMPLETE_FOR_CANDIDATE_POLICY' if err is None and not overs else 'INCOMPLETE','candidate_pairs':candidates,'comparisons_attempted':comparisons,'comparisons_failed':failed,'confirmed_pairs_jaccard_gte_threshold':confirmed,'confirmed_cross_source_pairs':cross,'affected_source_family_pair_counts':dict(sorted(affected.items())),'candidate_bucket_size_distribution':{str(k):v for k,v in sorted(bucketdist.items())},'oversized_bucket_count':len(overs),'oversized_buckets':overs,'potential_pairs_excluded_due_to_oversized_buckets':sum(x['potential_pairs_not_compared'] for x in overs),'unaccounted_skipped_pairs':0,'threshold':THRESHOLD,'limitations':['SimHash banding is approximate and may miss pairs that share no band.','Token-set Jaccard discards token order, punctuation, and non-ASCII tokens.']},'source_grouped_partitions':{'strategy':'leave-one-source-family-out','partition_count':len(parts),'partitions':parts,'all_partitions_valid':bool(parts) and all(p['valid'] for p in parts)},'resource_limits':{'max_runtime_seconds':max_seconds,'runtime_limit_reached':timehit,'max_sqlite_bytes':max_db_bytes,'disk_limit_reached':diskhit,'candidate_pair_cap':pair_cap,'candidate_pair_limit_reached':pairhit,'sqlite_cache_kib':cache_kib,'temporary_db_bytes_at_end':dbpath.stat().st_size if dbpath.exists() else 0},'coverage':{'error':err,'unprocessed_records':unprocessed,'malformed_records':malformed,'invalid_records':invalid,'failed_comparisons':failed,'runtime_limit_reached':timehit,'disk_limit_reached':diskhit,'pair_limit_reached':pairhit,'training_performed':False},'limitations':['Approximate SimHash candidate generation is not proof of absence of semantic near duplicates.','No campaign/thread/timestamp isolation is claimed.'],'duration_seconds':round(time.monotonic()-started,3)}
  outj.parent.mkdir(parents=True,exist_ok=True);tmp=outj.with_suffix(outj.suffix+'.tmp');tmp.write_text(json.dumps(evidence,indent=2,sort_keys=True)+'\n',encoding='utf-8');os.replace(tmp,outj)
  e=evidence['exact_duplicate_audit'];n=evidence['near_duplicate_audit'];lines=['# Step 27 SQLite-backed full-dataset leakage audit','',f"- **Status:** {status}",f"- **Audit version:** {VERSION}",f"- **UTC:** {utc}",f"- **Dataset:** `{evidence['dataset']['path']}`",f"- **Bytes:** {size:,}",f"- **Records processed:** {processed:,}",f"- **SHA-256:** `{h0}`",f"- **Duration:** {evidence['duration_seconds']} seconds",f"- **Error:** {err or 'none'}",'','## Source/class counts','','| Source | Rows | Legitimate | Phishing |','|---|---:|---:|---:|']
  for s,v in evidence['source_family_class_counts'].items():lines.append(f"| {s} | {v['rows']:,} | {v['class_counts'].get('LEGITIMATE',0):,} | {v['class_counts'].get('PHISHING',0):,} |")
  lines+=['','## Exact duplicates',f"- Groups: {e['duplicate_groups']}; excess rows: {e['excess_rows']}; conflicting-label groups: {e['conflicting_label_groups']}.",f"- Cross-source groups / excess rows: {e['cross_source_duplicate_groups']} / {e['cross_source_excess_rows']}.",'','## Near duplicates',f"- Candidate pairs: {candidates:,}; comparisons attempted: {comparisons:,}; confirmed pairs: {confirmed:,}; cross-source confirmed pairs: {cross:,}.",f"- Oversized buckets: {len(overs)}; potential pairs excluded: {sum(x['potential_pairs_not_compared'] for x in overs):,}; unaccounted skipped pairs: 0.",f"- Candidate bucket-size distribution: `{canon(n['candidate_bucket_size_distribution'])}`",'','## Coverage',f"- Unprocessed records: {unprocessed}; malformed: {malformed}; invalid: {invalid}; failed comparisons: {failed}.",f"- Runtime/disk/pair limits reached: {timehit}/{diskhit}/{pairhit}.",'- COMPLETE is forbidden if any error, excluded oversized bucket, failed comparison, changed input, or unprocessed record exists.','- Only aggregate metadata is persisted; raw email content is not written to the audit artifacts.','']
  tmp=outm.with_suffix(outm.suffix+'.tmp');tmp.write_text('\n'.join(lines),encoding='utf-8');os.replace(tmp,outm);return evidence
 except Exception as exc:
  failure={'schema_version':'1.0.0','audit_version':VERSION,'status':'FAILED','generated_at_utc':utc,'dataset':{'path':str(dataset),'size_bytes':size,'sha256_before':h0,'records_processed_before_failure':processed,'unprocessed_records_estimate':max(0,expected_records-processed),'expected_nonempty_lines':expected_records},'coverage':{'error_type':type(exc).__name__,'error_message':str(exc)[:300],'incomplete':True,'training_performed':False},'configuration':{'max_candidate_pairs':pair_cap,'max_runtime_seconds':max_seconds,'max_sqlite_bytes':max_db_bytes,'sqlite_cache_kib':cache_kib},'limitations':['Audit aborted due to an execution/database error; no complete coverage is claimed.']}
  outj.parent.mkdir(parents=True,exist_ok=True);tmp=outj.with_suffix(outj.suffix+'.tmp');tmp.write_text(json.dumps(failure,indent=2,sort_keys=True)+'\n',encoding='utf-8');os.replace(tmp,outj)
  outm.parent.mkdir(parents=True,exist_ok=True);tmp=outm.with_suffix(outm.suffix+'.tmp');tmp.write_text('# Step 27 SQLite-backed full-dataset leakage audit\n\n- **Status:** FAILED\n- **UTC:** '+utc+'\n- **Records processed before failure:** '+str(processed)+'\n- **Unprocessed estimate:** '+str(max(0,expected_records-processed))+'\n- **Error:** '+type(exc).__name__+': '+str(exc)[:300]+'\n- Partial execution is not complete evidence.\n',encoding='utf-8');os.replace(tmp,outm)
  return failure
 finally:
  # Explicitly close streaming cursors before deleting the temporary SQLite database (required on Windows).
  for cursor_name in ('buckets','cur'):
   cursor=locals().get(cursor_name)
   if cursor is not None:
    try: cursor.close()
    except Exception: pass
  if db is not None:
   db.close();db=None
  gc.collect()
  td.cleanup()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--dataset',type=Path,default=DATA);ap.add_argument('--output-json',type=Path,default=OUTJ);ap.add_argument('--output-md',type=Path,default=OUTM);ap.add_argument('--max-candidate-pairs',type=int,default=2_000_000);ap.add_argument('--max-seconds',type=int,default=900);ap.add_argument('--max-db-bytes',type=int,default=4*1024**3);ap.add_argument('--sqlite-cache-kib',type=int,default=65536);a=ap.parse_args()
 r=run(a.dataset,a.output_json,a.output_md,a.max_candidate_pairs,a.max_seconds,a.max_db_bytes,a.sqlite_cache_kib)
 print(canon({'status':r['status'],'sha256':r['dataset']['sha256_before'],'records':r['dataset']['records_processed'],'exact_groups':r['exact_duplicate_audit']['duplicate_groups'],'exact_excess':r['exact_duplicate_audit']['excess_rows'],'exact_cross_source':r['exact_duplicate_audit']['cross_source_duplicate_groups'],'candidate_pairs':r['near_duplicate_audit']['candidate_pairs'],'comparisons':r['near_duplicate_audit']['comparisons_attempted'],'confirmed':r['near_duplicate_audit']['confirmed_pairs_jaccard_gte_threshold'],'cross_source_confirmed':r['near_duplicate_audit']['confirmed_cross_source_pairs'],'oversized_buckets':r['near_duplicate_audit']['oversized_bucket_count'],'error':r['coverage']['error'],'duration_seconds':r['duration_seconds'],'json':str(a.output_json),'markdown':str(a.output_md)}));return 0 if r['status']=='COMPLETE' else 2
if __name__=='__main__':raise SystemExit(main())
