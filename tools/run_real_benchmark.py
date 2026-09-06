"""Standalone real-data DGA benchmark for DNSentinel — no repo imports needed.

Usage:
  python run_real_benchmark.py <dga_domains_full.csv> [<training_csv>]

- <dga_domains_full.csv> : chrmor-style headerless CSV  (class,family,domain ; class in {legit,dga})
- <training_csv>         : the project's bundled data (default: data/dns_exfiltration_dataset.csv
                           relative to this script's folder, with a 'domain'+'label' header)
"""
import csv, math, os, re, sys, random
from collections import Counter
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, roc_auc_score, confusion_matrix)

# ---- feature extraction (identical to backend/features.py) -----------------
ENGLISH_BIGRAMS = {'er':0.05,'th':0.05,'in':0.04,'on':0.03,'an':0.03,'re':0.02,'nd':0.02,
 'at':0.02,'en':0.02,'es':0.02,'of':0.02,'te':0.02,'ed':0.02,'or':0.01,'ti':0.01,'al':0.01,
 'is':0.01,'ng':0.01,'co':0.02,'om':0.03,'ne':0.01,'et':0.01,'it':0.01}

def entropy(d):
    if not d: return 0
    probs=[n/len(d) for n in Counter(d).values()]
    return -sum(p*math.log2(p) for p in probs)

def ngram(d,n=2):
    if not d or len(d)<n: return 0.01
    d=d.lower(); grams=[d[i:i+n] for i in range(len(d)-n+1)]
    return sum(ENGLISH_BIGRAMS.get(g,0.0001) for g in grams)/len(grams)

def maxrun(text,pat):
    m=re.findall(pat,text); return max((len(x) for x in m),default=0)

def maxsame(text):
    if not text: return 0
    mx=cur=1
    for i in range(1,len(text)):
        if text[i]==text[i-1]: cur+=1; mx=max(mx,cur)
        else: cur=1
    return mx

def feats(query):
    q=query; ql=q.lower(); parts=ql.split('.')
    sub=parts[0] if len(parts)>2 else ''
    e=entropy(q); length=len(q) if q else 0
    cons=re.findall(r'[^aeiou0-9.-]',ql); vow=re.findall(r'[aeiou]',ql)
    safe=length if length>0 else 1
    return {
      'entropy':e,'length':length,'subdomain_length':len(sub),'ngram_score':ngram(q),
      'frequency':1,
      'consonant_ratio':len(cons)/(length or 1),'digit_ratio':len(re.findall(r'[0-9]',ql))/(length or 1),
      'unique_char':len(set(ql))/(length or 1),
      'vowels_consonant_ratio':(len(vow)/len(cons)) if cons else 0,
      'max_continuous_numeric_len':maxrun(ql,r'[0-9]+'),'max_continuous_alphabet_len':maxrun(ql,r'[a-z]+'),
      'max_continuous_consonants_len':maxrun(ql,r'[^aeiou0-9.-]+'),
      'max_continuous_same_char':maxsame(re.sub(r'[^a-z]','',ql)),
      'upper_count':len(re.findall(r'[A-Z]',q)),'lower_count':len(re.findall(r'[a-z]',q)),
      'special_count':len(re.findall(r'[^a-zA-Z0-9]',q)),
      'labels':len(parts),'labels_max':max((len(p) for p in parts),default=0),
      'labels_average':sum(len(p) for p in parts)/(len(parts) or 1),
      'entropy_to_length_ratio':e/safe,'high_entropy_flag':1 if e>3.8 else 0,
      'domain_complexity':(safe*e)-(ngram(q)*10),
    }

ORDER=['entropy','length','subdomain_length','ngram_score','frequency','consonant_ratio',
 'digit_ratio','unique_char','vowels_consonant_ratio','max_continuous_numeric_len',
 'max_continuous_alphabet_len','max_continuous_consonants_len','max_continuous_same_char',
 'upper_count','lower_count','special_count','labels','labels_max','labels_average',
 'entropy_to_length_ratio','high_entropy_flag','domain_complexity']

def vec(dom):
    f=feats(dom); return [f[k] for k in ORDER]

def rf():
    return RandomForestClassifier(n_estimators=300,max_depth=30,min_samples_split=10,random_state=42)

def load_training(path):
    X,y=[],[]
    with open(path,encoding='utf-8',errors='ignore') as fh:
        for r in csv.DictReader(fh):
            q=(r.get('domain') or r.get('query') or '').strip()
            if not q: continue
            X.append(vec(q)); y.append(int(r.get('label',0)))
    return np.array(X,float),np.array(y,int)

def load_real(path,cap=25000):
    benign,mal=[],[]
    with open(path,encoding='utf-8',errors='ignore') as fh:
        for row in csv.reader(fh):
            if len(row)<3: continue
            cls,fam,dom=row[0].strip().lower(),row[1].strip(),row[2].strip().lower()
            if '.' not in dom: continue
            (benign if cls=='legit' else mal).append((dom,0 if cls=='legit' else 1,fam))
    random.seed(42); random.shuffle(benign); random.shuffle(mal)
    n=min(len(benign),len(mal),cap); rows=benign[:n]+mal[:n]; random.shuffle(rows)
    X=np.array([vec(d) for d,_,_ in rows],float); y=np.array([l for _,l,_ in rows],int)
    fam=np.array([f for _,_,f in rows]); return X,y,fam,n

def rpt(tag,yt,yp,pr=None):
    auc=f" auc={roc_auc_score(yt,pr):.3f}" if pr is not None and len(set(yt))==2 else ""
    print(f"{tag:<28} acc={accuracy_score(yt,yp):.3f} prec={precision_score(yt,yp,zero_division=0):.3f} "
          f"rec={recall_score(yt,yp,zero_division=0):.3f} f1={f1_score(yt,yp,zero_division=0):.3f}{auc}")
    print(f"{'':<28} confusion [[TN,FP],[FN,TP]] = {confusion_matrix(yt,yp).tolist()}")

def main():
    if len(sys.argv)<2:
        print("usage: python run_real_benchmark.py <dga_domains_full.csv> [training_csv]"); return
    dga=sys.argv[1]
    here=os.path.dirname(os.path.abspath(__file__))
    train=sys.argv[2] if len(sys.argv)>2 else os.path.join(here,"data","dns_exfiltration_dataset.csv")
    print(f"[*] training data: {train}")
    print(f"[*] real benchmark: {dga}\n")
    Xtr,ytr=load_training(train)
    Xb,yb,fam,n=load_real(dga)
    print(f"real benchmark: {len(yb)} rows ({n} benign / {n} malicious across {len(set(fam[yb==1]))} DGA families)\n")

    clf=rf().fit(Xtr,ytr)
    yp=clf.predict(Xb); pr=clf.predict_proba(Xb)[:,1]
    rpt("CROSS-DOMAIN (bundled->real)",yb,yp,pr)

    print("\nper-DGA-family recall (cross-domain model):")
    for f in sorted(set(fam[yb==1])):
        m=(fam==f)&(yb==1)
        print(f"  {str(f):<16} recall={recall_score(yb[m],yp[m],zero_division=0):.3f}  (n={int(m.sum())})")
    bm=fam=='legit'
    if bm.sum(): print(f"  benign FP-rate={ (yp[bm]==1).mean():.3f}  (n={int(bm.sum())})")

    Xt,Xe,yt,ye=train_test_split(Xb,yb,test_size=0.2,stratify=yb,random_state=42)
    c2=rf().fit(Xt,yt); p2=c2.predict(Xe); pr2=c2.predict_proba(Xe)[:,1]
    print(); rpt("IN-BENCHMARK (80/20 split)",ye,p2,pr2)

if __name__=="__main__":
    main()
