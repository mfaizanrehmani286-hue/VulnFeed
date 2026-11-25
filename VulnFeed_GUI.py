# VulnFeed - Your Own CVE Tracker
# Student: M. Faizan | PNY Trainings | Instructor: Abdul Mannan
# Public feeds only - Never scans any target. Respects NVD rate limits.
import json, os, sqlite3, csv, time, threading, tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
from datetime import datetime, timedelta, timezone
import urllib.request, urllib.parse, urllib.error

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DB = "vulnfeed.db"
WATCHLIST_FILE = "watchlist.json"
REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "UNKNOWN": 5}

# ---------- DB ----------
def init_db():
    con = sqlite3.connect(DB); cur = con.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS cves(
        cve_id TEXT PRIMARY KEY, published TEXT, modified TEXT,
        description TEXT, score REAL, severity TEXT, refs TEXT, matched TEXT)""")
    con.commit(); con.close()

def load_watchlist():
    if not os.path.exists(WATCHLIST_FILE):
        data = [{"vendor":"microsoft","product":"windows","version":""},{"vendor":"apache","product":"log4j","version":""}]
        json.dump(data, open(WATCHLIST_FILE,"w"), indent=2)
    return json.load(open(WATCHLIST_FILE))

def save_watchlist(data):
    json.dump(data, open(WATCHLIST_FILE,"w"), indent=2)

# ---------- NVD ----------
def nvd_request(params, api_key, log):
    headers = {"User-Agent":"VulnFeed/1.0"}
    if api_key: headers["apiKey"] = api_key
    for attempt in range(3):
        try:
            url = API + "?" + urllib.parse.urlencode(params)
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            if e.code in (429,500,502,503,504):
                wait = 6 if e.code==429 else 3
                log(f"HTTP {e.code} - {wait}s wait, retry {attempt+1}/3...")
                time.sleep(wait); continue
            raise Exception(f"NVD Error HTTP {e.code}: {e.read().decode()[:200]}")
        except Exception as e:
            if attempt<2: time.sleep(2); continue
            raise e
    raise Exception("NVD unreachable after retries")

def parse_cve(v):
    c = v.get("cve",{})
    cid = c.get("id","?")
    desc = ""
    for d in c.get("descriptions",[]):
        if d.get("lang")=="en": desc=d.get("value","")
    metrics = c.get("metrics",{})
    score, sev = 0.0, "UNKNOWN"
    if "cvssMetricV31" in metrics:
        m = metrics["cvssMetricV31"][0]["cvssData"]
        score, sev = float(m.get("baseScore",0)), m.get("baseSeverity","UNKNOWN")
    elif "cvssMetricV30" in metrics:
        m = metrics["cvssMetricV30"][0]["cvssData"]
        score, sev = float(m.get("baseScore",0)), m.get("baseSeverity","UNKNOWN")
    elif "cvssMetricV2" in metrics:
        m = metrics["cvssMetricV2"][0]["cvssData"]
        score, sev = float(m.get("baseScore",0)), m.get("baseSeverity","UNKNOWN")
    refs = ", ".join([r.get("url","") for r in c.get("references",[])][:5])
    cpes = []
    for conf in c.get("configurations",[]):
        for node in conf.get("nodes",[]):
            for m in node.get("cpeMatch",[]):
                cpes.append(m.get("criteria",""))
    return {"id":cid,"published":c.get("published",""),"modified":c.get("lastModified",""),
            "desc":desc,"score":score,"severity":sev.upper(),"refs":refs,"cpes":cpes,"raw_desc":desc.lower(),"cpe_text":" ".join(cpes).lower()}

def match_watchlist(parsed, watchlist, use_cpe):
    matched=[]
    for w in watchlist:
        prod = w.get("product","").lower(); vend = w.get("vendor","").lower()
        if use_cpe:
            if prod in parsed["cpe_text"] or vend in parsed["cpe_text"]: matched.append(f"{w.get('vendor')} {w.get('product')}")
        else:
            if prod in parsed["raw_desc"] or vend in parsed["raw_desc"]: matched.append(f"{w.get('vendor')} {w.get('product')}")
    return matched

# ---------- GUI ----------
class App(tk.Tk):
    def __init__(self):
        super().__init__(); self.title("VulnFeed - CVE Tracker | M. Faizan | PNY Trainings"); self.geometry("1100x700")
        init_db(); self.watchlist = load_watchlist(); self.results=[]; self.api_key_var=tk.StringVar(); self.api_key_var.set(os.getenv("NVD_API_KEY",""))
        self.build()

    def build(self):
        top = ttk.Frame(self, padding=10); top.pack(fill="x")
        ttk.Label(top, text="VulnFeed - CVE Tracker", font=("Arial",16,"bold")).pack(side="left")
        ttk.Label(top, text="  Public Feeds Only | No Scanning", foreground="green").pack(side="left")
        # Controls
        f = ttk.LabelFrame(self, text="Search NVD API 2.0", padding=8); f.pack(fill="x", padx=10)
        ttk.Label(f, text="CVE ID:").grid(row=0,column=0,sticky="w"); self.e_cve=ttk.Entry(f,width=22); self.e_cve.grid(row=0,column=1,padx=5)
        ttk.Label(f, text="Keyword:").grid(row=0,column=2); self.e_kw=ttk.Entry(f,width=22); self.e_kw.grid(row=0,column=3,padx=5)
        ttk.Label(f, text="Min Severity:").grid(row=0,column=4); self.cb_sev=ttk.Combobox(f, values=["LOW","MEDIUM","HIGH","CRITICAL"], width=10); self.cb_sev.set("HIGH"); self.cb_sev.grid(row=0,column=5,padx=5)
        ttk.Label(f, text="Days:").grid(row=0,column=6); self.e_days=ttk.Entry(f,width=6); self.e_days.insert(0,"7"); self.e_days.grid(row=0,column=7,padx=5)
        self.cpe_var=tk.BooleanVar(value=False); ttk.Checkbutton(f, text="CPE Match", variable=self.cpe_var).grid(row=0,column=8,padx=5)
        ttk.Label(f, text="NVD API Key (optional):").grid(row=1,column=0,columnspan=2,sticky="w",pady=5)
        ttk.Entry(f, textvariable=self.api_key_var, width=50, show="*").grid(row=1,column=2,columnspan=4,sticky="we",pady=5)
        ttk.Button(f, text="🔍 FETCH / SEARCH", command=self.start_fetch).grid(row=1,column=6,columnspan=3,pady=5)
        # Watchlist
        wf = ttk.LabelFrame(self, text="Watchlist (vendor + product)", padding=8); wf.pack(fill="x", padx=10, pady=5)
        self.w_listbox=tk.Listbox(wf, height=3); self.w_listbox.pack(side="left", fill="x", expand=True)
        self.refresh_watchlist()
        wb=ttk.Frame(wf); wb.pack(side="left", padx=5)
        ttk.Label(wb, text="Vendor").pack(); self.e_v=ttk.Entry(wb,width=15); self.e_v.pack()
        ttk.Label(wb, text="Product").pack(); self.e_p=ttk.Entry(wb,width=15); self.e_p.pack()
        ttk.Button(wb, text="Add", command=self.add_watch).pack(pady=2, fill="x")
        ttk.Button(wb, text="Delete Selected", command=self.del_watch).pack(fill="x")
        # Table
        cols=("CVE","Score","Severity","Published","Matched","Description")
        self.tree=ttk.Treeview(self, columns=cols, show="headings", height=12)
        for c in cols: self.tree.heading(c, text=c)
        self.tree.column("CVE",width=130); self.tree.column("Score",width=60); self.tree.column("Severity",width=90); self.tree.column("Published",width=110); self.tree.column("Matched",width=150); self.tree.column("Description",width=400)
        self.tree.pack(fill="both", expand=True, padx=10)
        self.tree.bind("<Double-1>", self.show_detail)
        # Buttons
        bf=ttk.Frame(self, padding=8); bf.pack(fill="x")
        for txt, cmd in [("💾 Save Report", self.save_report),("📤 Export CSV", self.export_csv),("📤 Export JSON", self.export_json),("📊 Trend 7/30 Days", self.show_trend),("🗑 Clear DB", self.clear_db),("🧪 Load Sample (Offline Test)", self.load_sample)]:
            ttk.Button(bf, text=txt, command=cmd).pack(side="left", padx=4)
        self.log_box=scrolledtext.ScrolledText(self, height=6); self.log_box.pack(fill="x", padx=10, pady=5)
        self.log("Ready. Add watchlist, set severity, click FETCH. Rate limit respected: 6s pause without key.")

    def log(self, msg):
        self.log_box.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n"); self.log_box.see("end"); self.update_idletasks()
    def refresh_watchlist(self):
        self.w_listbox.delete(0,"end")
        for w in self.watchlist: self.w_listbox.insert("end", f"{w.get('vendor')} - {w.get('product')} {w.get('version','')}")
    def add_watch(self):
        v,p=self.e_v.get().strip(), self.e_p.get().strip()
        if not v or not p: messagebox.showwarning("Watchlist","Vendor + Product dono likho"); return
        self.watchlist.append({"vendor":v,"product":p,"version":""}); save_watchlist(self.watchlist); self.refresh_watchlist(); self.log(f"Watchlist added: {v} {p}")
    def del_watch(self):
        sel=self.w_listbox.curselection()
        if not sel: return
        del self.watchlist[sel[0]]; save_watchlist(self.watchlist); self.refresh_watchlist()
    def start_fetch(self): threading.Thread(target=self.fetch, daemon=True).start()
    def fetch(self):
        cve_id=self.e_cve.get().strip(); kw=self.e_kw.get().strip(); min_sev=self.cb_sev.get()
        try: days=int(self.e_days.get() or 7)
        except: days=7
        if not cve_id and not kw and not self.watchlist:
            self.log("Keyword ya CVE ID likho"); return
        # If keyword empty, use watchlist products as keywords one by one
        keywords=[kw] if kw else [w["product"] for w in self.watchlist]
        all_parsed=[]
        for keyword in keywords:
            params={"resultsPerPage":20,"startIndex":0}
            if cve_id: params["cveId"]=cve_id
            else: params["keywordSearch"]=keyword
            if not cve_id:
                end=datetime.now(timezone.utc); start=end-timedelta(days=days)
                params["pubStartDate"]=start.strftime("%Y-%m-%dT%H:%M:%S.000Z"); params["pubEndDate"]=end.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            self.log(f"Fetching: {keyword} ...")
            try: data=nvd_request(params, self.api_key_var.get().strip(), self.log)
            except Exception as e: self.log(f"Error: {e}"); continue
            for v in data.get("vulnerabilities",[]): all_parsed.append(parse_cve(v))
            total=data.get("totalResults",0); self.log(f"Got {len(data.get('vulnerabilities',[]))} / Total {total}")
            time.sleep(6 if not self.api_key_var.get().strip() else 1)  # Rate limit respect
        self.process(all_parsed, min_sev)

    def process(self, parsed_list, min_sev):
        con=sqlite3.connect(DB); cur=con.cursor()
        new=[]; modified=[]
        for p in parsed_list:
            matched=match_watchlist(p, self.watchlist, self.cpe_var.get())
            if not matched: continue
            if SEV_ORDER.get(p["severity"],5) > SEV_ORDER.get(min_sev,1): continue
            cur.execute("SELECT description, score FROM cves WHERE cve_id=?", (p["id"],)); old=cur.fetchone()
            if old is None:
                new.append((p,matched))
            elif old[0]!=p["desc"] or float(old[1] or 0)!=p["score"]:
                modified.append((p,matched))
            cur.execute("INSERT OR REPLACE INTO cves VALUES(?,?,?,?,?,?,?,?)", (p["id"],p["published"],p["modified"],p["desc"],p["score"],p["severity"],p["refs"],",".join(matched)))
        con.commit(); con.close()
        new_sorted=sorted(new, key=lambda x:(SEV_ORDER.get(x[0]["severity"],5), x[0]["published"]))
        self.results=new_sorted
        self.tree.delete(*self.tree.get_children())
        for p,m in new_sorted: self.tree.insert("", "end", values=(p["id"],p["score"],p["severity"],p["published"][:10],",".join(m),p["desc"][:120]))
        self.log(f"✅ New: {len(new_sorted)} | Modified: {len(modified)} | Total fetched: {len(parsed_list)}")
        for p,m in modified: self.log(f"⚠ MODIFIED: {p['id']} score/desc changed")
        if not new_sorted: self.log("No new CVEs - second run will show same (duplicate check working)")
        else: messagebox.showinfo("VulnFeed Alert", f"{len(new_sorted)} NEW matching CVEs found!\nTop: {new_sorted[0][0]['id']} - {new_sorted[0][0]['severity']} {new_sorted[0][0]['score']}")

    def save_report(self):
        if not self.results: messagebox.showinfo("Report","Pehle FETCH karo, koi new CVE nahi"); return
        counts={}
        for p,m in self.results: counts[p["severity"]]=counts.get(p["severity"],0)+1
        fname=f"{REPORT_DIR}/report_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.txt"
        with open(fname,"w",encoding="utf-8") as f:
            f.write(f"VulnFeed Report - {datetime.now()}\nStudent: M. Faizan\nCounts: {counts}\nWatchlist: {self.watchlist}\n\n")
            for p,m in self.results: f.write(f"{p['id']} | {p['severity']} {p['score']} | {p['published']} | Matched: {m}\n{p['desc']}\nRefs: {p['refs']}\n\n")
        self.log(f"Report saved: {fname}"); messagebox.showinfo("Report", f"Saved: {fname}")
    def export_csv(self):
        con=sqlite3.connect(DB); rows=con.execute("SELECT * FROM cves").fetchall(); con.close()
        f=filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if f:
            with open(f,"w",newline="",encoding="utf-8") as fh: w=csv.writer(fh); w.writerow(["CVE","Published","Modified","Desc","Score","Severity","Refs","Matched"]); w.writerows(rows)
            self.log(f"CSV exported: {f}")
    def export_json(self):
        con=sqlite3.connect(DB); rows=con.execute("SELECT * FROM cves").fetchall(); con.close()
        f=filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json")])
        if f: json.dump(rows, open(f,"w"), indent=2); self.log(f"JSON exported: {f}")
    def show_trend(self):
        con=sqlite3.connect(DB); rows=con.execute("SELECT published, matched FROM cves").fetchall(); con.close()
        now=datetime.now(timezone.utc)
        c7=c30=0
        for pub,mat in rows:
            try: d=datetime.fromisoformat(pub.replace("Z","+00:00"))
            except: continue
            if (now-d).days<=7: c7+=1
            if (now-d).days<=30: c30+=1
        messagebox.showinfo("Trend", f"Last 7 days: {c7} CVEs\nLast 30 days: {c30} CVEs\nTotal in DB: {len(rows)}")
    def clear_db(self):
        if messagebox.askyesno("Clear","Saara DB clear kar dun?"):
            con=sqlite3.connect(DB); con.execute("DELETE FROM cves"); con.commit(); con.close(); self.log("DB cleared")
    def load_sample(self):
        sample=[{"id":"CVE-2021-44228","published":"2021-12-10T00:00:00.000Z","modified":"2021-12-10T00:00:00.000Z","desc":"Apache Log4j2 remote code execution vulnerability","score":10.0,"severity":"CRITICAL","refs":"https://nvd.nist.gov","cpes":[],"raw_desc":"apache log4j2 remote code execution","cpe_text":"cpe:2.3:a:apache:log4j:2.14.0"}]
        self.process(sample, "LOW"); self.log("Sample loaded - Offline test passed if 1 new shows")
    def show_detail(self, e):
        sel=self.tree.selection()
        if not sel: return
        vals=self.tree.item(sel[0])["values"]
        messagebox.showinfo(vals[0], f"CVE: {vals[0]}\nScore: {vals[1]} {vals[2]}\nPublished: {vals[3]}\nMatched: {vals[4]}\n\n{vals[5]}")

if __name__=="__main__": App().mainloop()