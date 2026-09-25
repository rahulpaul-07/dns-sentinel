import React, { useState, useEffect, useMemo, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  connectSSE, fetchAlerts, fetchStats, fetchTraffic, fetchModelInfo, uploadDataset, analyzeQuery,
  archiveCase, blockIP, markBenign, fetchIncidentReport,
  getExportCsvUrl, getAuditPdfUrl, getAlertPdfUrl,
} from '../services/api';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  AreaChart, Area, Cell, PieChart, Pie, CartesianGrid
} from 'recharts';
import {
  Shield, AlertTriangle, Activity, Search, Filter, Terminal,
  Zap, Crosshair, Cpu, UploadCloud, Download, X, Database,
  ArrowUpRight, Globe, Lock, Info, Server, Eye, ExternalLink,
  Command, ChevronRight, BarChart2, Clock, Unlock, Trash2, FileText
} from 'lucide-react';




import { StatusMetric, Th, SOCTooltip, SOCPieTooltip } from '../components/primitives';
import { ForensicCard } from '../components/ForensicCard';
import { CyberTableRow } from '../components/CyberTableRow';
import { DetailedModal } from '../components/DetailedModal';
import { TopologyView } from '../components/TopologyView';
import { ThreatHunterView } from '../components/ThreatHunterView';
import { ContainmentView } from '../components/ContainmentView';

const Dashboard = () => {
  const [traffic, setTraffic] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({
    total_requests: 0, total_alerts: 0,
    risk_distribution: { High: 0, Medium: 0, Low: 0 }
  });
  const [isConnected, setIsConnected] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const [filterSeverity, setFilterSeverity] = useState("All");
  const [, setIsUploading] = useState(false);
  const [selectedLog, setSelectedLog] = useState(null);
  const [manualQuery, setManualQuery] = useState("");
  const [manualIp, setManualIp] = useState("10.0.0.99");
  const [manualResult, setManualResult] = useState(null);
  const [manualError, setManualError] = useState(null);
  const [modelInfo, setModelInfo] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [report, setReport] = useState(null); // { id, markdown }
  const [viewMode, setViewMode] = useState("Triage"); // Triage vs Topology
  const [sortConfig, setSortConfig] = useState({ key: 'timestamp', direction: 'desc' });
  const [liveClock, setLiveClock] = useState(new Date());

  const fileInputRef = useRef(null);
  const searchInputRef = useRef(null);

  // Feature: "/" shortcut to focus search
  useEffect(() => {
    const handler = (e) => {
      if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  // Feature: Live clock
  useEffect(() => {
    const t = setInterval(() => setLiveClock(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    fetchAlerts().then(setAlerts).catch(console.error);
    fetchStats().then(setStats).catch(console.error);
    fetchTraffic().then(setTraffic).catch(console.error);
    fetchModelInfo().then(setModelInfo).catch(console.error);

    // Server-Sent Events: one-way push with built-in browser reconnection.
    const sse = connectSSE(
      (data) => {
        setTraffic(prev => [data, ...prev].slice(0, 100));
        if (data.prediction === "Malicious" || data.risk_level !== "Low") {
          setAlerts(prev => [data, ...prev].slice(0, 50));
        }
      },
      () => setIsConnected(true),
      () => setIsConnected(false)
    );

    const statsInterval = setInterval(() => {
        fetchStats().then(setStats).catch(() => setIsConnected(false));
    }, 5000);

    return () => {
        if(sse) sse.close();
        clearInterval(statsInterval);
    };
  }, []);

  const handleManualAnalysis = async (e) => {
    e.preventDefault();
    if(!manualQuery) return;
    setIsAnalyzing(true);
    setManualError(null);
    try {
      setManualResult(await analyzeQuery(manualQuery.trim(), manualIp.trim()));
    } catch(err) {
      setManualResult(null);
      setManualError(err.message);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setIsUploading(true);
    try {
      const res = await uploadDataset(file);
      alert(res.message || "Ingest started. Results will stream into the live feed.");
    } catch (err) {
      console.error("Upload failed", err);
      alert("Upload failed: " + err.message);
    } finally {
      setIsUploading(false);
      e.target.value = null;
    }
  };

  const handleArchive = async () => {
    if(!window.confirm("Start a new case? This permanently clears the audit ledger and all active SOAR rules. Export first if you need them.")) return;

    try {
      await archiveCase();
      window.location.reload(); // resync every view with the empty ledger
    } catch(err) {
      alert("Could not clear the ledger: " + err.message);
    }
  };

  const exportAuditPDF = () => {
    window.open(getAuditPdfUrl(), "_blank");
  };

  const exportAlertsCSV = () => {
    // Streaming CSV download from the backend (respects the active severity filter).
    const riskLevel = filterSeverity && filterSeverity !== 'All' ? filterSeverity : null;
    window.open(getExportCsvUrl(riskLevel), "_blank");
  };

  // Toggle column sort direction; drives the sortedTraffic memo and <Th/> headers.
  const handleSort = (key) => {
    setSortConfig((prev) => ({
      key,
      direction: prev.key === key && prev.direction === 'asc' ? 'desc' : 'asc',
    }));
  };

  const handleBlockAction = async (log) => {
    if(!log.db_id) return alert("Persistence sync pending...");
    try {
      const res = await blockIP(log.db_id);
      const messages = {
        SUCCESS: `Block rule created for ${res.entity} (expires ${new Date(res.cooldown_end).toLocaleString()})${res.dry_run ? ' [dry-run: recorded, not enforced]' : ''}.`,
        SKIPPED: `${log.source_ip} is already blocked.`,
        DENIED: res.message,
        INVALID: res.message,
        ENFORCEMENT_FAILED: `Rule recorded, but the OS firewall command failed for ${res.entity}.`,
      };
      alert(messages[res.status] || JSON.stringify(res));
    } catch (err) { alert("Action failed: " + err.message); }
  };

  const handleBenignAction = async (log) => {
    if(!log.db_id) return alert("Persistence sync pending...");
    try {
      await markBenign(log.db_id);
      alert("Marked as a false positive. The verdict is recorded on the alert and any block on this source was lifted.");
      setAlerts(prev => prev.filter(a => a.db_id !== log.db_id));
      setSelectedLog(null); // Close modal
    } catch (err) { alert("Action failed: " + err.message); }
  };

  const handleReportAction = async (log) => {
    if(!log.db_id) return alert("Persistence sync pending...");
    try {
      const res = await fetchIncidentReport(log.db_id);
      setReport({ id: log.db_id, markdown: res.markdown });
    } catch (err) { alert("Report failed: " + err.message); }
  };

  const handlePDFAction = (log) => {
    if(!log.db_id) return alert("Persistence sync pending...");
    window.open(getAlertPdfUrl(log.db_id), '_blank');
  };

  const filteredTraffic = useMemo(() => {
    let result = traffic.filter(item =>
      (item?.query?.toLowerCase().includes(searchTerm.toLowerCase()) ||
       item?.source_ip?.includes(searchTerm)) &&
      (filterSeverity === "All" || item?.risk_level === filterSeverity)
    );
    result.sort((a, b) => {
       let valA = a[sortConfig.key];
       let valB = b[sortConfig.key];
       if (sortConfig.key.includes('features.')) {
           valA = a.features[sortConfig.key.split('.')[1]];
           valB = b.features[sortConfig.key.split('.')[1]];
       }
       if (valA < valB) return sortConfig.direction === 'asc' ? -1 : 1;
       if (valA > valB) return sortConfig.direction === 'asc' ? 1 : -1;
       return 0;
    });
    return result;
  }, [traffic, searchTerm, filterSeverity, sortConfig]);

  const riskPieData = useMemo(() => [
    { name: 'Low', value: stats?.risk_distribution?.Low || 0, color: '#10b981' },
    { name: 'Medium', value: stats?.risk_distribution?.Medium || 0, color: '#f59e0b' },
    { name: 'High', value: stats?.risk_distribution?.High || 0, color: '#f43f5e' },
    { name: 'Critical', value: stats?.risk_distribution?.Critical || 0, color: '#a855f7' }
  ], [stats]);

  return (
    <div className="min-h-screen bg-[#02060e] selection:bg-[#00f2ff]/30">
      <div className="cyber-grid"></div>
      <div className="scanline"></div>

      {/* Live Threat Intelligence Ticker */}
      <div className="bg-black border-b border-[#00f2ff]/10 overflow-hidden relative z-[70]" style={{height: '28px'}}>
        <div className="absolute left-0 top-0 h-full flex items-center z-10" style={{background: 'linear-gradient(90deg, black 60%, transparent)'}}>
          <span className="text-[9px] font-bold text-[#00f2ff] tracking-widest uppercase px-4 whitespace-nowrap flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-pulse inline-block"></span>
            LIVE INTEL
          </span>
        </div>
        <div className="flex items-center h-full" style={{animation: 'tickerScroll 40s linear infinite', whiteSpace: 'nowrap', paddingLeft: '120px'}}>
          {[
            "SYSTEM: DNSentinel Threat Intelligence Platform — All systems nominal",
            `MODEL: 22-feature Random Forest + Isolation Forest${modelInfo ? ` | calibrated threshold ${modelInfo.decision_threshold.toFixed(2)}` : ''}`,
            "RISK: per-host mean + 2 sigma baselining escalates alert tiers",
            `SOAR: ${modelInfo?.soar_dry_run === false ? 'enforcement LIVE' : 'dry-run (rules recorded, not enforced)'} | 24h auto-expiry`,
            `STREAM: ${isConnected ? 'connected' : 'reconnecting'} via Server-Sent Events`,
            alerts[0] ? ("ALERT: " + (alerts[0].query || '') + " from " + (alerts[0].source_ip || '') + " [" + (alerts[0].risk_level || '') + "]") : "ALERT: Monitoring for DGA, Tunneling, and Exfiltration patterns",
            alerts[1] ? ("ALERT: " + (alerts[1].query || '') + " [" + (alerts[1].risk_level || '') + "]") : "INTEL: Behavioral baselining in progress across all hosts",
          ].map((item, i) => (
            <span key={i} className="text-[10px] text-slate-400 font-mono px-12">
              {item}
              <span className="mx-8 text-[#00f2ff]/20"> | </span>
            </span>
          ))}
        </div>
      </div>

      {/* Premium SOC Header */}
      <header className="border-b border-white/5 bg-[#020814]/80 backdrop-blur-3xl sticky top-0 z-[60]">
        <div className="max-w-[1800px] mx-auto px-8 h-20 flex items-center justify-between">
          <div className="flex items-center gap-6">
            <div className="p-3 bg-gradient-to-br from-[#00f2ff]/30 to-transparent rounded-2xl border border-[#00f2ff]/40 shadow-[0_0_30px_rgba(0,242,255,0.2)] group hover:scale-105 transition-all">
              <Shield className="text-[#00f2ff]" size={26} fillOpacity={0.1}/>
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-widest text-[#00f2ff] drop-shadow-glow">
                DNSENTINEL <span className="text-white font-light opacity-60">DASHBOARD</span>
              </h1>
              <div className="flex items-center gap-3">
                <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-emerald-400' : 'bg-rose-500 animate-pulse'} ring-4 ring-emerald-400/20`}></div>
                <span className="text-[10px] font-bold text-slate-500 tracking-[0.2em] uppercase">SYSTEM.STATUS: {isConnected ? 'SECURE_ACTIVE' : 'RECONNECTING'}</span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-4 bg-black/40 p-1.5 rounded-2xl border border-white/5 mx-auto">
             <button onClick={() => setViewMode("Triage")} className={`px-6 py-2 rounded-xl text-[10px] font-bold tracking-widest transition-all ${viewMode === 'Triage' ? 'bg-[#00f2ff] text-black shadow-[0_0_20px_rgba(0,242,255,0.4)]' : 'text-slate-500 hover:text-white'}`}>TRIAGE FEED</button>
             <button onClick={() => setViewMode("Topology")} className={`px-6 py-2 rounded-xl text-[10px] font-bold tracking-widest transition-all ${viewMode === 'Topology' ? 'bg-[#8b5cf6] text-white shadow-[0_0_20px_rgba(139,92,246,0.4)]' : 'text-slate-500 hover:text-white'}`}>TOPOLOGY MAP</button>
             <button onClick={() => setViewMode("Hunter")} className={`px-6 py-2 rounded-xl text-[10px] font-bold tracking-widest transition-all ${viewMode === 'Hunter' ? 'bg-amber-500 text-black shadow-[0_0_20px_rgba(245,158,11,0.4)]' : 'text-slate-500 hover:text-white'}`}>THREAT HUNTER</button>
             <button onClick={() => setViewMode("Containment")} className={`px-6 py-2 rounded-xl text-[10px] font-bold tracking-widest transition-all ${viewMode === 'Containment' ? 'bg-rose-500 text-white shadow-[0_0_20px_rgba(244,63,94,0.4)]' : 'text-slate-500 hover:text-white'}`}>CONTAINMENT AUDIT</button>
          </div>

          <div className="hidden lg:flex items-center gap-8">
             <div className="flex flex-col items-end border-r border-white/5 pr-8">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1">Alert Rate</span>
                <span className="text-2xl font-mono text-white leading-none font-bold tabular-nums">{stats.total_requests ? ((stats.total_alerts / stats.total_requests) * 100).toFixed(1) : '0.0'}<span className="text-xs text-slate-600 font-light ml-1">%</span></span>
             </div>
             {/* Live Clock */}
             <div className="flex flex-col items-end border-r border-white/5 pr-8">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1">System Time</span>
                <span className="text-lg font-mono text-white leading-none font-bold tabular-nums">{liveClock.toLocaleTimeString('en-GB', {hour12: false})}</span>
             </div>
             <div className="flex gap-4">
                <input type="file" ref={fileInputRef} onChange={handleFileUpload} className="hidden" accept=".csv,.log"/>
                <button onClick={handleArchive} className="flex items-center gap-3 px-5 py-3 bg-slate-900/50 border border-white/5 rounded-xl text-[11px] font-bold uppercase tracking-widest text-slate-500 hover:text-rose-400 hover:bg-rose-400/5 hover:border-rose-400/30 transition-all active:scale-95">
                  <Trash2 size={16}/>
                  New Case
                </button>
                <button onClick={() => fileInputRef.current.click()} className="flex items-center gap-3 px-5 py-3 bg-[#00f2ff]/5 border border-[#00f2ff]/20 rounded-xl text-[11px] font-bold uppercase tracking-widest text-[#00f2ff] hover:bg-[#00f2ff]/10 transition-all active:scale-95 shadow-lg shadow-cyan-500/5">
                  <UploadCloud size={16}/>
                  Stream Ingest
                </button>
                <button onClick={exportAuditPDF} className="flex items-center gap-3 px-5 py-3 bg-slate-900 border border-white/10 rounded-xl text-[11px] font-bold uppercase tracking-widest text-slate-400 hover:text-white hover:border-white/20 transition-all">
                  <FileText size={16}/>
                  DNS Audit
                </button>
                <button onClick={exportAlertsCSV} className="flex items-center gap-3 px-5 py-3 bg-slate-900 border border-white/10 rounded-xl text-[11px] font-bold uppercase tracking-widest text-slate-400 hover:text-white hover:border-white/20 transition-all">
                  <Download size={16}/>
                  Export CSV
                </button>
             </div>
          </div>
        </div>
      </header>

      <main className="max-w-[1800px] mx-auto p-8 space-y-10">

        {/* Core Metrics Deck */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
           <StatusMetric label="Alerts (Medium+)" value={stats.total_alerts} icon={<AlertTriangle size={24}/>} color="rose" />
           <StatusMetric label="Queries Analyzed" value={stats.total_requests} icon={<Activity size={24}/>} color="cyan" />
           <StatusMetric label="Decision Threshold" value={modelInfo ? modelInfo.decision_threshold.toFixed(2) : '-'} icon={<Zap size={24}/>} color="purple" />
           <StatusMetric label="Feature Vector" value="22-D" icon={<Cpu size={24}/>} color="amber" />
        </div>

        {viewMode === "Topology" ? (
           <TopologyView traffic={traffic} alerts={alerts} onSelectNode={(log) => setSelectedLog(log)} />
        ) : viewMode === "Hunter" ? (
           <ThreatHunterView traffic={traffic} onSelectNode={(log) => setSelectedLog(log)} />
        ) : viewMode === "Containment" ? (
           <ContainmentView onSelectNode={(log) => setSelectedLog(log)} />
        ) : (
          <div className="grid grid-cols-1 xl:grid-cols-12 gap-10">
            {/* Forensic Feed (Sidebar) */}
            <div className="xl:col-span-4 space-y-8">
              <section className="glass-panel p-8 h-[820px] flex flex-col group relative">
                <div className="absolute top-0 right-0 w-32 h-32 bg-rose-500/5 blur-[80px] rounded-full pointer-events-none"></div>
                <div className="flex items-center justify-between mb-8 pb-3 border-b border-white/5">
                  <h2 className="text-[11px] font-bold text-slate-500 tracking-[0.3em] uppercase flex items-center gap-4">
                     <div className="pulse-dot"></div>
                     Alert Feed
                  </h2>
                  <div className="text-[#00f2ff] px-2 py-1 bg-[#00f2ff]/10 rounded font-mono text-[9px] font-bold border border-[#00f2ff]/20">{isConnected ? 'LIVE' : 'OFFLINE'}</div>
                </div>

                <div className="flex-1 overflow-y-auto custom-scrollbar space-y-5 pr-2 scroll-smooth">
                   <AnimatePresence initial={false}>
                      {alerts.length === 0 ? (
                        <div className="h-full flex flex-col items-center justify-center opacity-10 text-center px-12">
                           <Lock size={64} className="mb-6" />
                           <p className="text-sm font-bold uppercase tracking-[0.2em] leading-loose">Clean Perimeter<br/>No Anomalies Detected</p>
                        </div>
                      ) : (
                        alerts.map((alert, idx) => (
                          <ForensicCard key={alert.db_id ?? `${alert.timestamp}-${idx}`} alert={alert} onClick={() => setSelectedLog(alert)} />
                        ))
                      )}
                   </AnimatePresence>
                </div>
              </section>
            </div>

            {/* Main SOC Control Panel */}
            <div className="xl:col-span-8 space-y-10">
               <section className="glass-panel p-10 h-[820px] flex flex-col">
                  <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-10 gap-6">
                    <h2 className="text-sm font-bold text-white tracking-[0.3em] uppercase flex items-center gap-4">
                      <Terminal size={22} className="text-[#00f2ff]" />
                      Live DNS Query Stream
                    </h2>

                    <div className="flex flex-wrap gap-4 w-full md:w-auto">
                      <select
                        className="bg-black/50 border border-white/10 rounded-xl px-5 py-3 text-[10px] text-slate-400 focus:outline-none focus:border-[#00f2ff]/50 cursor-pointer font-bold uppercase tracking-widest hover:bg-black/70 transition-all flex items-center"
                        value={filterSeverity}
                        onChange={(e)=>setFilterSeverity(e.target.value)}
                      >
                        <option value="All">All Severities</option>
                        <option value="Critical" className="text-purple-400 font-bold">Severity: Critical</option>
                        <option value="High" className="text-rose-400 font-bold">Severity: High</option>
                        <option value="Medium" className="text-amber-500 font-bold">Severity: Medium</option>
                        <option value="Low" className="text-emerald-400 font-bold">Severity: Low</option>
                      </select>

                      <div className="relative flex-1 md:w-80">
                        <Search size={18} className="absolute left-4 top-3 text-slate-600" />
                        <input
                          type="text" placeholder="Probe Domain or Host Origin..."
                          className="w-full bg-black/50 border border-white/10 rounded-xl pl-12 pr-5 py-3 text-[13px] text-slate-200 focus:outline-none focus:border-[#00f2ff]/40 focus:bg-black/70 transition-all font-mono placeholder:text-slate-700 shadow-inner"
                          onChange={(e) => setSearchTerm(e.target.value)}
                        />
                      </div>
                    </div>
                  </div>

                  <div className="overflow-y-auto overflow-x-auto flex-1 custom-scrollbar scroll-smooth">
                     <table className="w-full text-left">
                        <thead className="sticky top-0 bg-[#020814] border-b border-white/10 z-20">
                          <tr>
                             <Th label="Access Time" onClick={() => handleSort('timestamp')} skey="timestamp" config={sortConfig}/>
                             <Th label="Origin IP" onClick={() => handleSort('source_ip')} skey="source_ip" config={sortConfig}/>
                             <Th label="Protocol Payload" onClick={() => handleSort('query')} skey="query" config={sortConfig}/>
                             <Th label="Risk Index" onClick={() => handleSort('risk_score')} skey="risk_score" config={sortConfig} center/>
                             <Th label="Threat Level" onClick={() => handleSort('risk_level')} skey="risk_level" config={sortConfig} right/>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-white/[0.04]">
                          <AnimatePresence>
                            {filteredTraffic.map((row, idx) => (
                              <CyberTableRow key={row.db_id ?? `${row.timestamp}-${idx}`} row={row} onClick={() => setSelectedLog(row)} />
                            ))}
                          </AnimatePresence>
                        </tbody>
                     </table>
                  </div>
               </section>
            </div>
          </div>
        )}

        {/* Global Analytics Row */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 pb-20">

           {/* Attack Clustering (Donut) */}
           <div className="lg:col-span-3 glass-panel p-8">
              <h3 className="text-[11px] font-bold text-slate-500 tracking-[0.3em] mb-10 border-b border-white/5 pb-3 uppercase flex items-center gap-3">
                 <Command size={16} /> Risk Distribution
              </h3>
              <div className="h-[250px] relative reveal-card">
                 <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                    <span className="text-4xl font-mono font-bold text-white tracking-tighter tabular-nums">{stats.total_alerts}</span>
                    <span className="text-[10px] font-bold text-slate-600 uppercase tracking-widest mt-1">Alerts</span>
                 </div>
                 <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                       <Pie data={riskPieData} dataKey="value" innerRadius={85} outerRadius={110} paddingAngle={6} stroke="none">
                          {riskPieData.map((e, index) => <Cell key={`cell-${index}`} fill={e.color} />)}
                       </Pie>
                       <Tooltip content={<SOCPieTooltip />} />
                    </PieChart>
                 </ResponsiveContainer>
              </div>
           </div>

           {/* Direct Probe Terminal */}
           <div className="lg:col-span-4 glass-panel p-8 flex flex-col group">
              <div className="absolute top-0 left-0 w-full h-[2px] bg-gradient-to-r from-transparent via-[#00f2ff]/20 to-transparent"></div>
              <h3 className="text-[11px] font-bold text-[#00f2ff] tracking-[0.3em] mb-8 border-b border-[#00f2ff]/10 pb-3 uppercase flex items-center gap-3">
                 <Crosshair size={18} className="animate-pulse" /> Analyze a Query
              </h3>
              <form onSubmit={handleManualAnalysis} className="space-y-6 flex-1">
                 <div className="space-y-3">
                    <label className="text-[10px] text-slate-600 font-bold uppercase tracking-[0.2em] flex justify-between ml-1">Domain</label>
                    <input
                      type="text" required value={manualQuery} onChange={(e)=>setManualQuery(e.target.value)}
                      placeholder="e.g. unknown-tunnel.xyz"
                      className="w-full bg-black/60 border border-white/10 rounded-xl p-4 text-[13px] text-white focus:outline-none focus:border-[#00f2ff]/40 font-mono transition-all hover:bg-black/80"
                    />
                 </div>
                 <div className="space-y-3">
                    <label className="text-[10px] text-slate-600 font-bold uppercase tracking-[0.2em] flex justify-between ml-1">Source IP</label>
                    <input
                      type="text" value={manualIp} onChange={(e)=>setManualIp(e.target.value)}
                      placeholder="10.0.0.x"
                      className="w-full bg-black/60 border border-white/10 rounded-xl p-4 text-[13px] text-white focus:outline-none focus:border-[#00f2ff]/40 font-mono transition-all hover:bg-black/80"
                    />
                 </div>
                 <button
                  type="submit" disabled={isAnalyzing}
                  className="w-full py-5 bg-gradient-to-br from-[#00f2ff]/20 to-[#8b5cf6]/20 text-[#00f2ff] border border-[#00f2ff]/30 rounded-2xl text-[12px] font-bold tracking-[0.3em] hover:from-[#00f2ff]/30 hover:to-[#8b5cf6]/30 transition-all active:scale-95 flex justify-center items-center gap-4 mt-6 shadow-2xl shadow-cyan-500/10"
                 >
                    {isAnalyzing ? <div className="w-5 h-5 border-2 border-[#00f2ff] border-t-transparent rounded-full animate-spin"></div> : <><Cpu size={20}/> ANALYZE</>}
                 </button>
                 {manualError && (
                   <p role="alert" className="text-[11px] font-mono text-rose-400 bg-rose-500/10 border border-rose-500/20 rounded-xl p-3">{manualError}</p>
                 )}
                 {manualResult && !manualError && (
                   <button type="button" onClick={() => setSelectedLog(manualResult)}
                     className="w-full text-left text-[11px] font-mono text-slate-300 bg-black/40 border border-white/10 rounded-xl p-3 hover:border-[#00f2ff]/40">
                     {manualResult.query}: <span className="font-bold">{manualResult.risk_level}</span> ({manualResult.risk_score}),
                     P(malicious) {manualResult.ml_probability}. Click for details.
                   </button>
                 )}
              </form>
           </div>

           {/* Entropy Visualizer */}
           <div className="lg:col-span-5 glass-panel p-8">
              <h3 className="text-[11px] font-bold text-slate-500 tracking-[0.3em] mb-10 border-b border-white/5 pb-3 uppercase flex justify-between items-center">
                 Shannon Entropy, Last 30 Queries
                 <span className="font-mono text-[#00f2ff] opacity-40">[BITS/CHAR]</span>
              </h3>
              <div className="h-[280px] reveal-card">
                 <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={traffic.slice(0, 30).reverse()} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                        <defs>
                          <linearGradient id="cyberArea" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor="#00f2ff" stopOpacity={0.25}/>
                            <stop offset="100%" stopColor="#8b5cf6" stopOpacity={0}/>
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="5 5" stroke="rgba(255,255,255,0.02)" vertical={false} />
                        <XAxis dataKey="timestamp" hide />
                        <YAxis stroke="#475569" fontSize={10} tickFormatter={(val) => val.toFixed(1)} domain={[0, 6]} axisLine={false} tickLine={false} />
                        <Tooltip content={<SOCTooltip />} />
                        <Area
                          type="monotone" dataKey="features.entropy" stroke="#00f2ff" strokeWidth={4} fillOpacity={1} fill="url(#cyberArea)"
                          animationDuration={2000}
                        />
                    </AreaChart>
                 </ResponsiveContainer>
              </div>
           </div>
        </div>
      </main>

      {/* Forensic Modal Overlays */}
      <AnimatePresence>
        {selectedLog && (
          <DetailedModal
            log={selectedLog}
            onClose={() => setSelectedLog(null)}
            onBlock={handleBlockAction}
            onBenign={handleBenignAction}
            onReport={handleReportAction}
            onPDF={handlePDFAction}
          />
        )}

         {report && (
          <motion.div
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 z-[110] bg-black/98 backdrop-blur-3xl flex justify-center items-start overflow-y-auto p-4 sm:p-12 custom-scrollbar"
            onClick={() => setReport(null)}
          >
            <motion.div
              initial={{ scale: 0.95, y: 40 }} animate={{ scale: 1, y: 0 }} exit={{ scale: 0.95, y: 40 }}
              className="glass-panel max-w-4xl w-full p-10 sm:p-16 relative border-[#00f2ff]/20 shadow-[0_0_120px_rgba(0,0,0,1)] my-auto"
              onClick={e => e.stopPropagation()}
            >
               <div className="flex justify-between items-center mb-8 border-b border-white/5 pb-4">
                  <h3 className="text-xl font-bold tracking-widest text-[#00f2ff] uppercase">Incident Executive Summary</h3>
                  <button onClick={() => setReport(null)} aria-label="Close report" className="p-2 hover:bg-white/5 rounded-full"><X size={24}/></button>
               </div>
               <div className="prose prose-invert max-w-none font-mono text-sm leading-relaxed whitespace-pre-wrap text-slate-300">
                  {report.markdown}
               </div>
               <div className="mt-10 flex gap-4">
                  <button onClick={() => window.open(getAlertPdfUrl(report.id), '_blank')} className="px-6 py-3 bg-[#00f2ff]/10 text-[#00f2ff] border border-[#00f2ff]/30 rounded-xl text-[10px] font-bold tracking-widest uppercase hover:bg-[#00f2ff]/20 transition-all">Download PDF</button>
                  <button onClick={() => setReport(null)} className="px-6 py-3 bg-white/5 text-slate-400 border border-white/10 rounded-xl text-[10px] font-bold tracking-widest uppercase">Close File</button>
               </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

     {/* Keyboard Shortcut Hint */}
     <div className="fixed bottom-8 right-8 z-[998] flex items-center gap-2 opacity-30 hover:opacity-80 transition-opacity pointer-events-none">
       <kbd className="px-2 py-1 bg-slate-800 border border-white/10 rounded text-[10px] font-mono text-slate-400">/</kbd>
       <span className="text-[10px] text-slate-500 font-mono">to search</span>
     </div>
    </div>
  );
};

export default Dashboard;
