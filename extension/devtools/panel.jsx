import React, { useState, useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import { Shield, Settings, Activity, AlertTriangle, List, CheckCircle } from 'lucide-react';
import '../popup/popup.css';

const Panel = () => {
  const [events, setEvents] = useState([]);
  
  const fetchEvents = () => {
    const request = indexedDB.open("DNSentinelDB", 1);
    request.onsuccess = (e) => {
      const db = e.target.result;
      if(db.objectStoreNames.contains("dns_events")) {
        const tx = db.transaction("dns_events", "readonly");
        const store = tx.objectStore("dns_events");
        const getReq = store.getAll();
        getReq.onsuccess = () => {
          setEvents((getReq.result || []).sort((a,b) => b.timestamp - a.timestamp));
        };
      }
    };
  };

  useEffect(() => {
    fetchEvents();
    const interval = setInterval(fetchEvents, 5000);
    
    const listener = (msg) => {
      if (msg.type === "DNS_EVENT") {
        setEvents(prev => [msg.payload, ...prev]);
      }
    };
    chrome.runtime.onMessage.addListener(listener);
    
    return () => {
        clearInterval(interval);
        chrome.runtime.onMessage.removeListener(listener);
    };
  }, []);

  const getTierBadge = (tier) => {
      const colors = {
          'CRITICAL': 'bg-red-500 text-white',
          'HIGH': 'bg-red-500 text-white',
          'BLOCK': 'bg-orange-500 text-white',
          'MEDIUM': 'bg-orange-500 text-white',
          'ALERT': 'bg-yellow-500 text-black',
          'MONITOR': 'bg-blue-500 text-white',
          'LOW': 'bg-blue-500 text-white'
      };
      return <span className={`px-2 py-0.5 rounded text-xs font-bold ${colors[tier] || 'bg-slate-500 text-white'}`}>{tier}</span>;
  };

  return (
    <div className="flex h-screen bg-slate-950 text-slate-300">
        <div className="w-64 bg-slate-900 border-r border-slate-800 p-4 flex flex-col gap-6">
            <div className="flex items-center gap-2">
                <Shield className="w-8 h-8 text-cyan-500" />
                <h1 className="text-xl font-bold text-white">DNSentinel</h1>
            </div>
            
            <nav className="flex flex-col gap-2">
                <a href="#" className="flex items-center gap-2 px-3 py-2 bg-slate-800 text-cyan-400 rounded">
                    <Activity className="w-5 h-5" /> Live Telemetry
                </a>
                <a href="#" className="flex items-center gap-2 px-3 py-2 hover:bg-slate-800/50 rounded">
                    <List className="w-5 h-5" /> SOAR Log
                </a>
                <a href="#" className="flex items-center gap-2 px-3 py-2 hover:bg-slate-800/50 rounded">
                    <Settings className="w-5 h-5" /> Settings
                </a>
            </nav>
            
            <div className="mt-auto p-4 bg-slate-800/50 rounded border border-slate-700/50">
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Engine Status</h3>
                <div className="flex items-center gap-2 text-sm text-green-400">
                    <CheckCircle className="w-4 h-4" /> Local heuristics + API scoring
                </div>
            </div>
        </div>
        
        <div className="flex-1 flex flex-col overflow-hidden">
            <header className="p-4 border-b border-slate-800 bg-slate-900/50 flex justify-between items-center">
                <h2 className="text-lg font-semibold text-white">Forensic Dashboard</h2>
                <div className="text-sm">Total Events: {events.length}</div>
            </header>
            
            <main className="flex-1 overflow-auto p-6">
                <div className="bg-slate-900 rounded-lg border border-slate-800 overflow-hidden shadow-xl">
                    <table className="w-full text-left text-sm">
                        <thead className="bg-slate-800 text-slate-400">
                            <tr>
                                <th className="px-4 py-3">Timestamp</th>
                                <th className="px-4 py-3">Domain</th>
                                <th className="px-4 py-3">Tier</th>
                                <th className="px-4 py-3">Score</th>
                                <th className="px-4 py-3">Entropy</th>
                                <th className="px-4 py-3">XAI Explanation</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/50">
                            {events.map((ev, i) => (
                                <tr key={i} className="hover:bg-slate-800/30 transition-colors">
                                    <td className="px-4 py-3 whitespace-nowrap">{new Date(ev.timestamp).toLocaleTimeString()}</td>
                                    <td className="px-4 py-3 font-mono text-cyan-300">{ev.domain}</td>
                                    <td className="px-4 py-3">{getTierBadge(ev.tier)}</td>
                                    <td className="px-4 py-3 font-bold">{Math.round(ev.final_score)}</td>
                                    <td className="px-4 py-3 text-slate-500">{ev.features?.entropy?.toFixed(2)}</td>
                                    <td className="px-4 py-3 text-xs text-slate-400 max-w-xs truncate" title={ev.shap_reason}>
                                        {ev.shap_reason || "-"}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </main>
        </div>
    </div>
  );
};

const root = createRoot(document.getElementById('root'));
root.render(<Panel />);
