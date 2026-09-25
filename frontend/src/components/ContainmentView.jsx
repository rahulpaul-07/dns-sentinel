import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Shield, AlertTriangle, Clock, Unlock } from 'lucide-react';
import { fetchBlocked, unblockEntity } from '../services/api';
import { formatDateTime } from '../utils/format';

export const ContainmentView = () => {
  const [blocks, setBlocks] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);

  const refreshBlocks = () => {
    fetchBlocked()
      .then(data => { setBlocks(data); setError(null); })
      .catch(err => setError(err.message))
      .finally(() => setIsLoading(false));
  };

  useEffect(() => {
    refreshBlocks();
    const interval = setInterval(refreshBlocks, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleUnblock = async (target) => {
    try {
      await unblockEntity(target);
    } catch (err) {
      setError(`Unblock failed: ${err.message}`);
    }
    refreshBlocks();
  };

  return (
    <div className="space-y-8 min-h-[820px]">
       <div className="flex justify-between items-end mb-4">
          <div>
            <h2 className="text-2xl font-bold tracking-[0.2em] text-white uppercase drop-shadow-glow flex items-center gap-4">
               <Shield className="text-rose-500" size={24}/> Active Containment Rules
            </h2>
            <p className="text-[10px] text-slate-500 font-mono tracking-widest uppercase mt-2">SOAR rules with automatic 24-hour expiry</p>
          </div>
          <div className="px-4 py-2 bg-rose-500/10 border border-rose-500/20 rounded-xl">
             <span className="text-[10px] font-bold text-rose-400 uppercase tracking-widest">{blocks.length} ACTIVE BLOCKS</span>
          </div>
       </div>

       {error && <p role="alert" className="text-xs font-mono text-rose-400">{error}</p>}
       <div className="glass-panel overflow-hidden">
          <table className="w-full text-left border-collapse">
             <thead>
                <tr className="bg-white/5 border-b border-white/5">
                   <th className="p-6 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Target Entity</th>
                   <th className="p-6 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Rule Class</th>
                   <th className="p-6 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Reason</th>
                   <th className="p-6 text-[10px] font-bold text-slate-500 uppercase tracking-widest text-center">Risk Score</th>
                   <th className="p-6 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Expires</th>
                   <th className="p-6 text-[10px] font-bold text-slate-500 uppercase tracking-widest text-right">Actions</th>
                </tr>
             </thead>
             <tbody className="divide-y divide-white/5">
                {isLoading ? (
                  <tr><td colSpan="6" className="p-20 text-center text-slate-600 animate-pulse">Loading rules...</td></tr>
                ) : blocks.length === 0 ? (
                  <tr><td colSpan="6" className="p-20 text-center text-slate-600 italic">No active network rules currently enforced.</td></tr>
                ) : (
                  blocks.map((block) => (
                    <motion.tr
                      key={block.target} initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                      className="hover:bg-white/[0.02] transition-colors group"
                    >
                       <td className="p-6">
                          <div className="flex items-center gap-3">
                             <div className="w-2 h-2 rounded-full bg-rose-500 animate-pulse"></div>
                             <span className="font-mono text-sm font-bold text-white group-hover:text-rose-400 transition-colors">{block.target}</span>
                          </div>
                       </td>
                       <td className="p-6">
                          <span className="px-3 py-1 bg-white/5 border border-white/10 rounded-lg text-[9px] font-bold text-slate-400 uppercase">{block.rule_type}</span>
                       </td>
                       <td className="p-6 max-w-[300px]">
                          <p className="text-xs text-slate-500 truncate">{block.reason}</p>
                       </td>
                       <td className="p-6 text-center">
                          <span className="font-mono text-sm font-bold text-rose-500">{block.risk_score}</span>
                       </td>
                       <td className="p-6">
                          <div className="flex items-center gap-2 text-slate-400">
                             <Clock size={12}/>
                             <span className="text-[10px] font-mono">
                                {formatDateTime(block.expires_at)}
                             </span>
                          </div>
                       </td>
                       <td className="p-6 text-right">
                          <button
                            onClick={() => handleUnblock(block.target)}
                            className="p-2 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-500 border border-emerald-500/30 rounded-lg transition-all group-hover:scale-110"
                            title="Revoke rule"
                            aria-label={`Revoke rule for ${block.target}`}
                          >
                             <Unlock size={14}/>
                          </button>
                       </td>
                    </motion.tr>
                  ))
                )}
             </tbody>
          </table>
       </div>

       <div className="grid grid-cols-1 md:grid-cols-3 gap-8 pt-10">
          <div className="glass-panel p-8 space-y-4 border-l-4 border-l-amber-500">
             <div className="flex items-center gap-3 text-amber-500 mb-2">
                <AlertTriangle size={18}/>
                <h4 className="text-xs font-bold uppercase tracking-widest">Domain Sinkhole</h4>
             </div>
             <p className="text-[10px] text-slate-500 leading-relaxed uppercase">DOMAIN_SINKHOLE rules point a validated hostname at 127.0.0.1 via a tagged hosts-file entry, removed exactly when the rule expires or is revoked.</p>
          </div>
          <div className="glass-panel p-8 space-y-4 border-l-4 border-l-rose-500">
             <div className="flex items-center gap-3 text-rose-500 mb-2">
                <Shield size={18}/>
                <h4 className="text-xs font-bold uppercase tracking-widest">L3/L4 Firewall Rules</h4>
             </div>
             <p className="text-[10px] text-slate-500 leading-relaxed uppercase">IP_BLOCK rules map to iptables/ip6tables (Linux) or netsh (Windows). By default the backend runs in dry-run mode: rules are recorded and logged but not applied.</p>
          </div>
          <div className="glass-panel p-8 space-y-4 border-l-4 border-l-blue-500">
             <div className="flex items-center gap-3 text-blue-500 mb-2">
                <Clock size={18}/>
                <h4 className="text-xs font-bold uppercase tracking-widest">Automatic Remediation</h4>
             </div>
             <p className="text-[10px] text-slate-500 leading-relaxed uppercase">Every rule expires after 24 hours. A background task sweeps once a minute and revokes expired rules, so a false positive can never cause a permanent outage.</p>
          </div>
       </div>
    </div>
  );
};
