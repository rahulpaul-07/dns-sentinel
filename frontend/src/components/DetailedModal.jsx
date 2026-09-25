import { motion } from 'framer-motion';
import { Shield, Terminal, Zap, Crosshair, X, Globe, Lock, Server, Eye, ExternalLink, BarChart2, FileText } from 'lucide-react';
import { SeverityLevel, ModalStat, SHAPBar } from './primitives';
import { formatDateTime } from '../utils/format';

export const DetailedModal = ({ log, onClose, onBlock, onBenign, onReport, onPDF }) => {
  const features = log.features || {};
  const explanation = log.explanation || '';
  const shapText = explanation.split('[XAI: SHAP] ')[1];
  return (
  <motion.div
    initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
    className="fixed inset-0 z-[100] bg-black/95 backdrop-blur-3xl flex justify-center items-start overflow-y-auto p-4 sm:p-10 custom-scrollbar"
    onClick={onClose}
  >
    <motion.div
      initial={{ scale: 0.9, opacity: 0, y: 30 }} animate={{ scale: 1, opacity: 1, y: 0 }} exit={{ scale: 0.9, opacity: 0, y: 30 }}
      className="glass-panel max-w-4xl w-full p-8 sm:p-12 relative border-white/10 shadow-[0_0_100px_rgba(0,0,0,0.9)] my-auto"
      onClick={e => e.stopPropagation()}
    >
      <div className="flex justify-between items-start mb-10 pb-5 border-b border-white/5">
        <div>
           <div className="flex items-center gap-5 mb-3">
              <div className="p-3 bg-[#00f2ff]/10 rounded-2xl border border-[#00f2ff]/20 shadow-[0_0_20px_rgba(0,242,255,0.1)]"><Eye className="text-[#00f2ff]" size={28}/></div>
              <h2 className="text-2xl font-bold tracking-[0.3em] text-white uppercase drop-shadow-glow">Query Analysis</h2>
           </div>
           <p className="text-[10px] text-slate-600 font-mono tracking-[0.4em] uppercase">{formatDateTime(log.timestamp)}</p>
        </div>
        <button onClick={onClose} aria-label="Close" className="p-3 bg-white/5 rounded-2xl hover:bg-white/10 hover:rotate-90 transition-all"><X size={24} className="text-slate-400"/></button>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-3 gap-6 mb-10">
         <ModalStat label="Source IP" value={log.source_ip} icon={<Server size={14}/>} />
         <ModalStat label="Record Type" value={log.qtype} icon={<Globe size={14}/>} />
         <ModalStat label="Alert ID" value={log.db_id ? `SOC-${log.db_id}` : 'pending'} icon={<Lock size={14}/>} />
         <div className="col-span-2 lg:col-span-3 bg-black/60 p-8 rounded-3xl border border-white/5 group">
            <p className="text-[10px] text-slate-600 font-bold uppercase tracking-[0.3em] mb-4">Queried Name</p>
            <p className="font-mono text-[#00f2ff] text-lg leading-relaxed break-all select-all group-hover:text-white transition-colors">{log.query}</p>
         </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-10">
         <div className="space-y-8">
            <div className="bg-slate-900/60 p-8 rounded-3xl border border-white/5 space-y-6">
                <div className="flex justify-between items-center mb-2">
                   <span className="text-[10px] text-slate-500 font-bold uppercase tracking-[0.3em]">
                     Risk {log.risk_score}{typeof log.ml_probability === 'number' ? ` | P(malicious) ${log.ml_probability}` : ''}
                   </span>
                   <SeverityLevel level={log.risk_level} />
                </div>

                <div className="space-y-5">
                   <SHAPBar label="Shannon Entropy (bits/char)" value={features.entropy ?? 0} max={6} color="#00f2ff" />
                   <SHAPBar label="Length x Entropy Complexity" value={features.domain_complexity ?? 0} max={300} color="#8b5cf6" />
                   <SHAPBar label="Non-English Bigram Score" value={1 - (features.ngram_score ?? 1)} max={1} color="#f43f5e" />
                   <SHAPBar label="Label Count" value={features.labels ?? 0} max={10} color="#f59e0b" />
                </div>

                {log.isolation_outlier && (
                  <div className="mt-8 bg-purple-500/10 border border-purple-500/20 p-4 rounded-2xl flex items-center gap-4 animate-in">
                     <Zap size={22} className="text-purple-400 animate-pulse"/>
                     <div>
                        <p className="text-[10px] font-bold text-purple-400 uppercase tracking-widest">Isolation Forest Outlier</p>
                        <p className="text-[9px] text-slate-500 font-bold uppercase tracking-tighter mt-0.5">Feature vector is unusual relative to the training data</p>
                     </div>
                  </div>
                )}
            </div>
         </div>

         <div className="space-y-8">
            <div className="relative">
               <div className="bg-emerald-500/5 border-l-4 border-emerald-400 p-6 rounded-r-3xl italic relative min-h-[120px] flex items-center shadow-xl">
                  <div className="absolute -top-3 left-6 bg-emerald-400 text-black text-[9px] font-bold px-3 py-1 rounded-full uppercase tracking-tighter font-mono">ANALYSIS</div>
                  <p className="text-sm text-slate-300 leading-relaxed font-medium">"{explanation.split(' | ')[0] || 'No explanation recorded.'}"</p>
               </div>
            </div>

            {shapText && (
              <div className="bg-indigo-500/10 border border-indigo-500/20 p-8 rounded-3xl relative group reveal-card">
                 <BarChart2 size={24} className="absolute right-6 top-6 text-indigo-400 opacity-20 group-hover:opacity-100 transition-opacity" />
                 <p className="text-[11px] text-indigo-400 font-bold uppercase tracking-[0.3em] mb-4">SHAP Feature Attribution</p>
                 <p className="text-xs text-indigo-200 font-mono leading-relaxed opacity-70 italic">"{shapText.split(' | PIE')[0]}"</p>
              </div>
            )}

            {log.mitre && Object.entries(log.mitre).length > 0 && (
               <div className="pt-6 border-t border-white/5">
                  <h4 className="text-[11px] font-bold text-slate-600 uppercase tracking-[0.3em] mb-6 flex items-center gap-3">
                     <Lock size={16}/> MITRE ATT&CK Correlation
                  </h4>
                  <div className="space-y-4">
                     {Object.entries(log.mitre).map(([id, info]) => (
                       <a key={id} href={`https://attack.mitre.org/techniques/${id.replace('.', '/')}/`} target="_blank" rel="noreferrer" className="block bg-rose-500/5 border border-rose-500/10 p-5 rounded-2xl group hover:bg-rose-500/10 transition-all">
                          <div className="flex items-center justify-between mb-4">
                             <div className="flex items-center gap-3">
                                <span className="text-[11px] font-bold text-rose-400 border border-rose-400/30 px-3 py-1 rounded-lg bg-rose-500/10 font-mono">{id}</span>
                                <span className="text-sm font-bold text-slate-200 group-hover:text-white">{info.Name}</span>
                             </div>
                             <ExternalLink size={14} className="text-rose-500/40" />
                          </div>
                          <p className="text-[11px] text-slate-500 leading-relaxed mb-4 group-hover:text-slate-400">{info.Description}</p>
                          {info.Mitigation && (
                            <div className="bg-black/40 p-4 rounded-xl border border-white/5 border-l-2 border-l-rose-500">
                               <p className="text-[11px] text-slate-300 leading-loose italic">"{info.Mitigation}"</p>
                            </div>
                          )}
                       </a>
                     ))}
                  </div>
               </div>
            )}

            {features.intel_data && (
              <div className="pt-8 border-t border-white/5 space-y-6">
                 <h4 className="text-[11px] font-bold text-amber-500 uppercase tracking-[0.3em] flex items-center gap-3">
                    <Crosshair size={16}/> Threat Intelligence
                 </h4>
                 <div className="bg-amber-500/5 border border-amber-500/10 p-6 rounded-3xl space-y-6 group hover:bg-amber-500/10 transition-all">
                    <div className="flex justify-between items-center">
                       <span className="text-[10px] text-slate-500 font-bold uppercase tracking-widest">Reputation Score</span>
                       <div className="flex items-center gap-2">
                          <div className="h-1.5 w-24 bg-white/5 rounded-full overflow-hidden">
                             <div className="h-full bg-amber-500 shadow-[0_0_10px_#f59e0b]" style={{ width: `${features.intel_data.reputation_score}%` }}></div>
                          </div>
                          <span className="text-xs font-mono font-bold text-amber-400">{features.intel_data.reputation_score}/100</span>
                       </div>
                    </div>

                    <div className="flex flex-wrap gap-2">
                       {(features.intel_data.sources || []).map(s => (
                         <span key={s} className="px-3 py-1 bg-white/5 border border-white/10 rounded-lg text-[9px] font-bold text-slate-400 uppercase tracking-widest">{s}</span>
                       ))}
                    </div>

                    <div className="flex flex-wrap gap-2">
                       {features.intel_data.threat_tags?.map(tag => (
                         <span key={tag} className="px-3 py-1 bg-amber-500/10 border border-amber-500/20 rounded-lg text-[9px] font-bold text-amber-500 uppercase tracking-tighter"># {tag}</span>
                       ))}
                    </div>
                 </div>
              </div>
            )}
         </div>
      </div>

      {/* SOAR Action Toolbar */}
      <div className="mt-12 pt-10 border-t border-white/5 flex flex-wrap gap-6">
         <button onClick={() => onBlock(log)} className="flex-1 min-w-[180px] py-5 bg-rose-500/10 hover:bg-rose-500/20 text-rose-500 border border-rose-500/30 rounded-2xl text-[11px] font-bold tracking-[0.3em] transition-all flex justify-center items-center gap-4 group">
            <Shield size={18} className="group-hover:scale-110 transition-transform"/> BLOCK SOURCE IP
         </button>
         <button onClick={() => onBenign(log)} className="flex-1 min-w-[180px] py-5 bg-white/5 hover:bg-white/10 text-slate-400 border border-white/10 rounded-2xl text-[11px] font-bold tracking-[0.3em] transition-all flex justify-center items-center gap-4 group">
            <Eye size={18} className="group-hover:text-white transition-colors"/> MARK FALSE POSITIVE
         </button>
         <button onClick={() => onReport(log)} className="flex-1 min-w-[180px] py-5 bg-[#00f2ff]/10 hover:bg-[#00f2ff]/20 text-[#00f2ff] border border-[#00f2ff]/30 rounded-2xl text-[11px] font-bold tracking-[0.3em] transition-all flex justify-center items-center gap-4 group shadow-lg shadow-cyan-500/5">
            <Terminal size={18} className="animate-pulse"/> INCIDENT REPORT
         </button>
         <button onClick={() => onPDF(log)} className="flex-1 min-w-[180px] py-5 bg-emerald-500/10 hover:bg-emerald-400/20 text-emerald-400 border border-emerald-500/30 rounded-2xl text-[11px] font-bold tracking-[0.3em] transition-all flex justify-center items-center gap-4 group">
            <FileText size={18} className="group-hover:scale-110 transition-transform"/> DOWNLOAD PDF
         </button>
      </div>
    </motion.div>
  </motion.div>
  );
};

/* Helper UI Shells */
