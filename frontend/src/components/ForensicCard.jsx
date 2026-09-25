import { motion } from 'framer-motion';
import { AlertTriangle, ChevronRight } from 'lucide-react';
import { SeverityLevel } from './primitives';
import { formatTime } from '../utils/format';

export const ForensicCard = ({ alert, onClick }) => (
  <motion.div
    layout initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, x: 20 }}
    onClick={onClick}
    className={`p-6 rounded-3xl border-l-[6px] cursor-pointer transition-all hover:bg-black/40 mb-5 relative group border border-white/5
      ${alert.risk_level === 'Critical' ? 'bg-purple-900/10 border-l-purple-500 shadow-purple-500/10' :
        alert.risk_level === 'High' ? 'bg-rose-900/10 border-l-rose-500 shadow-rose-500/10' :
        'bg-slate-900/40 border-l-amber-500 shadow-amber-500/5'}
    `}
  >
     <div className="flex justify-between items-start mb-4">
        <span className="text-[10px] font-bold font-mono text-slate-600 tracking-widest">{formatTime(alert.timestamp)}</span>
        <SeverityLevel level={alert.risk_level} />
     </div>
     <div className="flex items-center gap-4 mb-4">
        <div className={`p-2.5 rounded-xl ${alert.risk_level === 'Critical' ? 'bg-purple-500/20 text-purple-400' : 'bg-rose-500/20 text-rose-400'}`}>
           <AlertTriangle size={18}/>
        </div>
        <p className="font-mono text-xs text-white/90 break-all leading-relaxed font-bold tracking-tight">{alert.query}</p>
     </div>
     <div className="flex items-center justify-between border-t border-white/5 pt-4">
        <div className="flex items-center gap-3">
           <div className={`w-2 h-2 rounded-full ${alert.risk_level === 'Critical' ? 'bg-purple-500' : 'bg-rose-500'} animate-pulse`}></div>
           <span className="text-[10px] text-slate-600 font-bold uppercase tracking-widest">{alert.source_ip}</span>
        </div>
        <ChevronRight size={18} className="text-slate-600 group-hover:text-white group-hover:translate-x-1 transition-all" />
     </div>
  </motion.div>
);
