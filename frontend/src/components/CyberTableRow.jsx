import { motion } from 'framer-motion';
import { SeverityLevel } from './primitives';
import { formatScore, formatTime } from '../utils/format';

export const CyberTableRow = ({ row, onClick }) => (
  <motion.tr
    layout initial={{ opacity: 0 }} animate={{ opacity: 1 }}
    onClick={onClick}
    className="hover:bg-white/[0.04] transition-all cursor-pointer group hover:shadow-[inset_4px_0_0_0_#00f2ff]"
  >
    <td className="py-6 px-4 font-mono text-[10px] text-slate-600 group-hover:text-slate-400 tabular-nums">
      {formatTime(row.timestamp)}
    </td>
    <td className="py-6 px-2 font-mono text-xs text-slate-300 group-hover:text-[#00f2ff] transition-colors tabular-nums">
      {row.source_ip}
    </td>
    <td className="py-6 px-2">
       <div className="flex items-center gap-4">
          <span className="text-[9px] font-bold bg-white/5 border border-white/5 px-2.5 py-1 rounded text-slate-500 font-mono uppercase truncate">{row.qtype}</span>
          <p className="font-mono text-xs text-white/80 truncate max-w-[250px] 2xl:max-w-[450px] tracking-tight">
            {row.intel_hit && <span className="mr-3 text-amber-500" title="Threat-intel hit">&#9679;</span>}
            {row.query}
          </p>
       </div>
    </td>
    <td className="py-6 px-2 text-center">
       <div className={`px-4 py-1.5 rounded-full inline-block font-mono text-xs border font-bold tabular-nums shadow-lg
          ${row.risk_score > 80 ? 'bg-purple-500/20 text-purple-400 border-purple-500/40 shadow-purple-900/10' :
            row.risk_score > 50 ? 'bg-rose-500/20 text-rose-400 border-rose-500/40 shadow-rose-900/10' :
            'bg-slate-900/80 text-slate-400 border-white/5 shadow-black/20'}
       `}>
          {formatScore(row.risk_score)}
       </div>
    </td>
    <td className="py-6 px-4 text-right">
       <SeverityLevel level={row.risk_level} />
    </td>
  </motion.tr>
);
