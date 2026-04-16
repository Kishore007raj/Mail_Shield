import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

export default function DetailSection({ title, icon, items, type }) {
  const [isOpen, setIsOpen] = useState(true);

  if (!items || items.length === 0) return null;

  const getSeverityClass = (severity) => {
    switch (severity) {
      case 'critical': return 'severity-critical';
      case 'high': return 'severity-high';
      case 'medium': return 'severity-medium';
      case 'low': return 'severity-low';
      default: return 'text-surface-400';
    }
  };

  const getSeverityBg = (severity) => {
    switch (severity) {
      case 'critical': return 'bg-danger-500/8 border-danger-500/15';
      case 'high': return 'bg-orange-500/8 border-orange-500/15';
      case 'medium': return 'bg-warning-500/8 border-warning-500/15';
      case 'low': return 'bg-surface-500/8 border-surface-500/15';
      default: return 'bg-surface-800/40 border-surface-700/30';
    }
  };

  const getSeverityDot = (severity) => {
    switch (severity) {
      case 'critical': return 'bg-danger-400';
      case 'high': return 'bg-orange-400';
      case 'medium': return 'bg-warning-400';
      case 'low': return 'bg-surface-400';
      default: return 'bg-surface-500';
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-card overflow-hidden"
    >
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between px-5 py-4 hover:bg-surface-800/30 transition-colors"
      >
        <div className="flex items-center gap-3">
          <span className="text-lg">{icon}</span>
          <h3 className="text-sm font-semibold text-surface-200">{title}</h3>
          <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-surface-800 text-surface-400 border border-surface-700/50">
            {items.length}
          </span>
        </div>
        <motion.svg
          animate={{ rotate: isOpen ? 180 : 0 }}
          transition={{ duration: 0.2 }}
          className="w-4 h-4 text-surface-500"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </motion.svg>
      </button>

      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="px-5 pb-4 space-y-2">
              {items.map((item, index) => (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.05 }}
                  className={`flex items-start gap-3 px-3.5 py-3 rounded-xl border ${getSeverityBg(item.severity)}`}
                >
                  <div className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${getSeverityDot(item.severity)}`} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-surface-200 leading-relaxed">
                      {item.description || item.issue || item.url || JSON.stringify(item)}
                    </p>
                    <div className="flex items-center gap-3 mt-1.5">
                      {item.severity && (
                        <span className={`text-xs font-semibold uppercase tracking-wide ${getSeverityClass(item.severity)}`}>
                          {item.severity}
                        </span>
                      )}
                      {item.rule && (
                        <span className="text-xs text-surface-500 font-mono">
                          {item.rule}
                        </span>
                      )}
                      {item.issue && type === 'url' && (
                        <span className="text-xs text-surface-500 font-mono">
                          {item.issue}
                        </span>
                      )}
                      {item.url && type === 'url' && (
                        <span className="text-xs text-surface-500 font-mono truncate max-w-xs">
                          {item.url}
                        </span>
                      )}
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
