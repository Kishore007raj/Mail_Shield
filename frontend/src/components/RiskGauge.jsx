import React from 'react';
import { motion } from 'framer-motion';

export default function RiskGauge({ score, classification }) {
  const circumference = 2 * Math.PI * 54;
  const progress = (score / 100) * circumference;
  const offset = circumference - progress;

  const getColor = () => {
    if (classification === 'Phishing') return { stroke: '#ef4444', glow: 'rgba(239, 68, 68, 0.3)', text: 'text-danger-400', bg: 'bg-danger-500/10' };
    if (classification === 'Suspicious') return { stroke: '#f59e0b', glow: 'rgba(245, 158, 11, 0.3)', text: 'text-warning-400', bg: 'bg-warning-500/10' };
    return { stroke: '#22c55e', glow: 'rgba(34, 197, 94, 0.3)', text: 'text-safe-400', bg: 'bg-safe-500/10' };
  };

  const colors = getColor();

  return (
    <motion.div
      initial={{ scale: 0.8, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      transition={{ duration: 0.5, ease: 'easeOut' }}
      className="flex flex-col items-center"
    >
      <div className="relative w-40 h-40">
        <svg className="w-40 h-40 transform -rotate-90" viewBox="0 0 120 120">
          <circle
            cx="60"
            cy="60"
            r="54"
            fill="none"
            stroke="#1e293b"
            strokeWidth="8"
          />
          <motion.circle
            cx="60"
            cy="60"
            r="54"
            fill="none"
            stroke={colors.stroke}
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset: offset }}
            transition={{ duration: 1.2, ease: 'easeOut', delay: 0.3 }}
            style={{
              filter: `drop-shadow(0 0 8px ${colors.glow})`,
            }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <motion.span
            className={`text-4xl font-bold ${colors.text}`}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.5 }}
          >
            {score}
          </motion.span>
          <span className="text-xs text-surface-500 font-medium">/ 100</span>
        </div>
      </div>

      <motion.div
        initial={{ y: 10, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ delay: 0.7 }}
        className={`mt-4 px-5 py-2 rounded-full text-sm font-bold ${colors.bg} ${colors.text} border border-current/20`}
      >
        {classification === 'Phishing' && '⚠ '}
        {classification === 'Suspicious' && '⚡ '}
        {classification === 'Safe' && '✓ '}
        {classification}
      </motion.div>
    </motion.div>
  );
}
