import React from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import RiskGauge from '../components/RiskGauge';
import DetailSection from '../components/DetailSection';

export default function ResultPage({ result }) {
  const navigate = useNavigate();

  if (!result) {
    return (
      <div className="pt-20 text-center">
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="glass-card p-12 max-w-md mx-auto"
        >
          <div className="text-4xl mb-4">🔎</div>
          <h2 className="text-xl font-semibold text-surface-200 mb-2">No Analysis Result</h2>
          <p className="text-surface-400 text-sm mb-6">Submit an email for analysis first.</p>
          <button onClick={() => navigate('/')} className="btn-primary">
            Go to Analyzer
          </button>
        </motion.div>
      </div>
    );
  }

  const { risk_score, classification, reasons, details, subject, sender, receiver, analyzed_at, id } = result;
  const { rule_flags = [], urls = [], header_issues = [], ml_prediction = {} } = details || {};

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: { staggerChildren: 0.1 },
    },
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 15 },
    visible: { opacity: 1, y: 0 },
  };

  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      animate="visible"
      className="pt-8 sm:pt-12 max-w-4xl mx-auto"
    >
      {/* Header Row */}
      <motion.div variants={itemVariants} className="flex items-center justify-between mb-8">
        <div>
          <button
            onClick={() => navigate('/')}
            className="flex items-center gap-2 text-sm text-surface-400 hover:text-surface-200 transition-colors mb-2"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
            New Analysis
          </button>
          <h1 className="text-2xl font-bold text-gradient">Analysis Report</h1>
        </div>
        <div className="text-right">
          <span className="text-xs text-surface-500 font-mono">ID: #{id}</span>
          {analyzed_at && (
            <p className="text-xs text-surface-500 mt-0.5">
              {new Date(analyzed_at).toLocaleString()}
            </p>
          )}
        </div>
      </motion.div>

      {/* Risk Score + Email Info */}
      <motion.div variants={itemVariants} className="glass-card p-6 sm:p-8 mb-6">
        <div className="flex flex-col sm:flex-row items-center sm:items-start gap-8">
          <RiskGauge score={risk_score} classification={classification} />

          <div className="flex-1 space-y-4 w-full">
            <div>
              <h2 className="text-lg font-semibold text-surface-200 mb-3">Email Summary</h2>
              <div className="space-y-2">
                {subject && (
                  <div className="flex items-start gap-2">
                    <span className="text-xs text-surface-500 font-semibold uppercase w-16 flex-shrink-0 pt-0.5">Subject</span>
                    <span className="text-sm text-surface-200 font-medium">{subject}</span>
                  </div>
                )}
                {sender && (
                  <div className="flex items-start gap-2">
                    <span className="text-xs text-surface-500 font-semibold uppercase w-16 flex-shrink-0 pt-0.5">From</span>
                    <span className="text-sm text-surface-300 font-mono">{sender}</span>
                  </div>
                )}
                {receiver && (
                  <div className="flex items-start gap-2">
                    <span className="text-xs text-surface-500 font-semibold uppercase w-16 flex-shrink-0 pt-0.5">To</span>
                    <span className="text-sm text-surface-300 font-mono">{receiver}</span>
                  </div>
                )}
              </div>
            </div>

            {/* ML Prediction Badge */}
            {ml_prediction && ml_prediction.available && (
              <div className="flex items-center gap-3 pt-2 border-t border-surface-800/50">
                <span className="text-xs text-surface-500 font-semibold uppercase">ML Model</span>
                <span className={`px-3 py-1 rounded-full text-xs font-bold ${
                  ml_prediction.prediction === 'phishing'
                    ? 'bg-danger-500/15 text-danger-400'
                    : 'bg-safe-500/15 text-safe-400'
                }`}>
                  {ml_prediction.prediction} — {(ml_prediction.confidence * 100).toFixed(1)}%
                </span>
              </div>
            )}
          </div>
        </div>
      </motion.div>

      {/* Reasons */}
      <motion.div variants={itemVariants} className="glass-card p-6 mb-6">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-surface-200 mb-4">
          <span>📋</span> Analysis Reasons
        </h3>
        <div className="space-y-2">
          {reasons.map((reason, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.3 + i * 0.08 }}
              className="flex items-start gap-3 px-3.5 py-2.5 rounded-lg bg-surface-800/40 border border-surface-700/25"
            >
              <span className={`mt-0.5 text-sm ${
                classification === 'Phishing' ? 'text-danger-400' :
                classification === 'Suspicious' ? 'text-warning-400' :
                'text-safe-400'
              }`}>
                {classification === 'Phishing' ? '⚠' : classification === 'Suspicious' ? '⚡' : '✓'}
              </span>
              <span className="text-sm text-surface-300">{reason}</span>
            </motion.div>
          ))}
        </div>
      </motion.div>

      {/* Detail Sections */}
      <motion.div variants={itemVariants} className="space-y-4 mb-8">
        <DetailSection
          title="Rule-Based Flags"
          icon="🛡"
          items={rule_flags}
          type="rule"
        />
        <DetailSection
          title="Suspicious URLs"
          icon="🔗"
          items={urls}
          type="url"
        />
        <DetailSection
          title="Header Forensics"
          icon="🔬"
          items={header_issues}
          type="header"
        />
      </motion.div>

      {/* ML Details */}
      {ml_prediction && ml_prediction.available && ml_prediction.probabilities && (
        <motion.div variants={itemVariants} className="glass-card p-6 mb-8">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-surface-200 mb-4">
            <span>🤖</span> ML Model Details
          </h3>
          <div className="grid grid-cols-2 gap-4">
            {Object.entries(ml_prediction.probabilities).map(([label, prob]) => (
              <div key={label} className="relative">
                <div className="flex justify-between text-xs mb-1.5">
                  <span className="text-surface-400 font-medium capitalize">{label}</span>
                  <span className="text-surface-300 font-mono">{(prob * 100).toFixed(1)}%</span>
                </div>
                <div className="h-2 bg-surface-800 rounded-full overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${prob * 100}%` }}
                    transition={{ duration: 0.8, delay: 0.5 }}
                    className={`h-full rounded-full ${
                      label === 'phishing'
                        ? 'bg-gradient-to-r from-danger-500 to-orange-500'
                        : 'bg-gradient-to-r from-safe-500 to-emerald-400'
                    }`}
                  />
                </div>
              </div>
            ))}
          </div>
        </motion.div>
      )}
    </motion.div>
  );
}
