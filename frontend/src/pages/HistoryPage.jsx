import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL || '';

export default function HistoryPage() {
  const [records, setRecords] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedId, setSelectedId] = useState(null);
  const [detail, setDetail] = useState(null);

  useEffect(() => {
    fetchHistory();
  }, []);

  const fetchHistory = async () => {
    try {
      const res = await axios.get(`${API_BASE}/api/history?limit=50`);
      setRecords(res.data);
    } catch (err) {
      setError('Failed to load history');
    } finally {
      setLoading(false);
    }
  };

  const viewDetail = async (id) => {
    if (selectedId === id) {
      setSelectedId(null);
      setDetail(null);
      return;
    }
    try {
      const res = await axios.get(`${API_BASE}/api/history/${id}`);
      setDetail(res.data);
      setSelectedId(id);
    } catch (err) {
      setError('Failed to load details');
    }
  };

  const getClassBadge = (classification) => {
    switch (classification) {
      case 'Phishing': return 'badge-phishing';
      case 'Suspicious': return 'badge-suspicious';
      default: return 'badge-safe';
    }
  };

  const getScoreColor = (score) => {
    if (score >= 70) return 'text-danger-400';
    if (score >= 30) return 'text-warning-400';
    return 'text-safe-400';
  };

  if (loading) {
    return (
      <div className="pt-20 flex justify-center">
        <svg className="animate-spin w-8 h-8 text-accent-400" viewBox="0 0 24 24" fill="none">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
      </div>
    );
  }

  return (
    <div className="pt-8 sm:pt-12 max-w-4xl mx-auto">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="mb-8"
      >
        <h1 className="text-2xl font-bold text-gradient mb-2">Analysis History</h1>
        <p className="text-surface-400 text-sm">
          {records.length} recorded analysis{records.length !== 1 ? 'es' : ''}
        </p>
      </motion.div>

      {error && (
        <div className="mb-6 px-4 py-3 rounded-xl bg-danger-500/10 border border-danger-500/20 text-danger-400 text-sm">
          {error}
        </div>
      )}

      {records.length === 0 ? (
        <div className="glass-card p-12 text-center">
          <div className="text-4xl mb-4">📭</div>
          <h2 className="text-lg font-semibold text-surface-300 mb-2">No Analysis History</h2>
          <p className="text-surface-500 text-sm">Analyzed emails will appear here.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {records.map((record, index) => (
            <motion.div
              key={record.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.03 }}
            >
              <button
                onClick={() => viewDetail(record.id)}
                className="w-full text-left glass-card-hover p-4 sm:p-5"
              >
                <div className="flex items-center justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 mb-1.5">
                      <span className={`text-lg font-bold font-mono ${getScoreColor(record.risk_score)}`}>
                        {record.risk_score}
                      </span>
                      <span className={getClassBadge(record.classification)}>
                        {record.classification}
                      </span>
                    </div>
                    <p className="text-sm text-surface-200 font-medium truncate">
                      {record.subject || '(No subject)'}
                    </p>
                    <p className="text-xs text-surface-500 mt-0.5 font-mono truncate">
                      {record.sender || 'Unknown sender'}
                    </p>
                  </div>
                  <div className="text-right flex-shrink-0">
                    <p className="text-xs text-surface-500">
                      {new Date(record.analyzed_at).toLocaleDateString()}
                    </p>
                    <p className="text-xs text-surface-600">
                      {new Date(record.analyzed_at).toLocaleTimeString()}
                    </p>
                  </div>
                </div>

                {selectedId === record.id && detail && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    className="mt-4 pt-4 border-t border-surface-700/30"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <div className="space-y-3">
                      <div>
                        <span className="text-xs text-surface-500 font-semibold uppercase">Reasons</span>
                        <ul className="mt-1.5 space-y-1">
                          {detail.reasons?.map((r, i) => (
                            <li key={i} className="text-xs text-surface-300 flex items-start gap-2">
                              <span className="text-accent-400 mt-0.5">•</span>
                              {r}
                            </li>
                          ))}
                        </ul>
                      </div>
                      {detail.details?.rule_flags?.length > 0 && (
                        <div>
                          <span className="text-xs text-surface-500 font-semibold uppercase">
                            Rule Flags ({detail.details.rule_flags.length})
                          </span>
                          <div className="mt-1.5 flex flex-wrap gap-1.5">
                            {detail.details.rule_flags.slice(0, 5).map((f, i) => (
                              <span key={i} className="text-[10px] px-2 py-0.5 rounded bg-surface-800 text-surface-400 border border-surface-700/30">
                                {f.rule || f.description?.slice(0, 40)}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </motion.div>
                )}
              </button>
            </motion.div>
          ))}
        </div>
      )}
    </div>
  );
}
