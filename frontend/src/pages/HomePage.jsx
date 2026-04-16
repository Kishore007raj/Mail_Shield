import React, { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useDropzone } from 'react-dropzone';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL || '';

const SAMPLE_PHISHING = `From: "PayPal Security" <security@paypa1-secure.tk>
To: victim@example.com
Reply-To: hacker@malicious-domain.xyz
Subject: URGENT: Your PayPal Account Has Been Compromised!
Date: Mon, 14 Apr 2025 10:30:00 +0000
X-Mailer: PHPMailer 6.0
X-Priority: 1
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail
Return-Path: <bounces@bulk-mailer.ga>
Received: from unknown (HELO bulk-mailer.ga) (192.168.1.100) by mx.example.com

Dear Valued Customer,

URGENT SECURITY ALERT!

We have detected unauthorized access to your PayPal account. Your account has been temporarily limited due to suspicious activity.

You MUST verify your identity within 24 hours or your account will be permanently suspended.

Click here to verify your account immediately:
http://192.168.1.1/paypal-verify/login.php

You will need to provide your email, password, and credit card information.

Failure to respond will result in permanent account termination.

Act now! Don't delay!

Sincerely,
PayPal Security Team`;

const SAMPLE_LEGIT = `From: "Alice Johnson" <alice.johnson@company.com>
To: bob.smith@company.com
Subject: Re: Q4 Project Timeline Update
Date: Mon, 14 Apr 2025 14:15:00 +0000
Authentication-Results: mx.company.com; spf=pass; dkim=pass; dmarc=pass
Return-Path: <alice.johnson@company.com>

Hi Bob,

Thanks for sending over the updated project timeline. I've reviewed the milestones and everything looks good for the Q4 deliverables.

The design review is scheduled for next Wednesday at 2:00 PM in Conference Room B.

Let me know if you need anything else before the stakeholder presentation on Friday.

Best regards,
Alice Johnson`;

export default function HomePage({ onResult }) {
  const [mode, setMode] = useState('text');
  const [rawEmail, setRawEmail] = useState('');
  const [file, setFile] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const onDrop = useCallback((acceptedFiles) => {
    if (acceptedFiles.length > 0) {
      const f = acceptedFiles[0];
      if (f.name.toLowerCase().endsWith('.eml')) {
        setFile(f);
        setError('');
      } else {
        setError('Only .eml files are supported');
      }
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: { 'message/rfc822': ['.eml'] },
    maxFiles: 1,
    multiple: false,
  });

  const handleAnalyze = async () => {
    setError('');
    setIsLoading(true);

    try {
      let response;

      if (mode === 'text') {
        if (!rawEmail.trim()) {
          setError('Please enter email content to analyze');
          setIsLoading(false);
          return;
        }
        response = await axios.post(`${API_BASE}/api/analyze`, {
          raw_email: rawEmail,
        });
      } else {
        if (!file) {
          setError('Please upload a .eml file');
          setIsLoading(false);
          return;
        }
        const formData = new FormData();
        formData.append('file', file);
        response = await axios.post(`${API_BASE}/api/analyze/upload`, formData, {
          headers: { 'Content-Type': 'multipart/form-data' },
        });
      }

      onResult(response.data);
      navigate('/result');
    } catch (err) {
      const message = err.response?.data?.detail || err.message || 'Analysis failed';
      setError(message);
    } finally {
      setIsLoading(false);
    }
  };

  const loadSample = (sample) => {
    setRawEmail(sample);
    setMode('text');
    setError('');
  };

  return (
    <div className="pt-8 sm:pt-12">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="text-center mb-10"
      >
        <h1 className="text-3xl sm:text-4xl font-bold mb-3">
          <span className="text-gradient">Email Threat Analysis</span>
        </h1>
        <p className="text-surface-400 text-sm sm:text-base max-w-2xl mx-auto">
          Submit an email for real-time phishing detection, forensic header analysis,
          URL threat scanning, and ML-powered classification.
        </p>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.1 }}
        className="glass-card p-6 sm:p-8 max-w-3xl mx-auto"
      >
        {/* Mode Tabs */}
        <div className="flex gap-1 p-1 bg-surface-800/60 rounded-xl mb-6 max-w-xs">
          <button
            onClick={() => { setMode('text'); setError(''); }}
            className={`flex-1 px-4 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 ${
              mode === 'text'
                ? 'bg-accent-500/15 text-accent-400 shadow-sm'
                : 'text-surface-400 hover:text-surface-200'
            }`}
          >
            📝 Raw Text
          </button>
          <button
            onClick={() => { setMode('upload'); setError(''); }}
            className={`flex-1 px-4 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 ${
              mode === 'upload'
                ? 'bg-accent-500/15 text-accent-400 shadow-sm'
                : 'text-surface-400 hover:text-surface-200'
            }`}
          >
            📎 Upload .eml
          </button>
        </div>

        <AnimatePresence mode="wait">
          {mode === 'text' ? (
            <motion.div
              key="text"
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              transition={{ duration: 0.2 }}
            >
              <div className="mb-4">
                <label className="block text-xs font-semibold text-surface-400 uppercase tracking-wider mb-2">
                  Paste Raw Email (with headers)
                </label>
                <textarea
                  id="email-input"
                  value={rawEmail}
                  onChange={(e) => setRawEmail(e.target.value)}
                  placeholder={"From: sender@example.com\nTo: recipient@example.com\nSubject: ...\n\nEmail body content..."}
                  rows={14}
                  className="input-field resize-y min-h-[200px]"
                />
              </div>
              <div className="flex flex-wrap gap-2 mb-4">
                <span className="text-xs text-surface-500 self-center mr-1">Load sample:</span>
                <button
                  onClick={() => loadSample(SAMPLE_PHISHING)}
                  className="px-3 py-1.5 text-xs font-medium rounded-lg bg-danger-500/10 text-danger-400 border border-danger-500/20 hover:bg-danger-500/20 transition-colors"
                >
                  ⚠ Phishing Email
                </button>
                <button
                  onClick={() => loadSample(SAMPLE_LEGIT)}
                  className="px-3 py-1.5 text-xs font-medium rounded-lg bg-safe-500/10 text-safe-400 border border-safe-500/20 hover:bg-safe-500/20 transition-colors"
                >
                  ✓ Legitimate Email
                </button>
              </div>
            </motion.div>
          ) : (
            <motion.div
              key="upload"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              transition={{ duration: 0.2 }}
            >
              <div
                {...getRootProps()}
                className={`border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition-all duration-300 mb-4 ${
                  isDragActive
                    ? 'border-accent-400 bg-accent-500/5'
                    : file
                    ? 'border-safe-500/40 bg-safe-500/5'
                    : 'border-surface-600/40 hover:border-surface-500/50 hover:bg-surface-800/30'
                }`}
              >
                <input {...getInputProps()} />
                {file ? (
                  <div>
                    <div className="text-3xl mb-3">📧</div>
                    <p className="text-safe-400 font-medium">{file.name}</p>
                    <p className="text-xs text-surface-500 mt-1">
                      {(file.size / 1024).toFixed(1)} KB — Click or drop to replace
                    </p>
                  </div>
                ) : (
                  <div>
                    <div className="text-3xl mb-3">📂</div>
                    <p className="text-surface-300 font-medium">
                      {isDragActive ? 'Drop .eml file here' : 'Drag & drop .eml file here'}
                    </p>
                    <p className="text-xs text-surface-500 mt-2">
                      or click to browse — Only .eml files accepted
                    </p>
                  </div>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Error Display */}
        <AnimatePresence>
          {error && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="mb-4 px-4 py-3 rounded-xl bg-danger-500/10 border border-danger-500/20 text-danger-400 text-sm"
            >
              {error}
            </motion.div>
          )}
        </AnimatePresence>

        {/* Analyze Button */}
        <button
          id="analyze-button"
          onClick={handleAnalyze}
          disabled={isLoading}
          className="btn-primary w-full flex items-center justify-center gap-2 text-base"
        >
          {isLoading ? (
            <>
              <svg className="animate-spin w-5 h-5" viewBox="0 0 24 24" fill="none">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path
                  className="opacity-75"
                  fill="currentColor"
                  d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
                />
              </svg>
              Analyzing...
            </>
          ) : (
            <>
              🔍 Analyze Email
            </>
          )}
        </button>

        {/* Feature Tags */}
        <div className="flex flex-wrap justify-center gap-2 mt-6 pt-5 border-t border-surface-800/50">
          {['Rule Engine', 'ML Detection', 'URL Analysis', 'Header Forensics', 'SPF/DKIM Check'].map((tag) => (
            <span
              key={tag}
              className="px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider rounded-md bg-surface-800/60 text-surface-500 border border-surface-700/30"
            >
              {tag}
            </span>
          ))}
        </div>
      </motion.div>
    </div>
  );
}
