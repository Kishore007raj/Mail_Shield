import React from 'react';
import { Link, useLocation } from 'react-router-dom';

const ShieldIcon = () => (
  <svg className="w-8 h-8" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path
      d="M12 2L3 7V12C3 17.55 6.84 22.74 12 24C17.16 22.74 21 17.55 21 12V7L12 2Z"
      className="fill-accent-500/20 stroke-accent-400"
      strokeWidth="1.5"
    />
    <path
      d="M9 12L11 14L15 10"
      className="stroke-accent-400"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export default function Header() {
  const location = useLocation();

  const navLinks = [
    { path: '/', label: 'Analyze' },
    { path: '/history', label: 'History' },
  ];

  return (
    <header className="sticky top-0 z-50 backdrop-blur-xl bg-surface-950/80 border-b border-surface-800/50">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <Link to="/" className="flex items-center gap-3 group">
            <div className="relative">
              <div className="absolute inset-0 bg-accent-500/20 rounded-lg blur-md group-hover:bg-accent-500/30 transition-colors" />
              <div className="relative">
                <ShieldIcon />
              </div>
            </div>
            <div>
              <h1 className="text-xl font-bold text-gradient leading-tight">PhishAegis</h1>
              <p className="text-[10px] font-medium text-surface-500 tracking-widest uppercase">DFIR • Threat Detection</p>
            </div>
          </Link>

          <nav className="flex items-center gap-1">
            {navLinks.map(({ path, label }) => (
              <Link
                key={path}
                to={path}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
                  location.pathname === path
                    ? 'bg-accent-500/10 text-accent-400 border border-accent-500/20'
                    : 'text-surface-400 hover:text-surface-200 hover:bg-surface-800/50'
                }`}
              >
                {label}
              </Link>
            ))}
            <div className="ml-3 h-6 w-px bg-surface-700/50" />
            <div className="ml-3 flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-safe-500 animate-pulse" />
              <span className="text-xs text-surface-500">System Online</span>
            </div>
          </nav>
        </div>
      </div>
    </header>
  );
}
