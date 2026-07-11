'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Shield, Activity, RefreshCw } from 'lucide-react';
import { api } from '@/lib/api';

export default function Navbar() {
  const pathname = usePathname();
  const [apiStatus, setApiStatus] = useState<'checking' | 'connected' | 'disconnected'>('checking');
  const [isRefreshing, setIsRefreshing] = useState(false);

  const checkHealth = async () => {
    setIsRefreshing(true);
    try {
      const res = await api.getHealth();
      if (res.status === 'ok') {
        setApiStatus('connected');
      } else {
        setApiStatus('disconnected');
      }
    } catch (err) {
      setApiStatus('disconnected');
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    checkHealth();
    // Poll health check every 15 seconds
    const interval = setInterval(checkHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  const navItems = [
    { name: 'Repositories', path: '/' },
    { name: 'Cross-Repo Clusters', path: '/clusters' },
    { name: 'Report Verifier', path: '/verify' },
  ];

  return (
    <header className="sticky top-0 z-50 w-full border-b border-border-dark bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        
        {/* Logo */}
        <Link href="/" className="flex items-center gap-2 font-sans font-bold text-xl tracking-tight text-white hover:opacity-90">
          <Shield className="h-6 w-6 text-accent-blue fill-accent-blue/10" />
          <span>Dark<span className="text-accent-blue">Shield</span></span>
          <span className="ml-1 rounded border border-accent-blue/20 bg-accent-blue/10 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider text-accent-blue">
            SecOps
          </span>
        </Link>

        {/* Navigation */}
        <nav className="hidden md:flex items-center gap-6">
          {navItems.map((item) => {
            const isActive = pathname === item.path || (item.path !== '/' && pathname.startsWith(item.path));
            return (
              <Link
                key={item.path}
                href={item.path}
                className={`text-sm font-medium transition-colors hover:text-white ${
                  isActive ? 'text-white border-b-2 border-accent-blue py-1' : 'text-slate-400'
                }`}
              >
                {item.name}
              </Link>
            );
          })}
        </nav>

        {/* API Health Status */}
        <div className="flex items-center gap-3">
          <button 
            onClick={checkHealth}
            disabled={isRefreshing}
            className="rounded-full p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white transition-colors disabled:opacity-50"
            title="Refresh connection status"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
          </button>
          <div className="flex items-center gap-2 rounded-full border border-border-dark bg-panel px-3 py-1.5 text-xs font-medium">
            {apiStatus === 'checking' && (
              <>
                <span className="h-2 w-2 rounded-full bg-yellow-500 animate-pulse" />
                <span className="text-slate-400">API: Connecting</span>
              </>
            )}
            {apiStatus === 'connected' && (
              <>
                <span className="h-2 w-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)] animate-pulse" />
                <span className="text-emerald-400">API: Connected</span>
              </>
            )}
            {apiStatus === 'disconnected' && (
              <>
                <span className="h-2 w-2 rounded-full bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]" />
                <span className="text-red-400">API: Offline</span>
              </>
            )}
          </div>
        </div>
      </div>
    </header>
  );
}
