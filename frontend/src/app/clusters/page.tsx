'use client';

import React, { useEffect, useState } from 'react';
import { ShieldAlert, AlertTriangle, Key, Copy, Check } from 'lucide-react';
import { api, Cluster } from '@/lib/api';

export default function ClustersPage() {
  const [clusters, setClusters] = useState<Cluster[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isError, setIsError] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const fetchClusters = async () => {
    try {
      setIsLoading(true);
      const data = await api.getClusters();
      setClusters(data);
      setIsError(false);
    } catch (err) {
      console.error(err);
      setIsError(true);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchClusters();
  }, []);

  const handleCopy = (hash: string, id: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const getSeverityBadge = (severity: Cluster['severity']) => {
    const sev = String(severity || 'MEDIUM').toUpperCase();
    switch (sev) {
      case 'CRITICAL':
        return (
          <span className="inline-flex items-center rounded border border-red-500/30 bg-red-950/20 px-2 py-0.5 text-xs font-bold text-red-400">
            CRITICAL
          </span>
        );
      case 'HIGH':
        return (
          <span className="inline-flex items-center rounded border border-orange-500/30 bg-orange-950/20 px-2 py-0.5 text-xs font-bold text-orange-400">
            HIGH
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="inline-flex items-center rounded border border-yellow-500/30 bg-yellow-950/20 px-2 py-0.5 text-xs font-bold text-yellow-400">
            MEDIUM
          </span>
        );
      case 'LOW':
      default:
        return (
          <span className="inline-flex items-center rounded border border-slate-500/30 bg-slate-950/20 px-2 py-0.5 text-xs font-bold text-slate-400">
            LOW
          </span>
        );
    }
  };

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-extrabold tracking-tight text-white">Cross-Repo Clusters</h1>
        <p className="text-slate-400 mt-1">Detect and manage secrets that have been reused across multiple monitored repositories.</p>
      </div>

      {/* Security Warning Banner */}
      <div className="flex items-start gap-3 rounded-xl border border-yellow-500/20 bg-yellow-950/10 p-4">
        <AlertTriangle className="h-5 w-5 text-yellow-500 shrink-0 mt-0.5" />
        <div>
          <h4 className="text-sm font-bold text-yellow-500">Credential Leak Alert</h4>
          <p className="text-sm text-yellow-500/90 mt-1">
            A cluster means the exact same secret key was found in multiple repositories. Rotate these keys immediately and avoid reuse across separate environments.
          </p>
        </div>
      </div>

      {isLoading ? (
        <div className="flex h-64 flex-col items-center justify-center gap-3">
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-slate-800 border-t-accent-blue" />
          <span className="text-sm font-medium text-slate-400">Loading clusters...</span>
        </div>
      ) : isError ? (
        <div className="rounded-xl border border-red-500/20 bg-red-950/10 p-6 text-center text-red-400">
          <p className="font-semibold">Failed to fetch clusters.</p>
          <button 
            onClick={fetchClusters}
            className="mt-3 inline-flex items-center gap-1 text-sm font-medium underline hover:text-red-300"
          >
            Retry request
          </button>
        </div>
      ) : clusters.length === 0 ? (
        <div className="rounded-2xl border border-dashed border-border-dark bg-panel/30 py-16 text-center">
          <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full bg-slate-900 border border-border-dark text-slate-400">
            <Key className="h-6 w-6" />
          </div>
          <h3 className="mt-4 text-lg font-bold text-white">No cross-repo clusters found</h3>
          <p className="mx-auto mt-2 max-w-sm text-sm text-slate-400">
            Cross-repo credential reuse is evaluated once 2 or more monitored repositories are successfully scanned and found to share identical secret values.
          </p>
        </div>
      ) : (
        <div className="overflow-hidden rounded-xl border border-border-dark bg-panel shadow-lg">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-border-dark bg-panel/50 text-xs font-semibold uppercase tracking-wider text-slate-400">
                <th className="py-4 px-6">Secret Type</th>
                <th className="py-4 px-6">Severity</th>
                <th className="py-4 px-6">Repos Affected</th>
                <th className="py-4 px-6">Secret Hash</th>
                <th className="py-4 px-6">First Detected</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-dark/60 text-sm text-slate-300">
              {clusters.map((cluster) => {
                const isCriticalOverlap = cluster.repo_count >= 3;
                return (
                  <tr 
                    key={cluster.id} 
                    className={`transition-colors hover:bg-slate-800/30 ${
                      isCriticalOverlap ? 'bg-red-950/15 text-red-100 hover:bg-red-950/25' : ''
                    }`}
                  >
                    <td className="py-4 px-6 font-semibold flex items-center gap-2">
                      <ShieldAlert className={`h-4 w-4 ${isCriticalOverlap ? 'text-red-400' : 'text-slate-400'}`} />
                      {cluster.secret_type}
                    </td>
                    <td className="py-4 px-6">{getSeverityBadge(cluster.severity)}</td>
                    <td className="py-4 px-6">
                      <span className={`font-mono text-sm font-bold ${
                        isCriticalOverlap ? 'text-red-400' : 'text-white'
                      }`}>
                        {cluster.repo_count} {cluster.repo_count === 1 ? 'repo' : 'repos'}
                      </span>
                    </td>
                    <td className="py-4 px-6">
                      <div className="flex items-center gap-2 font-mono text-xs">
                        <span className="text-slate-400 select-all shrink-0">
                          {cluster.secret_hash.substring(0, 16)}...
                        </span>
                        <button
                          onClick={() => handleCopy(cluster.secret_hash, cluster.id)}
                          className="text-slate-500 hover:text-white transition-colors"
                          title="Copy Full Hash"
                        >
                          {copiedId === cluster.id ? (
                            <Check className="h-3.5 w-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="h-3.5 w-3.5" />
                          )}
                        </button>
                      </div>
                    </td>
                    <td className="py-4 px-6 text-slate-400 text-xs">
                      {new Date(cluster.created_at).toLocaleDateString(undefined, {
                        year: 'numeric',
                        month: 'short',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
