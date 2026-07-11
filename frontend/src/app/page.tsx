'use client';

import React, { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { 
  Plus, 
  GitFork, 
  ExternalLink, 
  AlertTriangle, 
  Trash2, 
  ShieldAlert, 
  Search,
  CheckCircle2,
  Clock,
  AlertCircle
} from 'lucide-react';
import { api, Repo } from '@/lib/api';

export default function Dashboard() {
  const router = useRouter();
  const [repos, setRepos] = useState<Repo[]>([]);
  const [scores, setScores] = useState<Record<string, number>>({});
  const [searchQuery, setSearchQuery] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [isError, setIsError] = useState(false);
  
  // Modal state
  const [isOpen, setIsOpen] = useState(false);
  const [githubUrl, setGithubUrl] = useState('');
  const [validationError, setValidationError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const fetchRepos = async () => {
    try {
      setIsLoading(true);
      const data = await api.listRepos();
      setRepos(data);
      setIsError(false);
      
      // Fetch scores in parallel for completed repos
      const doneRepos = data.filter(r => r.status === 'done');
      doneRepos.forEach(async (repo) => {
        try {
          const scoreData = await api.getScore(repo.id);
          setScores(prev => ({
            ...prev,
            [repo.id]: scoreData.security_score
          }));
        } catch (err) {
          console.error(`Failed to fetch score for repo ${repo.id}`, err);
        }
      });
    } catch (err) {
      setIsError(true);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchRepos();
  }, []);

  const handleAddRepo = async (e: React.FormEvent) => {
    e.preventDefault();
    setValidationError('');
    
    // Quick validation
    const urlPattern = /^https:\/\/github\.com\/([^/]+)\/([^/]+)/;
    if (!githubUrl.trim()) {
      setValidationError('GitHub URL is required');
      return;
    }
    if (!urlPattern.test(githubUrl.trim())) {
      setValidationError('Must be a valid GitHub URL, e.g. https://github.com/owner/repo');
      return;
    }

    setIsSubmitting(true);
    try {
      const res = await api.createRepo(githubUrl.trim());
      setIsOpen(false);
      setGithubUrl('');
      // Navigate directly to the repo details page
      router.push(`/repos/${res.id}`);
    } catch (err: any) {
      setValidationError(err.message || 'Failed to register repository');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDeleteRepo = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation(); // Avoid navigating to repo detail
    if (!confirm('Are you sure you want to delete this repository? All findings and reports will be deleted.')) {
      return;
    }

    try {
      await api.deleteRepo(id);
      setRepos(prev => prev.filter(r => r.id !== id));
    } catch (err) {
      alert('Failed to delete repository');
    }
  };

  const filteredRepos = repos.filter(repo => {
    const fullName = `${repo.owner}/${repo.name}`.toLowerCase();
    return fullName.includes(searchQuery.toLowerCase()) || repo.github_url.toLowerCase().includes(searchQuery.toLowerCase());
  });

  const getScoreColor = (score: number) => {
    if (score >= 75) return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20';
    if (score >= 40) return 'text-amber-400 bg-amber-500/10 border-amber-500/20';
    return 'text-red-400 bg-red-500/10 border-red-500/20';
  };

  const getStatusBadge = (status: Repo['status']) => {
    switch (status) {
      case 'pending':
        return (
          <span className="inline-flex items-center gap-1 rounded bg-slate-800 px-2 py-0.5 text-xs font-semibold text-slate-300 border border-slate-700">
            <Clock className="h-3 w-3" /> Pending
          </span>
        );
      case 'scanning':
        return (
          <span className="inline-flex items-center gap-1 rounded bg-blue-900/40 px-2 py-0.5 text-xs font-semibold text-blue-400 border border-blue-800/40 animate-pulse">
            <span className="h-1.5 w-1.5 rounded-full bg-blue-400 animate-ping" /> Scanning
          </span>
        );
      case 'done':
        return (
          <span className="inline-flex items-center gap-1 rounded bg-emerald-950/40 px-2 py-0.5 text-xs font-semibold text-emerald-400 border border-emerald-800/40">
            <CheckCircle2 className="h-3 w-3" /> Complete
          </span>
        );
      case 'error':
        return (
          <span className="inline-flex items-center gap-1 rounded bg-red-950/40 px-2 py-0.5 text-xs font-semibold text-red-400 border border-red-800/40">
            <AlertCircle className="h-3 w-3" /> Error
          </span>
        );
    }
  };

  const getFindingsColor = (count: number) => {
    if (count === 0) return 'text-emerald-400 bg-emerald-500/10 border border-emerald-500/20';
    if (count <= 5) return 'text-amber-400 bg-amber-500/10 border border-amber-500/20';
    return 'text-red-400 bg-red-500/10 border border-red-500/20';
  };

  return (
    <div className="space-y-8">
      {/* Top Banner / Actions */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-3xl font-extrabold tracking-tight text-white">Security Command</h1>
          <p className="text-slate-400 mt-1">Monitor and verify vulnerabilities, secrets, and supply chain exposure across repositories.</p>
        </div>
        <button
          onClick={() => setIsOpen(true)}
          className="inline-flex items-center gap-2 rounded-lg bg-accent-blue px-4 py-2.5 text-sm font-semibold text-white shadow-lg hover:bg-accent-blue-hover hover:shadow-accent-blue/20 transition-all cursor-pointer"
        >
          <Plus className="h-4.5 w-4.5" />
          <span>Add Repository</span>
        </button>
      </div>

      {/* Stats Counter Overview */}
      {repos.length > 0 && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <div className="rounded-xl border border-border-dark bg-panel p-5">
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Monitored Repositories</p>
            <p className="mt-2 text-3xl font-bold text-white">{repos.length}</p>
          </div>
          <div className="rounded-xl border border-border-dark bg-panel p-5">
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Scanning in Progress</p>
            <p className="mt-2 text-3xl font-bold text-blue-400">
              {repos.filter(r => r.status === 'scanning').length}
            </p>
          </div>
          <div className="rounded-xl border border-border-dark bg-panel p-5">
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Failed / Errors</p>
            <p className="mt-2 text-3xl font-bold text-red-400">
              {repos.filter(r => r.status === 'error').length}
            </p>
          </div>
        </div>
      )}

      {/* Main Content Area */}
      {isLoading ? (
        <div className="flex h-64 flex-col items-center justify-center gap-3">
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-slate-800 border-t-accent-blue" />
          <span className="text-sm font-medium text-slate-400">Loading repositories...</span>
        </div>
      ) : isError ? (
        <div className="rounded-xl border border-red-500/20 bg-red-950/10 p-6 text-center text-red-400">
          <p className="font-semibold">Failed to load monitored repositories.</p>
          <button 
            onClick={fetchRepos}
            className="mt-3 inline-flex items-center gap-1 text-sm font-medium underline hover:text-red-300"
          >
            Retry request
          </button>
        </div>
      ) : filteredRepos.length === 0 ? (
        <div className="rounded-2xl border border-dashed border-border-dark bg-panel/30 py-16 text-center">
          <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full bg-slate-900 border border-border-dark text-slate-400">
            <GitFork className="h-6 w-6" />
          </div>
          <h3 className="mt-4 text-lg font-bold text-white">No repositories monitored</h3>
          <p className="mx-auto mt-2 max-w-sm text-sm text-slate-400">
            {searchQuery ? "No repositories match your search query." : "Register your first GitHub repository to start scanning for secrets, dependency vulnerabilities, and insecure code configurations."}
          </p>
          {!searchQuery && (
            <button
              onClick={() => setIsOpen(true)}
              className="mt-5 inline-flex items-center gap-2 rounded-lg bg-accent-blue/15 border border-accent-blue/30 px-4 py-2 text-sm font-semibold text-accent-blue hover:bg-accent-blue/20 transition-all cursor-pointer"
            >
              <Plus className="h-4 w-4" />
              <span>Register Repository</span>
            </button>
          )}
        </div>
      ) : (
        <div className="space-y-4">
          {/* Search bar */}
          <div className="relative max-w-md">
            <Search className="absolute top-3 left-3 h-4 w-4 text-slate-500" />
            <input
              type="text"
              placeholder="Filter repositories..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full rounded-lg border border-border-dark bg-panel py-2 pr-4 pl-10 text-sm text-white placeholder-slate-500 focus:border-accent-blue focus:outline-none focus:ring-1 focus:ring-accent-blue"
            />
          </div>

          {/* Grid of cards */}
          <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3">
            {filteredRepos.map((repo) => {
              const score = scores[repo.id];
              return (
                <div
                  key={repo.id}
                  onClick={() => router.push(`/repos/${repo.id}`)}
                  className="group relative flex flex-col justify-between rounded-xl border border-border-dark bg-panel hover:border-slate-700 hover:bg-panel-light p-6 transition-all duration-200 cursor-pointer shadow-lg hover:shadow-black/40"
                >
                  <div className="space-y-4">
                    {/* Card Header */}
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-2 max-w-[80%]">
                        <GitFork className="h-4 w-4 text-slate-500 shrink-0" />
                        <span className="font-mono text-sm font-bold text-white truncate" title={`${repo.owner}/${repo.name}`}>
                          {repo.owner}/{repo.name}
                        </span>
                      </div>
                      <a
                        href={repo.github_url}
                        target="_blank"
                        rel="noreferrer"
                        onClick={(e) => e.stopPropagation()} // Stop navigation
                        className="text-slate-500 hover:text-white transition-colors"
                        title="Open on GitHub"
                      >
                        <ExternalLink className="h-3.5 w-3.5" />
                      </a>
                    </div>

                    {/* Status badges row */}
                    <div className="flex flex-wrap items-center gap-2">
                      {getStatusBadge(repo.status)}
                      
                      {repo.status === 'done' && (
                        <span className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 text-xs font-semibold ${getFindingsColor(repo.finding_count)}`}>
                          <ShieldAlert className="h-3 w-3" /> {repo.finding_count} {repo.finding_count === 1 ? 'finding' : 'findings'}
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Card Footer / Scores */}
                  <div className="mt-6 flex items-center justify-between border-t border-border-dark/60 pt-4">
                    <div className="flex flex-col">
                      <span className="text-[10px] uppercase tracking-wider text-slate-500">Security Rating</span>
                      {repo.status === 'done' ? (
                        score !== undefined ? (
                          <span className={`text-lg font-extrabold ${getScoreColor(score)} mt-0.5`}>
                            {score} / 100
                          </span>
                        ) : (
                          <span className="text-slate-400 text-sm font-semibold mt-1">Fetching...</span>
                        )
                      ) : (
                        <span className="text-slate-500 text-xs font-semibold mt-1">—</span>
                      )}
                    </div>

                    <button
                      onClick={(e) => handleDeleteRepo(repo.id, e)}
                      className="rounded p-1.5 text-slate-500 hover:bg-red-950/20 hover:text-red-400 transition-colors"
                      title="Remove Repository"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Modal Dialog */}
      {isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm">
          <div 
            className="w-full max-w-lg rounded-xl border border-border-dark bg-panel p-6 shadow-2xl animate-in fade-in zoom-in duration-200"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-start justify-between">
              <h2 className="text-xl font-bold text-white">Monitor New Repository</h2>
              <button
                onClick={() => {
                  setIsOpen(false);
                  setValidationError('');
                  setGithubUrl('');
                }}
                className="text-slate-400 hover:text-white text-lg font-semibold cursor-pointer"
              >
                &times;
              </button>
            </div>
            
            <form onSubmit={handleAddRepo} className="mt-4 space-y-4">
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400">
                  GitHub Repository URL
                </label>
                <input
                  type="text"
                  placeholder="e.g. https://github.com/octocat/Hello-World"
                  value={githubUrl}
                  onChange={(e) => setGithubUrl(e.target.value)}
                  disabled={isSubmitting}
                  className="mt-2 w-full rounded-lg border border-border-dark bg-background py-2.5 px-3.5 text-sm text-white placeholder-slate-500 focus:border-accent-blue focus:outline-none focus:ring-1 focus:ring-accent-blue disabled:opacity-50"
                  autoFocus
                />
                <p className="mt-1.5 text-xs text-slate-500">
                  Only public repositories are currently supported. The scanner will fetch repository commits, dependencies, and code configuration.
                </p>
              </div>

              {validationError && (
                <div className="flex items-start gap-2 rounded-lg bg-red-950/20 border border-red-500/20 p-3 text-xs text-red-400">
                  <AlertTriangle className="h-4 w-4 shrink-0" />
                  <span>{validationError}</span>
                </div>
              )}

              <div className="flex justify-end gap-3 mt-6">
                <button
                  type="button"
                  onClick={() => {
                    setIsOpen(false);
                    setValidationError('');
                    setGithubUrl('');
                  }}
                  disabled={isSubmitting}
                  className="rounded-lg border border-border-dark bg-transparent px-4 py-2 text-sm font-semibold text-slate-400 hover:bg-slate-800 hover:text-white transition-colors cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="rounded-lg bg-accent-blue px-4 py-2 text-sm font-semibold text-white hover:bg-accent-blue-hover transition-colors disabled:opacity-50 flex items-center gap-2 cursor-pointer"
                >
                  {isSubmitting ? (
                    <>
                      <span className="h-4 w-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                      <span>Registering...</span>
                    </>
                  ) : (
                    <span>Register Repository</span>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
