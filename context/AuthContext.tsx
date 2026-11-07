import React, { createContext, useContext, useEffect, useState } from 'react';
import type { AuditorRole, AuthContextType, UserProfile } from '../types/auth';

const AuthContext = createContext<AuthContextType | undefined>(undefined);
const STORAGE_KEY = 'sentinel_auth_user';

function readStoredUser(): UserProfile | null {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const value = JSON.parse(raw) as Partial<UserProfile>;
    if (typeof value.id !== 'string' || typeof value.name !== 'string' || typeof value.email !== 'string' || typeof value.role !== 'string') return null;
    return {
      id: value.id,
      name: value.name,
      email: value.email,
      role: value.role as AuditorRole,
      avatarUrl: typeof value.avatarUrl === 'string' ? value.avatarUrl : '',
      joinedAt: typeof value.joinedAt === 'string' ? value.joinedAt : new Date().toLocaleDateString(),
      totalAuditsRun: Number.isFinite(value.totalAuditsRun) ? Number(value.totalAuditsRun) : 0,
    };
  } catch {
    return null;
  }
}

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserProfile | null>(readStoredUser);

  useEffect(() => {
    try {
      if (user) window.localStorage.setItem(STORAGE_KEY, JSON.stringify(user));
      else window.localStorage.removeItem(STORAGE_KEY);
    } catch {
      // The demo remains usable when browser storage is disabled or full.
    }
  }, [user]);

  const login = (email: string, name?: string, role?: AuditorRole) => {
    const normalizedEmail = email.trim().toLowerCase();
    const normalizedName = name?.trim() || normalizedEmail.split('@')[0] || 'Demo Auditor';
    setUser({
      id: `demo-${Date.now()}`,
      name: normalizedName,
      email: normalizedEmail,
      role: role || 'Application Security Auditor',
      avatarUrl: '',
      joinedAt: new Date().toLocaleDateString('en-IN', { month: 'short', year: 'numeric' }),
      totalAuditsRun: 0,
    });
  };

  const logout = () => setUser(null);
  const incrementAuditCount = () => setUser((current) => current ? { ...current, totalAuditsRun: current.totalAuditsRun + 1 } : null);

  return (
    <AuthContext.Provider value={{ user, isAuthenticated: user !== null, login, logout, incrementAuditCount }}>
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within AuthProvider.');
  return context;
}
