"use client";

import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { Permission, Role, User } from "./types";

interface AuthState {
  access: string | null;
  refresh: string | null;
  user: User | null;
  hydrated: boolean;
  setSession: (access: string, refresh: string, user: User) => void;
  setAccess: (access: string) => void;
  setHydrated: (hydrated: boolean) => void;
  setUser: (user: User) => void;
  logout: () => void;
}

export const useAuth = create<AuthState>()(
  persist(
    (set) => ({
      access: null,
      refresh: null,
      user: null,
      hydrated: false,
      setSession: (access, refresh, user) => set({ access, refresh, user }),
      setAccess: (access) => set({ access }),
      setHydrated: (hydrated) => set({ hydrated }),
      setUser: (user) => set({ user }),
      logout: () => set({ access: null, refresh: null, user: null }),
    }),
    {
      name: "soc-auth",
      partialize: (s) => ({ access: s.access, refresh: s.refresh, user: s.user }),
      // localStorage rehydrates synchronously inside create(); use the state handle, not useAuth.
      onRehydrateStorage: () => (state) => state?.setHydrated(true),
    },
  ),
);

export function can(user: User | null | undefined, permission: Permission) {
  return !!user && user.permissions.includes(permission);
}

export const ROLE_HOME: Record<Role, string> = {
  admin: "/admin",
  soc_manager: "/manager",
  tier1_analyst: "/queue",
  tier2_responder: "/responder",
  auditor: "/audit",
};

export const ROLE_LABEL: Record<Role, string> = {
  admin: "SOC Admin",
  soc_manager: "SOC Manager",
  tier1_analyst: "Tier-1 Analyst",
  tier2_responder: "Tier-2 Responder",
  auditor: "Auditor",
};
