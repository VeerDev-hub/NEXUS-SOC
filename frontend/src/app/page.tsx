"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";
import { ROLE_HOME, useAuth } from "@/lib/auth";
import { Spinner } from "@/components/ui";

export default function Home() {
  const router = useRouter();
  const { user, hydrated } = useAuth();
  useEffect(() => {
    if (!hydrated) return;
    router.replace(user ? ROLE_HOME[user.role] : "/login");
  }, [hydrated, user, router]);
  return <Spinner />;
}
