const IST = "Asia/Kolkata";

export function formatDateTime(value?: string | null) {
  if (!value) return "-";
  const d = new Date(value);
  return d.toLocaleString("en-IN", { timeZone: IST, day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", hour12: false });
}

export function formatTime(value?: string | null) {
  if (!value) return "-";
  return new Date(value).toLocaleTimeString("en-IN", { timeZone: IST, hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
}

export function timeAgo(value?: string | null) {
  if (!value) return "-";
  const seconds = Math.round((Date.now() - new Date(value).getTime()) / 1000);
  if (seconds < 45) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

export function formatDuration(ms?: number | null) {
  if (ms === null || ms === undefined) return "-";
  if (ms < 1000) return `${ms} ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${Math.round(s % 60)}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

export function formatSeconds(seconds?: number | null) {
  return seconds === null || seconds === undefined ? "-" : formatDuration(seconds * 1000);
}

export function formatNumber(n?: number | null) {
  return n === null || n === undefined ? "-" : n.toLocaleString("en-IN");
}

export function initials(name: string) {
  return name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((p) => p[0]!.toUpperCase())
    .join("");
}

export function displayName(u?: { first_name?: string; last_name?: string; username: string } | null) {
  if (!u) return "";
  return [u.first_name, u.last_name].filter(Boolean).join(" ") || u.username;
}
