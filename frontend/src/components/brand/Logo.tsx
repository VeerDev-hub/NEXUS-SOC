export default function Logo({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" aria-hidden>
      <path d="M16 2 4 7v8c0 7.2 5.1 13.4 12 15 6.9-1.6 12-7.8 12-15V7L16 2Z" fill="#14171c" stroke="#3987e5" strokeWidth="2" />
      <circle cx="16" cy="11" r="2.4" fill="#3987e5" />
      <circle cx="10.5" cy="19" r="2.4" fill="#199e70" />
      <circle cx="21.5" cy="19" r="2.4" fill="#d95926" />
      <path d="M16 13.4 11.6 17M16 13.4l4.4 3.6M12.9 19h6.2" stroke="#b4bac5" strokeWidth="1.2" />
    </svg>
  );
}
