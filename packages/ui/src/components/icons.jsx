/* Inline icons (lucide paths): packages/ui has no icon dependency and none is added for these few glyphs. */
function Icon({ className, children }) {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
    >
      {children}
    </svg>
  );
}

export const CheckIcon = ({ className }) => (
  <Icon className={className}>
    <path d="M20 6 9 17l-5-5" />
  </Icon>
);
export const AlertIcon = ({ className }) => (
  <Icon className={className}>
    <circle cx="12" cy="12" r="10" />
    <line x1="12" x2="12" y1="8" y2="12" />
    <line x1="12" x2="12.01" y1="16" y2="16" />
  </Icon>
);
export const ChevronIcon = ({ className }) => (
  <Icon className={className}>
    <path d="m6 9 6 6 6-6" />
  </Icon>
);
export const XIcon = ({ className }) => (
  <Icon className={className}>
    <path d="M18 6 6 18" />
    <path d="m6 6 12 12" />
  </Icon>
);
export const PlusIcon = ({ className }) => (
  <Icon className={className}>
    <path d="M5 12h14" />
    <path d="M12 5v14" />
  </Icon>
);
export const LoaderIcon = ({ className }) => (
  <Icon className={className}>
    <path d="M21 12a9 9 0 1 1-6.219-8.56" />
  </Icon>
);
export const ArrowUpIcon = ({ className }) => (
  <Icon className={className}>
    <path d="m5 12 7-7 7 7" />
    <path d="M12 19V5" />
  </Icon>
);
export const ArrowDownIcon = ({ className }) => (
  <Icon className={className}>
    <path d="M12 5v14" />
    <path d="m19 12-7 7-7-7" />
  </Icon>
);
export const LockIcon = ({ className }) => (
  <Icon className={className}>
    <rect width="18" height="11" x="3" y="11" rx="2" ry="2" />
    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
  </Icon>
);
