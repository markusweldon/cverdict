/** Hand-drawn 16px stroke icons. Decorative: always paired with visible or screen-reader text. */
import type { ComponentChildren } from 'preact';

interface IconProps {
  size?: number;
  class?: string;
}

function Svg({ size = 16, class: cls, children, fill }: IconProps & { children: ComponentChildren; fill?: boolean }) {
  return (
    <svg
      class={`icon${cls ? ` ${cls}` : ''}`}
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill={fill ? 'currentColor' : 'none'}
      stroke={fill ? 'none' : 'currentColor'}
      stroke-width="1.5"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {children}
    </svg>
  );
}

export const IconFlame = (p: IconProps) => (
  <Svg {...p}>
    <path d="M8 1.75c.35 2.3 3.85 3.6 3.85 7.35A3.85 3.85 0 0 1 8 12.95 3.85 3.85 0 0 1 4.15 9.1c0-1.6.75-2.65 1.6-3.35.2 1.3.85 2.05 1.65 2.35C7.15 6.35 7.25 3.7 8 1.75Z" />
    <path d="M6.6 14.25h2.8" />
  </Svg>
);
export const IconCrosshair = (p: IconProps) => (
  <Svg {...p}>
    <circle cx="8" cy="8" r="5.25" />
    <path d="M8 1.25v3M8 11.75v3M1.25 8h3M11.75 8h3" />
  </Svg>
);
export const IconEye = (p: IconProps) => (
  <Svg {...p}>
    <path d="M1.5 8S3.9 3.5 8 3.5 14.5 8 14.5 8 12.1 12.5 8 12.5 1.5 8 1.5 8Z" />
    <circle cx="8" cy="8" r="1.9" />
  </Svg>
);
export const IconEyeOff = (p: IconProps) => (
  <Svg {...p}>
    <path d="M6.3 3.7A6.9 6.9 0 0 1 8 3.5C12.1 3.5 14.5 8 14.5 8a11 11 0 0 1-1.6 2.2M10.3 11.9A6.3 6.3 0 0 1 8 12.5C3.9 12.5 1.5 8 1.5 8a11.5 11.5 0 0 1 2.4-3" />
    <path d="M2 2l12 12" />
  </Svg>
);
export const IconQuiet = (p: IconProps) => (
  <Svg {...p}>
    <circle cx="8" cy="8" r="5.25" stroke-dasharray="2.2 2.4" />
  </Svg>
);
export const IconUp = (p: IconProps) => (
  <Svg {...p}>
    <path d="M8 12.5v-9M4.25 7.25 8 3.5l3.75 3.75" />
  </Svg>
);
export const IconDown = (p: IconProps) => (
  <Svg {...p}>
    <path d="M8 3.5v9M4.25 8.75 8 12.5l3.75-3.75" />
  </Svg>
);
export const IconInfo = (p: IconProps) => (
  <Svg {...p}>
    <circle cx="8" cy="8" r="6" />
    <path d="M8 7.3v3.7" />
    <circle cx="8" cy="5" r=".4" fill="currentColor" />
  </Svg>
);
export const IconUnknown = (p: IconProps) => (
  <Svg {...p}>
    <circle cx="8" cy="8" r="6" stroke-dasharray="2.4 1.8" />
    <path d="M6.3 6.4a1.8 1.8 0 1 1 2.5 1.65c-.5.2-.8.6-.8 1.1v.3" />
    <circle cx="8" cy="11.3" r=".4" fill="currentColor" />
  </Svg>
);
export const IconSearch = (p: IconProps) => (
  <Svg {...p}>
    <circle cx="7" cy="7" r="4.5" />
    <path d="m10.4 10.4 3.6 3.6" />
  </Svg>
);
export const IconSun = (p: IconProps) => (
  <Svg {...p}>
    <circle cx="8" cy="8" r="2.9" />
    <path d="M8 1.5v1.3M8 13.2v1.3M1.5 8h1.3M13.2 8h1.3M3.4 3.4l.9.9M11.7 11.7l.9.9M3.4 12.6l.9-.9M11.7 4.3l.9-.9" />
  </Svg>
);
export const IconMoon = (p: IconProps) => (
  <Svg {...p}>
    <path d="M13.3 9.6A5.6 5.6 0 1 1 6.4 2.7a4.6 4.6 0 0 0 6.9 6.9Z" />
  </Svg>
);
export const IconSource = (p: IconProps) => (
  <Svg {...p}>
    <circle cx="4.5" cy="3.75" r="1.5" />
    <circle cx="4.5" cy="12.25" r="1.5" />
    <circle cx="11.5" cy="5.5" r="1.5" />
    <path d="M4.5 5.25v5.5M11.5 7c0 2.6-2.2 3.2-5.4 4" />
  </Svg>
);
export const IconCopy = (p: IconProps) => (
  <Svg {...p}>
    <rect x="5.25" y="5.25" width="8.5" height="8.5" rx="1.75" />
    <path d="M10.75 5.25V3.75a1.5 1.5 0 0 0-1.5-1.5h-5.5a1.5 1.5 0 0 0-1.5 1.5v5.5a1.5 1.5 0 0 0 1.5 1.5h1.5" />
  </Svg>
);
export const IconCheck = (p: IconProps) => (
  <Svg {...p}>
    <path d="m3.25 8.5 3.1 3.1 6.4-7.2" />
  </Svg>
);
export const IconLink = (p: IconProps) => (
  <Svg {...p}>
    <path d="M6.75 9.25 9.25 6.75M7.25 4.5l.9-.9a2.75 2.75 0 0 1 3.9 3.9l-.9.9M8.75 11.5l-.9.9a2.75 2.75 0 0 1-3.9-3.9l.9-.9" />
  </Svg>
);
export const IconExternal = (p: IconProps) => (
  <Svg {...p}>
    <path d="M9.25 2.75h4v4M13.25 2.75 7.5 8.5M11.75 9.75v2.5a1 1 0 0 1-1 1h-7a1 1 0 0 1-1-1v-7a1 1 0 0 1 1-1h2.5" />
  </Svg>
);
export const IconChevronRight = (p: IconProps) => (
  <Svg {...p}>
    <path d="M6 3.5 10.5 8 6 12.5" />
  </Svg>
);
export const IconChevronDown = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3.5 6 8 10.5 12.5 6" />
  </Svg>
);
export const IconArrowRight = (p: IconProps) => (
  <Svg {...p}>
    <path d="M2.75 8h10.5M9 3.75 13.25 8 9 12.25" />
  </Svg>
);
export const IconArrowLeft = (p: IconProps) => (
  <Svg {...p}>
    <path d="M13.25 8H2.75M7 3.75 2.75 8 7 12.25" />
  </Svg>
);
export const IconX = (p: IconProps) => (
  <Svg {...p}>
    <path d="m4 4 8 8M12 4l-8 8" />
  </Svg>
);
export const IconKeyboard = (p: IconProps) => (
  <Svg {...p}>
    <rect x="1.5" y="3.75" width="13" height="8.5" rx="1.75" />
    <path d="M4.25 6.5h.01M6.75 6.5h.01M9.25 6.5h.01M11.75 6.5h.01M4.75 9.5h6.5" />
  </Svg>
);
export const IconClock = (p: IconProps) => (
  <Svg {...p}>
    <circle cx="8" cy="8" r="6" />
    <path d="M8 4.75V8l2.25 1.5" />
  </Svg>
);
export const IconCalendar = (p: IconProps) => (
  <Svg {...p}>
    <rect x="2" y="3" width="12" height="11" rx="1.75" />
    <path d="M2 6.5h12M5.25 1.75v2.5M10.75 1.75v2.5" />
  </Svg>
);
export const IconRss = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3 2.75A10.25 10.25 0 0 1 13.25 13M3 6.75A6.25 6.25 0 0 1 9.25 13" />
    <circle cx="3.75" cy="12.25" r="1" fill="currentColor" />
  </Svg>
);
export const IconDownload = (p: IconProps) => (
  <Svg {...p}>
    <path d="M8 2.25v8M4.5 7 8 10.5 11.5 7M2.75 13.25h10.5" />
  </Svg>
);
export const IconLock = (p: IconProps) => (
  <Svg {...p}>
    <rect x="3" y="7" width="10" height="7" rx="1.75" />
    <path d="M5.25 7V5a2.75 2.75 0 0 1 5.5 0v2" />
  </Svg>
);
export const IconScan = (p: IconProps) => (
  <Svg {...p}>
    <path d="M2 5V3.75A1.75 1.75 0 0 1 3.75 2H5M11 2h1.25A1.75 1.75 0 0 1 14 3.75V5M14 11v1.25A1.75 1.75 0 0 1 12.25 14H11M5 14H3.75A1.75 1.75 0 0 1 2 12.25V11" />
    <circle cx="8" cy="8" r="2.4" />
  </Svg>
);
export const IconLayers = (p: IconProps) => (
  <Svg {...p}>
    <path d="M8 2 14 5 8 8 2 5Z" />
    <path d="m2 8 6 3 6-3M2 11l6 3 6-3" />
  </Svg>
);
export const IconSparkle = (p: IconProps) => (
  <Svg {...p}>
    <path d="m7 2 1.25 3.75L12 7l-3.75 1.25L7 12 5.75 8.25 2 7l3.75-1.25Z" />
    <path d="M12.5 10.5v3M11 12h3" />
  </Svg>
);
export const IconCode = (p: IconProps) => (
  <Svg {...p}>
    <path d="M5.5 4.5 2 8l3.5 3.5M10.5 4.5 14 8l-3.5 3.5" />
  </Svg>
);
export const IconTerminal = (p: IconProps) => (
  <Svg {...p}>
    <rect x="1.75" y="2.75" width="12.5" height="10.5" rx="1.75" />
    <path d="m4.5 6.25 2 1.75-2 1.75M8.25 10h3.25" />
  </Svg>
);
export const IconAlert = (p: IconProps) => (
  <Svg {...p}>
    <path d="M7.13 2.5a1 1 0 0 1 1.74 0l5.6 9.75a1 1 0 0 1-.87 1.5H2.4a1 1 0 0 1-.87-1.5Z" />
    <path d="M8 6.25v3" />
    <circle cx="8" cy="11.4" r=".4" fill="currentColor" />
  </Svg>
);
export const IconRefresh = (p: IconProps) => (
  <Svg {...p}>
    <path d="M13.25 8A5.25 5.25 0 1 1 11.5 4M13.25 2.25V5.5H10" />
  </Svg>
);
export const IconStar = (p: IconProps) => (
  <Svg {...p}>
    <path d="m8 2 1.8 3.65 4 .58-2.9 2.84.68 4L8 11.17 4.42 13.07l.68-4-2.9-2.84 4-.58Z" />
  </Svg>
);
export const IconFilter = (p: IconProps) => (
  <Svg {...p}>
    <path d="M2.25 3h11.5L9.5 8.25v4.5l-3-1.5v-3Z" />
  </Svg>
);
export const IconShield = (p: IconProps) => (
  <Svg {...p}>
    <path d="M8 1.75 13 3.5v4c0 3.15-2.15 5.6-5 6.75-2.85-1.15-5-3.6-5-6.75v-4Z" />
  </Svg>
);
export const IconCommand = (p: IconProps) => (
  <Svg {...p}>
    <path d="M6 6h4v4H6zM6 6V4.25A1.75 1.75 0 1 0 4.25 6H6M10 6V4.25A1.75 1.75 0 1 1 11.75 6H10M6 10v1.75A1.75 1.75 0 1 1 4.25 10H6M10 10v1.75A1.75 1.75 0 1 0 11.75 10H10" />
  </Svg>
);

/** The brand mark: a flat noise floor with one signal spike rising out of it. */
export const Mark = ({ size = 20, class: cls }: IconProps) => (
  <svg class={`mark${cls ? ` ${cls}` : ''}`} width={size} height={size} viewBox="0 0 32 32" fill="none" aria-hidden="true" focusable="false">
    <path d="M3 22.5h7.2l1.6-2.2 1.6 2.2h1.4L19 5.5l3.2 17h6.8" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" />
    <circle cx="19" cy="5.5" r="2.2" fill="currentColor" />
  </svg>
);
