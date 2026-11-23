/**
 * Browser downloads for The Surge's chart: a Blob behind a temporary <a download>, and a PNG drawn
 * from the chart's SVG with its computed colours inlined, so it matches the theme on screen.
 */

/** Save a Blob as a file through a temporary link. */
export function downloadBlob(blob: Blob, name: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.rel = 'noopener';
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Some browsers read the URL after click() returns.
  window.setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

const STYLE_PROPS = ['fill', 'fill-opacity', 'stroke', 'stroke-width', 'stroke-dasharray', 'stroke-opacity', 'stroke-linecap', 'stroke-linejoin', 'opacity', 'font-family', 'font-size', 'font-weight', 'paint-order'] as const;

/** A standalone copy of the SVG: computed styles inlined, the hover and drag marks left out. */
function standaloneSvg(svg: SVGSVGElement): string {
  const clone = svg.cloneNode(true) as SVGSVGElement;
  const src = [svg, ...svg.querySelectorAll('*')];
  const dst = [clone, ...clone.querySelectorAll('*')];
  src.forEach((el, i) => {
    const cs = getComputedStyle(el);
    const style = STYLE_PROPS.map((p) => `${p}:${cs.getPropertyValue(p)}`).join(';');
    dst[i].setAttribute('style', style);
  });
  clone.querySelectorAll('[data-export="skip"]').forEach((el) => el.remove());
  clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
  clone.removeAttribute('tabindex');
  return new XMLSerializer().serializeToString(clone);
}

export interface PngText {
  title: string;
  subtitle: string;
  legend: { label: string; color: string; dashed?: boolean }[];
  footer: string;
}

/** Draw the chart with a title, legend and footer onto a canvas at 2x, then save it as a PNG. */
export async function downloadPng(svg: SVGSVGElement, text: PngText, name: string): Promise<void> {
  const w = svg.width.baseVal.value;
  const h = svg.height.baseVal.value;
  const root = getComputedStyle(document.documentElement);
  const color = (v: string, fallback: string) => root.getPropertyValue(v).trim() || fallback;
  const bg = color('--surface', '#111317');
  const fg = color('--text', '#e6e8eb');
  const muted = color('--muted', '#8a919c');
  const pad = 20;
  const head = 64;
  const foot = 28;
  const scale = 2;
  const font = getComputedStyle(document.body).fontFamily || 'sans-serif';
  // Lay the legend out first, wrapping to the chart width, so the canvas can be sized for it.
  const measure = document.createElement('canvas').getContext('2d');
  if (measure) measure.font = `12px ${font}`;
  const spots: { x: number; row: number }[] = [];
  let lx = pad;
  let row = 0;
  for (const item of text.legend) {
    const iw = 20 + (measure?.measureText(item.label).width ?? item.label.length * 7);
    if (lx > pad && lx + iw > pad + w) {
      lx = pad;
      row++;
    }
    spots.push({ x: lx, row });
    lx += iw + 16;
  }
  const legendH = (row + 1) * 18 + 4;
  const canvas = document.createElement('canvas');
  canvas.width = (w + pad * 2) * scale;
  canvas.height = (head + legendH + h + foot) * scale;
  const ctx = canvas.getContext('2d');
  if (!ctx) throw new Error('Canvas is not available');
  ctx.scale(scale, scale);
  ctx.fillStyle = bg;
  ctx.fillRect(0, 0, w + pad * 2, head + legendH + h + foot);
  ctx.fillStyle = fg;
  ctx.font = `600 16px ${font}`;
  ctx.fillText(text.title, pad, 28);
  ctx.fillStyle = muted;
  ctx.font = `12px ${font}`;
  ctx.fillText(text.subtitle, pad, 48, w);
  text.legend.forEach((item, k) => {
    const { x, row: r } = spots[k];
    const ly = head + 4 + r * 18;
    ctx.strokeStyle = item.color;
    ctx.lineWidth = 2;
    ctx.setLineDash(item.dashed ? [4, 3] : []);
    ctx.beginPath();
    ctx.moveTo(x, ly);
    ctx.lineTo(x + 14, ly);
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillStyle = muted;
    ctx.fillText(item.label, x + 20, ly + 4);
  });
  const img = new Image();
  // A data: URL, not a blob: one: the site's CSP allows images from 'self' and data: only.
  await new Promise<void>((resolve, reject) => {
    img.onload = () => resolve();
    img.onerror = () => reject(new Error('Could not draw the chart'));
    img.src = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(standaloneSvg(svg))}`;
  });
  ctx.drawImage(img, pad, head + legendH, w, h);
  ctx.fillStyle = muted;
  ctx.font = `11px ${font}`;
  ctx.fillText(text.footer, pad, head + legendH + h + 18, w);
  const blob = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, 'image/png'));
  if (!blob) throw new Error('Could not make the PNG');
  downloadBlob(blob, name);
}
