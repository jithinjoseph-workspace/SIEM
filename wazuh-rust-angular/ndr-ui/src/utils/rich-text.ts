/**
 * AI answers (markdown) as readable HTML: headings, tables, lists, bold, italics, code, with
 * severities, verdicts, case numbers, ATT&CK ids and addresses as coloured chips. The text is
 * escaped first, so nothing in it (a log line, an attacker's string) becomes markup. Styles: the
 * global `.rich` rules in styles.css.
 */

// verdict phrases only: a word like "Suspicious" in a rule's name is not a verdict
const VERDICTS: [RegExp, string][] = [
  [/\b(compromised|true positive|confirmed incident)\b/gi, 'rt-verdict rt-bad'],
  [/\b(attack attempt)\b/gi, 'rt-verdict rt-warn'],
  [/\b(likely benign|false positive)\b/gi, 'rt-verdict rt-ok'],
];

/** Chips for the words an analyst scans for (escaped text in, HTML out). */
function decorate(s: string): string {
  return s
    .replace(/\b(CRITICAL|HIGH|MEDIUM|LOW)\b/g, (_, w: string) => `<span class="rt-pill rt-${w.toLowerCase()}">${w}</span>`)
    .replace(/\b(P[1-4])\b/g, '<span class="rt-pill rt-prio">$1</span>')
    .replace(/\bINC-\d{4}-\d{3,}\b/g, '<span class="rt-chip rt-case">$&</span>')
    .replace(/\bT\d{4}(?:\.\d{3})?\b/g, '<span class="rt-chip rt-mitre">$&</span>')
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '<span class="rt-chip rt-ip">$&</span>')
    .replace(/\b\d{1,3}(?:\.\d+)?%/g, '<span class="rt-num">$&</span>')
    .replace(VERDICTS[0][0], `<span class="${VERDICTS[0][1]}">$1</span>`)
    .replace(VERDICTS[1][0], `<span class="${VERDICTS[1][1]}">$1</span>`)
    .replace(VERDICTS[2][0], `<span class="${VERDICTS[2][1]}">$1</span>`);
}

function inline(s: string): string {
  return decorate(s)
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/(^|[\s(])[*_]([^*_\s][^*_]*?)[*_](?=[\s).,;:!?]|$)/g, '$1<em>$2</em>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    // a stray marker the model left (an unclosed ** or ###) is not shown
    .replace(/\*{2,}|#{2,}\s*/g, '');
}

export function richText(md: string): string {
  const esc = (md || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  let html = '';
  let list: '' | 'ul' | 'ol' = '';
  let table = 0; // rows written so far
  const closeList = () => { if (list) { html += `</${list}>`; list = ''; } };
  for (const raw of esc.split('\n')) {
    const bullet = /^\s*[-*•]\s+(.*)$/.exec(raw);
    const numbered = /^\s*\d+[.)]\s+(.*)$/.exec(raw);
    const row = /^\s*\|(.*)\|\s*$/.exec(raw);
    if (list === 'ul' && !bullet) closeList();
    if (list === 'ol' && !numbered) closeList();
    if (table && !row) { html += '</tbody></table></div>'; table = 0; }
    if (row) {
      if (/^[\s|:-]+$/.test(row[1])) continue; // the |---| line under the header
      const cells = row[1].split('|').map(c => inline(c.trim()));
      html += table ? `<tr>${cells.map(c => `<td>${c}</td>`).join('')}</tr>`
        : `<div class="rt-table"><table><thead><tr>${cells.map(c => `<th>${c}</th>`).join('')}</tr></thead><tbody>`;
      table++;
      continue;
    }
    const head = /^(#{1,4})\s+(.*)$/.exec(raw);
    if (head) { closeList(); html += `<h${Math.min(head[1].length + 2, 6)} class="rt-h">${inline(head[2])}</h${Math.min(head[1].length + 2, 6)}>`; continue; }
    if (/^\s*(-{3,}|\*{3,}|_{3,})\s*$/.test(raw)) { closeList(); html += '<hr class="rt-hr">'; continue; }
    if (bullet && list !== 'ul') { closeList(); html += '<ul>'; list = 'ul'; }
    if (numbered && list !== 'ol') { closeList(); html += '<ol>'; list = 'ol'; }
    const item = bullet || numbered;
    const text = inline(item ? item[1] : raw);
    html += item ? `<li>${text}</li>` : (text.trim() ? `<p>${text}</p>` : '');
  }
  closeList();
  return html + (table ? '</tbody></table></div>' : '');
}
