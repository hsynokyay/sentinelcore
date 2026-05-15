"use client";

import { Fragment } from "react";

// MarkdownDescription renders the structured description format the DAST
// worker writes (rule_metadata.go RenderDescription). It deliberately
// supports only the subset we emit — no HTML passthrough, no script tags,
// no XSS surface. Anything outside the supported syntax falls through as
// plain text.
//
// Supported syntax:
//   **Heading**            — bold paragraph header
//   - bullet              — list item
//   `inline code`         — monospace span
//   https://...           — auto-linked
//   blank line            — paragraph break
interface MarkdownDescriptionProps {
  source: string;
}

export function MarkdownDescription({ source }: MarkdownDescriptionProps) {
  if (!source) {
    return (
      <p className="text-sm text-muted-foreground italic">
        No description available.
      </p>
    );
  }

  const blocks = parseBlocks(source);

  return (
    <div className="space-y-4 text-sm leading-relaxed">
      {blocks.map((block, i) => (
        <RenderBlock key={i} block={block} />
      ))}
    </div>
  );
}

// ---------- parser ----------

type Block =
  | { kind: "heading"; text: string }
  | { kind: "paragraph"; text: string }
  | { kind: "list"; items: string[] };

// **bold** at the start of an otherwise-empty line marks a heading.
const HEADING_RE = /^\*\*(.+?)\*\*\s*$/;
const BULLET_RE = /^- (.*)$/;

function parseBlocks(source: string): Block[] {
  const lines = source.replace(/\r\n/g, "\n").split("\n");
  const blocks: Block[] = [];
  let buf: string[] = [];
  let bulletBuf: string[] = [];

  const flushParagraph = () => {
    if (buf.length === 0) return;
    blocks.push({ kind: "paragraph", text: buf.join("\n").trim() });
    buf = [];
  };
  const flushList = () => {
    if (bulletBuf.length === 0) return;
    blocks.push({ kind: "list", items: bulletBuf });
    bulletBuf = [];
  };

  for (const raw of lines) {
    const line = raw.trim();

    if (line === "") {
      flushParagraph();
      flushList();
      continue;
    }

    const headingMatch = line.match(HEADING_RE);
    if (headingMatch) {
      flushParagraph();
      flushList();
      blocks.push({ kind: "heading", text: headingMatch[1] });
      continue;
    }

    const bulletMatch = line.match(BULLET_RE);
    if (bulletMatch) {
      flushParagraph();
      bulletBuf.push(bulletMatch[1]);
      continue;
    }

    flushList();
    buf.push(line);
  }
  flushParagraph();
  flushList();

  return blocks;
}

// ---------- renderers ----------

function RenderBlock({ block }: { block: Block }) {
  switch (block.kind) {
    case "heading":
      return (
        <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          {block.text}
        </h4>
      );
    case "paragraph":
      return (
        <p className="text-foreground">
          <Inline text={block.text} />
        </p>
      );
    case "list":
      return (
        <ul className="space-y-1.5 list-disc list-outside pl-5 marker:text-muted-foreground">
          {block.items.map((item, i) => (
            <li key={i} className="text-foreground">
              <Inline text={item} />
            </li>
          ))}
        </ul>
      );
  }
}

// ---------- inline tokenizer ----------
// Splits text into runs of plain / `code` / **bold** / autolink. Order
// matters: we tokenize one run at a time, longest-match-first per
// position, so nesting like **`code`** still works (the bold strips its
// markers, then the code regex catches the inner ticks).

const URL_RE = /https?:\/\/[^\s)]+/g;
const CODE_RE = /`([^`]+)`/g;
const BOLD_RE = /\*\*([^*]+)\*\*/g;

interface Token {
  kind: "text" | "code" | "bold" | "link";
  value: string;
}

function tokenize(text: string): Token[] {
  // Multi-pass: bold → code → link. Each pass converts matched ranges to
  // sentinels we can splice back at render time. The simplest correct
  // implementation is a single scan with a ranked regex.
  const re = new RegExp(
    `(${BOLD_RE.source})|(${CODE_RE.source})|(${URL_RE.source})`,
    "g",
  );
  const tokens: Token[] = [];
  let lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = re.exec(text)) !== null) {
    if (match.index > lastIndex) {
      tokens.push({ kind: "text", value: text.slice(lastIndex, match.index) });
    }
    if (match[1]) {
      tokens.push({ kind: "bold", value: match[2] });
    } else if (match[3]) {
      tokens.push({ kind: "code", value: match[4] });
    } else if (match[5]) {
      tokens.push({ kind: "link", value: match[5] });
    }
    lastIndex = match.index + match[0].length;
  }
  if (lastIndex < text.length) {
    tokens.push({ kind: "text", value: text.slice(lastIndex) });
  }
  return tokens;
}

function Inline({ text }: { text: string }) {
  const tokens = tokenize(text);
  return (
    <>
      {tokens.map((tok, i) => {
        switch (tok.kind) {
          case "text":
            return <Fragment key={i}>{tok.value}</Fragment>;
          case "bold":
            return (
              <strong key={i} className="font-semibold text-foreground">
                {tok.value}
              </strong>
            );
          case "code":
            return (
              <code
                key={i}
                className="px-1.5 py-0.5 rounded text-[12px] font-mono bg-muted border"
              >
                {tok.value}
              </code>
            );
          case "link":
            return (
              <a
                key={i}
                href={tok.value}
                target="_blank"
                rel="noreferrer noopener"
                className="text-primary hover:underline break-all"
              >
                {tok.value}
              </a>
            );
        }
      })}
    </>
  );
}
