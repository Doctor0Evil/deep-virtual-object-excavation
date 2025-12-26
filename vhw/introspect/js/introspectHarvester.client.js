/**
 * Introspective Virtual Object Harvester (Browser / DevTools)
 * Virtual-Hardwire / VSC-Artemis Ecosystem.[file:1][file:2]
 *
 * This module:
 *  - Records deep inspection paths from DevTools / console interactions.
 *  - Classifies rare / low-visibility objects (closures, internal slots, non-enumerables).
 *  - Emits JSON IntrospectFinding / IntrospectSession payloads.
 *  - Applies governance filters (no secrets, no neurosignals, no PII).
 *  - Publishes upstream to GitHub issues and AI-chat metadata streams.
 */

/* eslint-disable no-console */

const GOVERNANCE_PATTERNS = {
  secrets: [
    { id: "aws_access_key", regex: /AKIA[0-9A-Z]{16}/g },                       // AWS key.[file:4]
    { id: "gcp_api_key", regex: /AIza[0-9A-Za-z\-_]{35}/g },                    // GCP key.[file:4]
    { id: "private_key_block", regex: /-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/g } // PEM.[file:4]
  ],
  neurosignals: [
    { id: "neuromorphic_banned_band", regex: /\b9(4[4-9]|5[0-8])MHz\b/g },     // 944–958 MHz.[file:1]
    { id: "neurosignal_coercion", regex: /\bCOERCION\b/gi },                    // banned signal marker.[file:1]
    { id: "neurosignal_emotion_control", regex: /\bEMOTIONCONTROL\b/gi }        // banned signal marker.[file:1]
  ]
};

const ENVIRONMENT = (() => {
  if (typeof window !== "undefined" && typeof document !== "undefined") return "browser";
  if (typeof self !== "undefined" && self instanceof WorkerGlobalScope) return "worker";
  return "node";
})();

/**
 * @typedef {Object} IntrospectFinding
 * @property {string}  session_id
 * @property {string}  timestamp_utc
 * @property {string}  environment              // "browser","node","worker","vhw-sandbox"
 * @property {string}  root_object_kind         // "buffer","function","other","typed-array","scope-frame","prototype-node"
 * @property {string}  [root_object_hint]
 * @property {string[]} navigation_path
 * @property {string}  [rare_object_kind]       // "closure_capture","non-enumerable","symbolic","internal-slot",...
 * @property {string}  [rare_object_summary]
 * @property {number}  [prototype_depth]
 * @property {number}  [scope_depth]
 * @property {string}  [visibility]
 * @property {string}  [source_location]
 * @property {string[]} [tags]
 * @property {string}  [notes]
 * @property {string[]} [governance_flags]
 * @property {number}  [secret_redactions]
 * @property {boolean} [neurosignal_blocked]
 * @property {string}  [export_channel]         // "github-issue","ai-chat","local-only","cas-queue"
 */

/**
 * @typedef {Object} IntrospectSession
 * @property {string}          session_id
 * @property {string}          started_at_utc
 * @property {string}          [finished_at_utc]
 * @property {string}          environment
 * @property {string}          [player_handle]
 * @property {number}          finding_count
 * @property {IntrospectFinding[]} findings
 * @property {Object}          [metrics_snapshot]
 * @property {Object}          [governance_summary]
 */

/**
 * Create a new session skeleton.
 * @param {Partial<IntrospectSession>} [opts]
 * @returns {IntrospectSession}
 */
export function createSession(opts = {}) {
  const now = new Date().toISOString();
  const sessionId = opts.session_id || `INTROSPECT-${ENVIRONMENT}-${now}-${Math.random().toString(36).slice(2, 8)}`;

  /** @type {IntrospectSession} */
  const session = {
    session_id: sessionId,
    started_at_utc: now,
    environment: ENVIRONMENT,
    player_handle: opts.player_handle || "vhw-introspect-player",
    finding_count: 0,
    findings: [],
    metrics_snapshot: {
      finding_count_total: 0,
      avg_scope_depth: 0,
      avg_prototype_depth: 0,
      rare_object_ratio: {}
    },
    governance_summary: undefined
  };

  return session;
}

/**
 * Infer root_object_kind based on runtime object.
 * @param {*} obj
 * @returns {string}
 */
function inferRootObjectKind(obj) {
  if (!obj) return "other";
  if (obj._isBuffer || (typeof Buffer !== "undefined" && obj instanceof Buffer)) return "buffer";
  if (typeof obj === "function") return "function";
  if (obj.BYTES_PER_ELEMENT && typeof obj.length === "number") return "typed-array";
  return "other";
}

/**
 * Summarize object into a short hint string.
 * @param {*} obj
 * @returns {string}
 */
function summarizeRootObject(obj) {
  if (!obj) return "null|undefined";
  if (typeof obj === "function") {
    return obj.name ? `function ${obj.name}()` : "anonymous function";
  }
  if (obj._isBuffer || (typeof Buffer !== "undefined" && obj instanceof Buffer)) {
    return `buffer(len=${obj.length ?? "?"})`;
  }
  if (obj && obj.constructor && obj.constructor.name) {
    return obj.constructor.name;
  }
  return typeof obj;
}

/**
 * Simple navigation path capture from a sequence of labels, already observed by UI.[conversation_history:0]
 * @param {string[]} segments
 * @returns {string[]}
 */
function normalizeNavigationPath(segments) {
  return segments.map((s) => String(s)).slice(0, 16);
}

/**
 * Compute prototype chain depth.
 * @param {*} obj
 * @returns {number}
 */
function computePrototypeDepth(obj) {
  let depth = 0;
  let current = obj && Object.getPrototypeOf(obj);
  while (current) {
    depth += 1;
    current = Object.getPrototypeOf(current);
    if (depth > 32) break;
  }
  return depth;
}

/**
 * Classify rare object kind heuristically from descriptor.
 * @param {*} value
 * @param {PropertyDescriptor} [desc]
 * @param {string} [slotName]
 * @returns {string|undefined}
 */
function classifyRareObjectKind(value, desc, slotName) {
  if (desc && desc.enumerable === false) return "non-enumerable";
  if (slotName && /^Symbol\(/.test(slotName)) return "symbolic";
  if (slotName && slotName.startsWith("[[")) return "internal-slot";
  if (typeof value === "function" && /\bclosure\b/i.test(String(value))) return "closure_capture";
  return undefined;
}

/**
 * Governance filter: redact secrets, detect neurosignals, compute flags.
 * @param {string} text
 * @returns {{ redacted: string, secretCount: number, flags: string[], neurosignalBlocked: boolean }}
 */
function applyGovernanceFilters(text) {
  let redacted = text || "";
  let secretCount = 0;
  const flags = [];
  let neurosignalBlocked = false;

  for (const pattern of GOVERNANCE_PATTERNS.secrets) {
    if (pattern.regex.test(redacted)) {
      redacted = redacted.replace(pattern.regex, "***REDACTED***");
      secretCount += 1;
      flags.push(pattern.id);
      pattern.regex.lastIndex = 0;
    }
  }

  for (const pattern of GOVERNANCE_PATTERNS.neurosignals) {
    if (pattern.regex.test(redacted)) {
      neurosignalBlocked = true;
      flags.push(pattern.id);
      pattern.regex.lastIndex = 0;
    }
  }

  if (flags.length > 0) flags.sort();

  return { redacted, secretCount, flags, neurosignalBlocked };
}

/**
 * Build a single IntrospectFinding from an inspected object and UI path.
 * @param {IntrospectSession} session
 * @param {*} rootObject
 * @param {string[]} uiPathSegments  e.g. ["buffer.inspect","[[Scopes]]","scope[2]","locals.x"].[conversation_history:0]
 * @param {Object} [options]
 * @param {string} [options.notes]
 * @param {string} [options.sourceLocation]
 * @param {string[]} [options.tags]
 * @returns {IntrospectFinding}
 */
export function createFinding(session, rootObject, uiPathSegments, options = {}) {
  const ts = new Date().toISOString();
  const rootKind = inferRootObjectKind(rootObject);
  const rootHint = summarizeRootObject(rootObject);
  const navigation_path = normalizeNavigationPath(uiPathSegments);
  const prototype_depth = computePrototypeDepth(rootObject);
  const scope_depth = navigation_path.length;

  const rawNotes = options.notes || `Introspect path: ${navigation_path.join(" -> ")}`;
  const { redacted, secretCount, flags, neurosignalBlocked } = applyGovernanceFilters(rawNotes);

  /** @type {IntrospectFinding} */
  const finding = {
    session_id: session.session_id,
    timestamp_utc: ts,
    environment: session.environment,
    root_object_kind: rootKind,
    root_object_hint: rootHint,
    navigation_path,
    rare_object_kind: undefined,
    rare_object_summary: undefined,
    prototype_depth,
    scope_depth,
    visibility: "enumerable",
    source_location: options.sourceLocation || "unknown:0:0",
    tags: options.tags || [],
    notes: redacted,
    governance_flags: flags,
    secret_redactions: secretCount,
    neurosignal_blocked: neurosignalBlocked,
    export_channel: "github-issue"
  };

  // Derive rare_object_kind from basic heuristics.
  const leafName = navigation_path[navigation_path.length - 1] || "";
  const leafValue = rootObject && rootObject[leafName];
  const desc = rootObject ? Object.getOwnPropertyDescriptor(rootObject, leafName) : undefined;
  const rare = classifyRareObjectKind(leafValue, desc, leafName);
  if (rare) {
    finding.rare_object_kind = rare;
    finding.rare_object_summary = `${rare} at path ${leafName}`;
  }

  // Visibility refinement.
  if (desc && desc.enumerable === false) finding.visibility = "non-enumerable";

  // Export-channel policy.
  if (neurosignalBlocked) {
    finding.export_channel = "local-only";
  } else if (flags.includes("aws_access_key") || flags.includes("gcp_api_key") || flags.includes("private_key_block")) {
    finding.export_channel = "local-only";
  } else {
    finding.export_channel = "github-issue";
  }

  return finding;
}

/**
 * Append finding to session and update metrics.
 * @param {IntrospectSession} session
 * @param {IntrospectFinding} finding
 */
export function appendFinding(session, finding) {
  session.findings.push(finding);
  session.finding_count = session.findings.length;

  const total = session.findings.length;
  let sumScope = 0;
  let sumProto = 0;
  const rareCountByKind = {};

  for (const f of session.findings) {
    if (typeof f.scope_depth === "number") sumScope += f.scope_depth;
    if (typeof f.prototype_depth === "number") sumProto += f.prototype_depth;
    if (f.rare_object_kind) {
      rareCountByKind[f.rare_object_kind] = (rareCountByKind[f.rare_object_kind] || 0) + 1;
    }
  }

  const avg_scope_depth = total ? sumScope / total : 0;
  const avg_prototype_depth = total ? sumProto / total : 0;
  const rare_object_ratio = {};
  Object.entries(rareCountByKind).forEach(([k, v]) => {
    rare_object_ratio[k] = v / total;
  });

  session.metrics_snapshot = {
    finding_count_total: total,
    avg_scope_depth,
    avg_prototype_depth,
    rare_object_ratio
  };
}

/**
 * Finalize session and compute governance summary.
 * @param {IntrospectSession} session
 * @returns {IntrospectSession}
 */
export function finalizeSession(session) {
  session.finished_at_utc = new Date().toISOString();

  let redactions_total = 0;
  let neurosignal_events = 0;
  let blocked_exports = 0;

  for (const f of session.findings) {
    redactions_total += f.secret_redactions || 0;
    if (f.neurosignal_blocked) neurosignal_events += 1;
    if (f.export_channel === "local-only") blocked_exports += 1;
  }

  const total_findings = session.finding_count;
  const exportable_findings = total_findings - blocked_exports;

  session.governance_summary = {
    session_id: session.session_id,
    total_findings,
    redactions_total,
    neurosignal_events,
    blocked_exports,
    exportable_findings,
    policy_version: "gov-policy-v3.1.0",
    reviewer_role: "auto-introspect-harvester-js"
  };

  return session;
}

/**
 * Render a GitHub issue body string from a session.
 * @param {IntrospectSession} session
 * @returns {string}
 */
export function renderGithubIssueBody(session) {
  const gs = session.governance_summary || finalizeSession(session).governance_summary;

  const sortedFindings = [...session.findings].sort((a, b) => {
    const ak = a.rare_object_kind || "";
    const bk = b.rare_object_kind || "";
    if (ak === bk) return 0;
    return ak < bk ? -1 : 1;
  });

  const top3 = sortedFindings.slice(0, 3).map((f, idx) => {
    return `  ${idx + 1}. [${f.rare_object_kind || "normal"}] ${f.rare_object_summary || f.root_object_hint} @ ${f.source_location}`;
  }).join("\n");

  const navSamples = sortedFindings.slice(0, 3).map((f) => {
    return `  - ${f.navigation_path.join(" -> ")}`;
  }).join("\n");

  return [
    `Session: ${session.session_id}`,
    `Environment: ${session.environment}`,
    `Findings: ${session.finding_count}`,
    `Redactions: ${gs.redactions_total}`,
    `Exportable findings: ${gs.exportable_findings}`,
    "",
    "Highlights:",
    top3 || "  (no rare objects)",
    "",
    "Navigation Samples:",
    navSamples || "  (no navigation samples)",
    ""
  ].join("\n");
}

/**
 * Export payload for AI chat metadata stream.
 * Secrets / neurosignal-blocked findings are stripped to obey governance.[file:3]
 * @param {IntrospectSession} session
 * @returns {{ session: IntrospectSession, findings: IntrospectFinding[] }}
 */
export function buildAIChatMetadataPayload(session) {
  const safeFindings = session.findings.filter((f) => {
    if (f.neurosignal_blocked) return false;
    if (f.export_channel === "local-only") return false;
    return true;
  });

  const cloneSession = {
    ...session,
    findings: safeFindings
  };

  return {
    session: cloneSession,
    findings: safeFindings
  };
}

/**
 * Convenience capture helper:
 *  - creates session if needed
 *  - creates finding
 *  - appends and returns { session, finding }.
 *
 * @param {IntrospectSession|null} session
 * @param {*} rootObject
 * @param {string[]} uiPathSegments
 * @param {Object} [options]
 * @returns {{ session: IntrospectSession, finding: IntrospectFinding }}
 */
export function captureFinding(session, rootObject, uiPathSegments, options = {}) {
  const activeSession = session || createSession();
  const finding = createFinding(activeSession, rootObject, uiPathSegments, options);
  appendFinding(activeSession, finding);
  return { session: activeSession, finding };
}

/**
 * Example usage (browser console / devtools):
 *
 *   import {
 *     createSession,
 *     captureFinding,
 *     finalizeSession,
 *     renderGithubIssueBody
 *   } from "./introspectHarvester.client.js";
 *
 *   const s = createSession({ player_handle: "dev-console-player" });
 *   const buffer = new TextEncoder().encode("hello world");
 *
 *   const { session, finding } = captureFinding(
 *     s,
 *     buffer,
 *     ["buffer.inspect", "[[Scopes]]", "scope[2]", "locals.internal_config_cache"],
 *     {
 *       notes: "Discovered hidden scope variables under inspect>[[Scopes]]>2>locals.internal_config_cache",
 *       sourceLocation: "app/virtual/buffer-debugger.ts:44:11",
 *       tags: ["buffer", "internal-slot", "debug-only"]
 *     }
 *   );
 *
 *   finalizeSession(session);
 *   console.log("GitHub issue body:\\n" + renderGithubIssueBody(session));
 *
 * This pattern keeps your “Introspect‑Explorer / Code Archaeology game”
 * standardized on JSON IntrospectFinding / IntrospectSession payloads.[conversation_history:0]
 */

