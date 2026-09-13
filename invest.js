'use strict';

const { STAGES } = require('./playbook');

function collectIocs(investigation) {
  const iocs = { hashes: [], ips: [], domains: [], urls: [] };
  const fa = investigation.data.fileAnalysis || {};
  const na = investigation.data.networkActivity || {};

  if (fa.hash) iocs.hashes.push(...splitList(fa.hash));
  if (na.destinationIp) iocs.ips.push(...splitList(na.destinationIp));
  if (na.domain) iocs.domains.push(...splitList(na.domain));
  if (na.urls) iocs.urls.push(...splitList(na.urls));

  return iocs;
}

function splitList(value) {
  return String(value)
    .split(/[,\n;]+/)
    .map((v) => v.trim())
    .filter(Boolean);
}

function toMarkdown(investigation) {
  const lines = [];
  lines.push(`# Malware Investigation Report`);
  lines.push('');
  lines.push(`- **ID:** ${investigation.id}`);
  lines.push(`- **Alert ID:** ${investigation.alertId || '(none)'}`);
  lines.push(`- **Analyst:** ${investigation.analyst || '(unspecified)'}`);
  lines.push(`- **Created:** ${investigation.createdAt}`);
  lines.push(`- **Last updated:** ${investigation.updatedAt}`);
  lines.push(`- **Status:** ${investigation.status}`);
  lines.push('');
  lines.push('---');

  for (const stage of STAGES) {
    const data = investigation.data[stage.key] || {};
    const answered = stage.fields.filter((f) => data[f.key]);
    lines.push('');
    lines.push(`## ${stage.id}. ${stage.title} _(${stage.phase})_`);
    lines.push('');
    lines.push(stage.description);
    lines.push('');
    if (answered.length === 0) {
      lines.push('_No data recorded for this stage._');
    } else {
      lines.push('| Field | Value |');
      lines.push('|---|---|');
      for (const f of stage.fields) {
        if (data[f.key]) lines.push(`| ${f.label} | ${escapeMd(data[f.key])} |`);
      }
    }
    if (stage.watchFor) {
      const flagged = data._flags || [];
      if (flagged.length) {
        lines.push('');
        lines.push('**Flagged indicators:**');
        for (const flag of flagged) lines.push(`- ${flag}`);
      }
    }
    if (data.notes) {
      lines.push('');
      lines.push(`**Notes:** ${data.notes}`);
    }
  }

  const iocs = collectIocs(investigation);
  lines.push('');
  lines.push('---');
  lines.push('');
  lines.push('## IOC Summary');
  lines.push('');
  for (const [type, values] of Object.entries(iocs)) {
    lines.push(`**${capitalize(type)}:** ${values.length ? values.join(', ') : '_none recorded_'}`);
  }

  const mitre = investigation.data.documentHunt?.mitreMapping;
  lines.push('');
  lines.push('## MITRE ATT&CK Mapping');
  lines.push('');
  lines.push(mitre ? mitre : '_not yet mapped_');

  lines.push('');
  lines.push('## Attack Chain Summary');
  lines.push('');
  lines.push('How it entered → What executed → What it did → Where it moved → How it was contained');
  lines.push('');
  lines.push(`- **Entered:** ${investigation.data.detection?.detectionName || '_unknown_'}`);
  lines.push(`- **Executed:** ${investigation.data.processTree?.parentProcess || '_unknown_'} → ${investigation.data.processTree?.childProcesses || '_unknown_'}`);
  lines.push(`- **Did:** ${summarizeImpact(investigation)}`);
  lines.push(`- **Moved:** ${investigation.data.impact?.lateralMovement || '_none recorded_'}`);
  lines.push(`- **Contained via:** ${summarizeContainment(investigation)}`);

  return lines.join('\n');
}

function summarizeImpact(investigation) {
  const impact = investigation.data.impact || {};
  const items = ['persistence', 'credentialAccess', 'privilegeEscalation', 'dataExfiltration']
    .map((k) => impact[k])
    .filter(Boolean);
  return items.length ? items.join('; ') : '_none recorded_';
}

function summarizeContainment(investigation) {
  const c = investigation.data.containRemediate || {};
  const items = Object.entries(c)
    .filter(([k, v]) => v && k !== 'notes' && k !== '_flags')
    .map(([, v]) => v);
  return items.length ? items.join('; ') : '_none recorded_';
}

function escapeMd(value) {
  return String(value).replace(/\|/g, '\\|').replace(/\n/g, '<br>');
}

function capitalize(s) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

module.exports = { toMarkdown, collectIocs };
