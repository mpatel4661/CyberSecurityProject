const findingsList = document.getElementById('findingsList');
const headerStatus = document.getElementById('headerStatus');
const executiveSummary = document.getElementById('executiveSummary');
const frontendChecklist = document.getElementById('frontendChecklist');
const backendChecklist = document.getElementById('backendChecklist');
const infraChecklist = document.getElementById('infraChecklist');
const themeToggle = document.querySelector('[data-theme-toggle]');
const filters = document.querySelectorAll('.filter');
const form = document.getElementById('scanForm');
const demoButton = document.getElementById('loadDemo');

let currentFindings = [];
let activeFilter = 'all';

const headerRules = [
  { key: 'csp', name: 'Content-Security-Policy', desc: 'XSS aur unsafe resource loading ko control karta hai.' },
  { key: 'hsts', name: 'Strict-Transport-Security', desc: 'Browser ko HTTPS-only use karne ke liye force karta hai.' },
  { key: 'nosniff', name: 'X-Content-Type-Options', desc: 'MIME sniffing attacks reduce karta hai.' },
  { key: 'frame', name: 'X-Frame-Options / frame-ancestors', desc: 'Clickjacking risk reduce karta hai.' },
  { key: 'referrer', name: 'Referrer-Policy', desc: 'Sensitive URL data leak ko limit karta hai.' }
];

const frontendRules = [
  { id: 'fe-1', title: 'Missing CSP', severity: 'high', area: 'Frontend', owasp: 'A02:2025 Security Misconfiguration', when: data => !data.hasCsp, evidence: 'Response me Content-Security-Policy missing ya weak hai.', why: 'CSP ke bina malicious scripts aur XSS impact badh sakta hai.', fix: 'Strict CSP lagaiye, nonce/hash use kariye, aur sirf required domains allowlist kariye.' },
  { id: 'fe-2', title: 'Mixed content possibility', severity: 'medium', area: 'Frontend', owasp: 'A04:2025 Cryptographic Failures', when: data => !data.hasHttps, evidence: 'HTTPS absent hone par scripts/images insecure transport se aa sakte hain.', why: 'Attacker content tamper ya sniff kar sakta hai.', fix: 'Website aur assets dono ko HTTPS par serve kariye.' },
  { id: 'fe-3', title: 'Client-side validation only risk', severity: 'medium', area: 'Frontend', owasp: 'A06:2025 Insecure Design', when: data => /form|upload|login|register/i.test(data.notes), evidence: 'Frontend forms present hain, isliye server-side validation confirm karna zaroori hai.', why: 'Sirf browser validation bypass ki ja sakti hai.', fix: 'Har input ko backend par validate, sanitize aur reject rules ke saath enforce kariye.' },
  { id: 'fe-4', title: 'Dependency exposure review required', severity: 'low', area: 'Frontend', owasp: 'A03:2025 Software Supply Chain Failures', when: () => true, evidence: 'Third-party JS libraries ka version review static app me manually required hai.', why: 'Outdated dependencies known CVEs la sakti hain.', fix: 'Dependency inventory maintain kariye aur regular patching process rakhiye.' },
  { id: 'fe-5', title: 'Clickjacking defense check', severity: 'medium', area: 'Frontend', owasp: 'A02:2025 Security Misconfiguration', when: () => true, evidence: 'Frame protection headers ki verification required hai.', why: 'Sensitive pages malicious iframe me embed ho sakte hain.', fix: 'X-Frame-Options ya CSP frame-ancestors configure kariye.' }
];

const backendRules = [
  { id: 'be-1', title: 'Rate limiting missing', severity: 'high', area: 'Backend', owasp: 'A07:2025 Authentication Failures', when: data => !data.hasRateLimit, evidence: 'Login/API brute-force controls absent dikh rahe hain.', why: 'Credential stuffing aur abuse ka chance badhta hai.', fix: 'IP/user based rate limiting, captcha, lockout aur anomaly detection add kariye.' },
  { id: 'be-2', title: 'Broken access control review required', severity: 'critical', area: 'Backend', owasp: 'A01:2025 Broken Access Control', when: data => /admin|panel|dashboard|api/i.test(data.notes), evidence: 'Privileged routes mention hui hain, authorization verification zaroori hai.', why: 'Unauthorized data access ya privilege escalation ho sakta hai.', fix: 'Har route par server-side authorization checks aur role validation enforce kariye.' },
  { id: 'be-3', title: 'Injection protection review', severity: 'high', area: 'Backend', owasp: 'A05:2025 Injection', when: data => /search|query|filter|sql|database|upload/i.test(data.notes), evidence: 'Dynamic input processing mention hui hai.', why: 'Unsanitized input SQL/command/template injection me badal sakta hai.', fix: 'Parameterized queries, strict validation, escaping, ORM safeguards aur allowlists use kariye.' },
  { id: 'be-4', title: 'Session and token hardening', severity: 'medium', area: 'Backend', owasp: 'A07:2025 Authentication Failures', when: data => data.authType !== 'none', evidence: 'Authentication flow selected hai.', why: 'Weak session handling unauthorized access de sakti hai.', fix: 'Secure, HttpOnly, SameSite cookies; token expiry; rotation; MFA; logout invalidation apply kariye.' },
  { id: 'be-5', title: 'Exception handling review', severity: 'medium', area: 'Backend', owasp: 'A10:2025 Mishandling of Exceptional Conditions', when: () => true, evidence: 'Unhandled errors verbose stack trace expose kar sakte hain.', why: 'Attackers internal structure samajh sakte hain.', fix: 'Centralized error handler, safe messages, logging, and graceful failures implement kariye.' }
];

const infraRules = [
  { id: 'in-1', title: 'HTTPS hardening needed', severity: 'critical', area: 'Infrastructure', owasp: 'A04:2025 Cryptographic Failures', when: data => !data.hasHttps, evidence: 'HTTPS unchecked hai.', why: 'Sensitive data interception aur tampering ka direct risk hota hai.', fix: 'TLS enable kariye, HTTP to HTTPS redirect lagaiye, strong certificates use kariye.' },
  { id: 'in-2', title: 'WAF not indicated', severity: 'low', area: 'Infrastructure', owasp: 'A02:2025 Security Misconfiguration', when: data => !data.hasWaf, evidence: 'WAF presence specified nahi hai.', why: 'Automated malicious traffic ko filter karna mushkil hota hai.', fix: 'Managed WAF ya reverse proxy layer consider kariye.' },
  { id: 'in-3', title: 'Security header baseline incomplete', severity: 'high', area: 'Infrastructure', owasp: 'A02:2025 Security Misconfiguration', when: data => !data.hasCsp || !data.hasHttps, evidence: 'Baseline hardening controls incomplete hain.', why: 'Basic browser-enforced security controls weak hain.', fix: 'CSP, HSTS, nosniff, frame controls aur referrer policy enable kariye.' },
  { id: 'in-4', title: 'Open service exposure review', severity: 'medium', area: 'Infrastructure', owasp: 'A02:2025 Security Misconfiguration', when: () => true, evidence: 'Public services aur unnecessary ports ka audit required hai.', why: 'Extra exposed services attack surface ko bada dete hain.', fix: 'Only required ports expose kariye, firewall aur allowlist maintain kariye.' }
];

function severityWeight(level) {
  return { critical: 25, high: 16, medium: 10, low: 5 }[level] || 0;
}

function evaluate(data) {
  const rules = [...frontendRules, ...backendRules, ...infraRules];
  const findings = rules.filter(rule => rule.when(data)).map(rule => ({ ...rule }));
  findings.sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity));
  return findings;
}

function renderFindings() {
  const filtered = activeFilter === 'all' ? currentFindings : currentFindings.filter(item => item.severity === activeFilter);
  if (!filtered.length) {
    findingsList.className = 'findings-list empty-state';
    findingsList.innerHTML = `
      <div class="empty-illustration">✅</div>
      <h4>No findings for this filter</h4>
      <p>Current filter me koi issue nahi mila.</p>
    `;
    return;
  }

  findingsList.className = 'findings-list';
  findingsList.innerHTML = filtered.map(item => `
    <article class="finding-card">
      <div class="finding-top">
        <div>
          <h4>${item.title}</h4>
          <div class="finding-meta">
            <span>${item.area}</span>
            <span>${item.owasp}</span>
          </div>
        </div>
        <span class="badge ${item.severity}">${item.severity.toUpperCase()}</span>
      </div>
      <div class="finding-body">
        <p><strong>Evidence:</strong> ${item.evidence}</p>
        <p><strong>Why it matters:</strong> ${item.why}</p>
        <p><strong>Solution:</strong> ${item.fix}</p>
      </div>
    </article>
  `).join('');
}

function renderHeaders(data) {
  const statusData = {
    csp: data.hasCsp,
    hsts: data.hasHttps,
    nosniff: data.hasHttps,
    frame: true,
    referrer: true
  };

  headerStatus.innerHTML = headerRules.map(rule => {
    const ok = statusData[rule.key];
    const stateClass = ok ? 'status-pass' : 'status-fail';
    const stateText = ok ? 'Configured / expected' : 'Review needed';
    return `
      <article>
        <div class="status-row">
          <div>
            <h4>${rule.name}</h4>
            <small>${rule.desc}</small>
          </div>
          <strong class="${stateClass}">${stateText}</strong>
        </div>
      </article>
    `;
  }).join('');
}

function renderChecklist(target, items) {
  target.innerHTML = items.map(item => {
    const ok = item.status === 'pass';
    const warn = item.status === 'warn';
    const stateClass = ok ? 'status-pass' : warn ? 'status-warn' : 'status-fail';
    return `
      <li>
        <div class="status-row">
          <div>
            <h4>${item.title}</h4>
            <small>${item.desc}</small>
          </div>
          <strong class="${stateClass}">${item.label}</strong>
        </div>
      </li>
    `;
  }).join('');
}

function buildChecklists(data) {
  renderChecklist(frontendChecklist, [
    { title: 'CSP policy', desc: 'Browser-level script restrictions', status: data.hasCsp ? 'pass' : 'fail', label: data.hasCsp ? 'Present' : 'Missing' },
    { title: 'Client validation support', desc: 'Forms aur user inputs present hone par server validation required', status: /form|upload|login|register/i.test(data.notes) ? 'warn' : 'pass', label: /form|upload|login|register/i.test(data.notes) ? 'Review' : 'Good' },
    { title: 'Dependency review', desc: 'Third-party JS/CSS libraries ko patch cycle me rakhiye', status: 'warn', label: 'Manual review' }
  ]);

  renderChecklist(backendChecklist, [
    { title: 'Authentication hardening', desc: 'Session/JWT/Basicauth secure implementation', status: data.authType !== 'none' ? 'warn' : 'pass', label: data.authType !== 'none' ? 'Verify' : 'Public' },
    { title: 'Rate limiting', desc: 'Brute-force aur abuse mitigation', status: data.hasRateLimit ? 'pass' : 'fail', label: data.hasRateLimit ? 'Enabled' : 'Missing' },
    { title: 'Authorization review', desc: 'Admin/API access control checks', status: /admin|panel|dashboard|api/i.test(data.notes) ? 'warn' : 'pass', label: /admin|panel|dashboard|api/i.test(data.notes) ? 'Required' : 'Basic' }
  ]);

  renderChecklist(infraChecklist, [
    { title: 'HTTPS / TLS', desc: 'Encrypted transport and redirect policy', status: data.hasHttps ? 'pass' : 'fail', label: data.hasHttps ? 'Enabled' : 'Missing' },
    { title: 'WAF layer', desc: 'Traffic filtering and managed protection', status: data.hasWaf ? 'pass' : 'warn', label: data.hasWaf ? 'Detected' : 'Optional' },
    { title: 'Service exposure', desc: 'Public ports and admin surfaces audit', status: 'warn', label: 'Audit needed' }
  ]);
}

function updateSummary(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach(item => counts[item.severity]++);
  document.getElementById('criticalCount').textContent = counts.critical;
  document.getElementById('highCount').textContent = counts.high;
  document.getElementById('mediumCount').textContent = counts.medium;
  document.getElementById('lowCount').textContent = counts.low;

  const score = Math.min(100, findings.reduce((sum, item) => sum + severityWeight(item.severity), 0));
  const safeScore = Math.max(0, 100 - score);
  document.getElementById('riskScore').textContent = safeScore;
  document.getElementById('riskLabel').textContent = safeScore > 79 ? 'Strong baseline' : safeScore > 59 ? 'Moderate risk' : 'High risk';

  document.getElementById('frontendBar').style.width = `${Math.max(18, 100 - ((counts.high + counts.critical) * 18 + counts.medium * 8))}%`;
  document.getElementById('backendBar').style.width = `${Math.max(16, 100 - ((counts.critical) * 22 + counts.high * 12))}%`;
  document.getElementById('infraBar').style.width = `${Math.max(12, 100 - ((counts.critical + counts.high) * 16))}%`;
}

function renderExecutiveSummary(data, findings) {
  const severe = findings.filter(item => item.severity === 'critical' || item.severity === 'high');
  executiveSummary.innerHTML = `
    <div class="finding-meta">
      <span class="report-tag">Target: ${data.targetUrl || 'N/A'}</span>
      <span class="report-tag">API: ${data.apiUrl || 'Not provided'}</span>
      <span class="report-tag">Auth: ${data.authType.toUpperCase()}</span>
    </div>
    <p>Audit result ke hisaab se sabse important focus areas ${severe.slice(0, 3).map(item => item.title).join(', ') || 'basic hardening'} hain. Sabse pehle critical aur high findings ko fix karke phir manual verification aur real backend scanning tools ke saath validation karna chahiye.</p>
    <ul>
      <li>OWASP mapping ke basis par access control, misconfiguration, injection aur authentication controls ko priority dijiye.</li>
      <li>Production use ke liye is demo ko real HTTP header fetcher, crawler, dependency scanner, and backend job runner ke saath extend kijiye.</li>
      <li>Unauthorized target scanning se bachiye; sirf owner-approved audits kariye.</li>
    </ul>
  `;
}

function collectFormData() {
  return {
    targetUrl: document.getElementById('targetUrl').value.trim(),
    apiUrl: document.getElementById('apiUrl').value.trim(),
    authType: document.getElementById('authType').value,
    notes: document.getElementById('notes').value.trim(),
    hasHttps: document.getElementById('hasHttps').checked,
    hasCsp: document.getElementById('hasCsp').checked,
    hasWaf: document.getElementById('hasWaf').checked,
    hasRateLimit: document.getElementById('hasRateLimit').checked,
    authorized: document.getElementById('authorized').checked
  };
}

function runAudit(data) {
  currentFindings = evaluate(data);
  renderFindings();
  renderHeaders(data);
  buildChecklists(data);
  updateSummary(currentFindings);
  renderExecutiveSummary(data, currentFindings);
}

form.addEventListener('submit', event => {
  event.preventDefault();
  const data = collectFormData();
  if (!data.authorized) {
    alert('Authorized scan confirmation required.');
    return;
  }
  runAudit(data);
});

demoButton.addEventListener('click', () => {
  document.getElementById('targetUrl').value = 'https://shop-demo.example.com';
  document.getElementById('apiUrl').value = 'https://api.shop-demo.example.com';
  document.getElementById('authType').value = 'jwt';
  document.getElementById('notes').value = 'React frontend, admin dashboard, login, search, file upload, Node API, database queries, public product pages';
  document.getElementById('hasHttps').checked = true;
  document.getElementById('hasCsp').checked = false;
  document.getElementById('hasWaf').checked = false;
  document.getElementById('hasRateLimit').checked = false;
  document.getElementById('authorized').checked = true;
  runAudit(collectFormData());
});

filters.forEach(button => {
  button.addEventListener('click', () => {
    filters.forEach(item => item.classList.remove('active'));
    button.classList.add('active');
    activeFilter = button.dataset.filter;
    renderFindings();
  });
});

themeToggle.addEventListener('click', () => {
  const html = document.documentElement;
  const current = html.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
  const next = current === 'dark' ? 'light' : 'dark';
  html.setAttribute('data-theme', next);
  themeToggle.setAttribute('aria-label', `Switch to ${current} mode`);
});

renderHeaders({ hasCsp: false, hasHttps: false });
buildChecklists({ authType: 'session', notes: '', hasRateLimit: false, hasHttps: false, hasWaf: false, hasCsp: false });