(function() {
  'use strict';

  // ── Detect platform ──
  const ua = navigator.userAgent;
  const isWin = /windows/i.test(ua);
  const isMac = /mac os/i.test(ua) && !/iphone|ipad/i.test(ua);
  const isLinux = /linux/i.test(ua) && !/android/i.test(ua);
  let os = 'linux';
  if (isWin) os = 'windows';
  else if (isMac) os = 'darwin';

  function updateDownloadLinks() {
    document.querySelectorAll('[data-os]').forEach(el => {
      el.style.display = el.dataset.os === os ? 'inline-flex' : 'none';
    });
  }

  // ── Terminal Animation ──
  function runTerminal() {
    const tty = document.getElementById('tty-body');
    if (!tty) return;

    const lines = [
      { type: 'prompt', text: 'trace --help' },
      { type: 'output', html: 'Trace - Multi-agent cybersecurity platform<br>Usage: trace [command]<br><br>Commands:<br>  serve         Start SIEM daemon<br>  investigate   Run security investigation<br>  case          Case management<br>  compliance    Compliance reporting (GDPR/HIPAA/PCI)<br>  server        Web dashboard<br>  hunt          Threat hunting' },
      { type: 'prompt', text: 'trace serve --siem --log-dir /var/log' },
      { type: 'output', html: '[siem] loaded 462 detection rules<br>[siem] loaded 1,567 decoders<br>[siem] engine started (poll: 5s)<br>[ALERT] sshd: authentication failed (severity: 5, mitre: T1110)<br>[ALERT] investigation <span class="tty-highlight">8cfb1e92</span> completed - playbook: ip-reputation' },
      { type: 'prompt', text: 'trace investigate 172.104.59.38 --playbook ip-reputation' },
      { type: 'output', html: 'Running playbook: ip-reputation<br>Investigation ID: <span class="tty-highlight">626f1bc8</span><br><br>Indicators:<br>  - <span class="tty-highlight">172.104.59.38</span> (abuseipdb.ip_reputation)<br>  - <span class="tty-highlight">172.104.59.38</span> (sift.vt_lookup)<br><br><span class="tty-success">Investigation completed. Confidence: 40%</span>' },
      { type: 'prompt', text: 'trace case list' },
      { type: 'output', html: 'ID        Title                                Status<br>──────── ─────────────────────────────────── ──────────<br>a24f4b4a  SIEM: Multiple failed login attempts   open<br>0c3afaa5  Phishing investigation Q3 2026        resolved<br>d7c6d716  C:\\Windows\\System32\\notepad.exe         completed' },
      { type: 'prompt', text: 'trace compliance report --framework pci_dss_v4.0' },
      { type: 'output', html: 'PCI DSS v4.0 Compliance Report<br>Score: <span class="tty-highlight">86%</span> (12/14 controls passed)<br><br>1.2.5  Network access controls     <span class="tty-success">✅ Pass</span><br>2.2.7  Insecure protocols           <span class="tty-warn">⚠️ Fail</span><br>6.2    Patch management            <span class="tty-success">✅ Pass</span><br>8.3.2  MFA for admin access        <span class="tty-success">✅ Pass</span>' },
    ];

    tty.innerHTML = '';
    let idx = 0;
    const SPEED = 45; // ms per char

    function typeLine(line) {
      if (idx >= lines.length) return;
      const data = lines[idx];
      const wrapper = document.createElement('div');
      wrapper.className = 'tty-line';

      if (data.type === 'prompt') {
        const prompt = document.createElement('span');
        prompt.className = 'tty-prompt';
        prompt.textContent = '$ ';
        wrapper.appendChild(prompt);
        const text = document.createElement('span');
        text.className = 'tty-cmd';
        text.textContent = '';
        wrapper.appendChild(text);
        tty.appendChild(wrapper);

        let ci = 0;
        function typeChar() {
          if (ci < data.text.length) {
            text.textContent += data.text[ci++];
            setTimeout(typeChar, SPEED);
          } else {
            tty.scrollTop = tty.scrollHeight;
            idx++;
            setTimeout(() => typeLine(lines[idx]), 400);
          }
        }
        typeChar();
      } else {
        wrapper.innerHTML = '<span class="tty-output">' + data.html + '</span>';
        tty.appendChild(wrapper);
        tty.scrollTop = tty.scrollHeight;
        idx++;
        setTimeout(() => typeLine(lines[idx]), 600);
      }
    }

    // Start after page load
    setTimeout(() => typeLine(lines[0]), 500);
  }

  // ── Scroll-triggered animations ──
  function observeElements() {
    const els = document.querySelectorAll('.feature-card, .stat-card, .demo-section .tty');
    if (!('IntersectionObserver' in window)) {
      els.forEach(el => el.style.opacity = '1');
      return;
    }
    const io = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.style.opacity = '1';
          entry.target.style.transform = 'translateY(0)';
          io.unobserve(entry.target);
        }
      });
    }, { threshold: 0.1 });
    els.forEach(el => {
      el.style.opacity = '0';
      el.style.transform = 'translateY(16px)';
      el.style.transition = 'opacity .5s ease, transform .5s ease';
      io.observe(el);
    });
  }

  // ── Copy command button ──
  function setupCopy() {
    document.querySelectorAll('.copy-btn').forEach(btn => {
      btn.addEventListener('click', function(e) {
        const cmd = this.dataset.cmd;
        if (!cmd) return;
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(cmd).then(() => {
            const orig = this.textContent;
            this.textContent = 'Copied!';
            setTimeout(() => { this.textContent = orig; }, 2000);
          }).catch(() => {});
        } else {
          // Fallback for older browsers
          const ta = document.createElement('textarea');
          ta.value = cmd;
          ta.style.position = 'fixed'; ta.style.opacity = '0';
          document.body.appendChild(ta);
          ta.select();
          try { document.execCommand('copy'); } catch(e) {}
          document.body.removeChild(ta);
        }
      });
    });
  }

  // ── TUI screen cycling ──
  function runTUI() {
    const screens = document.querySelectorAll('.tui-screen');
    const tabs = document.querySelectorAll('.tui-tab');
    if (!screens.length || !tabs.length) return;

    let current = 0;
    const INTERVAL = 4000;

    function showScreen(idx) {
      screens.forEach(s => s.classList.remove('active'));
      tabs.forEach(t => t.classList.remove('active'));
      screens[idx].classList.add('active');
      tabs[idx].classList.add('active');
    }

    function nextScreen() {
      current = (current + 1) % screens.length;
      showScreen(current);
    }

    // Start cycling after the terminal loads
    setTimeout(() => {
      showScreen(0);
      setInterval(nextScreen, INTERVAL);
    }, 2000);

    // Click to jump to a specific screen
    tabs.forEach((tab, i) => {
      tab.addEventListener('click', function() {
        current = i;
        showScreen(i);
      });
    });
  }

  // ── Radar Animation ──
  function runRadar() {
    const c = document.getElementById('radarCanvas');
    if (!c) return;
    const ctx = c.getContext('2d');
    let w, h, cx, cy, angle = 0;
    const blips = [];
    const threatNames = ['SSH Brute', 'DNS Tunnel', 'Malware', 'Port Scan', 'DDoS', 'CVE Exploit', 'Phishing', 'Ransomware'];
    for (let i = 0; i < 28; i++) {
      blips.push({
        dist: 0.1 + Math.random() * 0.55,
        a: Math.random() * Math.PI * 2,
        speed: 0.001 + Math.random() * 0.005,
        life: 0.3 + Math.random() * 0.7,
        size: 2 + Math.random() * 4,
        type: Math.random() < 0.3 ? 'threat' : Math.random() < 0.6 ? 'warn' : 'info',
        label: Math.random() < 0.15 ? threatNames[Math.floor(Math.random() * threatNames.length)] : null,
        pulse: Math.random() * Math.PI * 2,
      });
    }
    function resize() {
      w = c.width = c.offsetWidth;
      h = c.height = c.offsetHeight;
      cx = w * 0.72; cy = h * 0.5;
    }
    resize(); window.addEventListener('resize', resize);
    function draw() {
      ctx.clearRect(0, 0, w, h);
      const r = Math.min(w, h) * 0.42;
      // Radar rings
      for (let i = 1; i <= 5; i++) {
        const ringR = r * (i / 5);
        ctx.beginPath();
        ctx.arc(cx, cy, ringR, 0, Math.PI * 2);
        const alpha = i === 1 ? 0.08 + Math.sin(angle * 0.5) * 0.02
                    : 0.025 + (5 - i) * 0.006;
        ctx.strokeStyle = `rgba(90,160,250,${alpha})`;
        ctx.lineWidth = i === 1 ? 1 : 0.5;
        ctx.stroke();
        // Range label
        ctx.fillStyle = 'rgba(255,255,255,0.04)';
        ctx.font = '9px "JetBrains Mono", monospace';
        ctx.textAlign = 'center';
        ctx.fillText(`${i * 20}%`, cx + ringR + 10, cy + 3);
      }
      // Crosshairs
      ctx.strokeStyle = 'rgba(90,160,250,0.03)';
      ctx.lineWidth = 0.5;
      ctx.beginPath();
      ctx.moveTo(cx - r, cy); ctx.lineTo(cx + r, cy);
      ctx.moveTo(cx, cy - r); ctx.lineTo(cx, cy + r);
      ctx.stroke();
      // Azimuth ticks
      for (let deg = 0; deg < 360; deg += 15) {
        const rad = deg * Math.PI / 180;
        const inner = r * 0.96;
        const outer = r * (deg % 45 === 0 ? 1.0 : 0.98);
        ctx.beginPath();
        ctx.moveTo(cx + Math.cos(rad) * inner, cy + Math.sin(rad) * inner);
        ctx.lineTo(cx + Math.cos(rad) * outer, cy + Math.sin(rad) * outer);
        ctx.strokeStyle = deg % 45 === 0
          ? 'rgba(90,160,250,0.06)'
          : 'rgba(90,160,250,0.03)';
        ctx.lineWidth = deg % 45 === 0 ? 0.8 : 0.4;
        ctx.stroke();
      }
      // Sweep line
      angle += 0.006;
      const sx = cx + Math.cos(angle) * r;
      const sy = cy + Math.sin(angle) * r;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(sx, sy);
      ctx.strokeStyle = `rgba(90,160,250,${0.2 + Math.sin(angle * 0.5) * 0.05})`;
      ctx.lineWidth = 1.5;
      ctx.stroke();
      // Sweep glow trail
      const grdSweep = ctx.createRadialGradient(cx, cy, 0, cx, cy, r);
      grdSweep.addColorStop(0, `rgba(90,160,250,${0.06 + Math.sin(angle * 0.5) * 0.02})`);
      grdSweep.addColorStop(0.5, `rgba(90,160,250,${0.02 * Math.sin(angle * 0.3 + 1)})`);
      grdSweep.addColorStop(1, 'rgba(90,160,250,0)');
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, r, angle - 0.2, angle + 0.3);
      ctx.closePath();
      ctx.fillStyle = grdSweep;
      ctx.fill();
      // Center glow
      const centerGrd = ctx.createRadialGradient(cx, cy, 0, cx, cy, 20);
      centerGrd.addColorStop(0, 'rgba(90,160,250,0.15)');
      centerGrd.addColorStop(1, 'rgba(90,160,250,0)');
      ctx.fillStyle = centerGrd;
      ctx.beginPath();
      ctx.arc(cx, cy, 20, 0, Math.PI * 2);
      ctx.fill();
      ctx.beginPath();
      ctx.arc(cx, cy, 2.5, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(90,160,250,0.7)';
      ctx.fill();
      // Blips
      blips.forEach(b => {
        b.a += b.speed;
        b.life -= 0.0015;
        b.pulse += 0.03;
        if (b.life <= 0) {
          b.life = 0.3 + Math.random() * 0.7;
          b.dist = 0.1 + Math.random() * 0.55;
          b.a = Math.random() * Math.PI * 2;
          b.size = 2 + Math.random() * 4;
          b.type = Math.random() < 0.3 ? 'threat' : Math.random() < 0.6 ? 'warn' : 'info';
          b.label = Math.random() < 0.15 ? threatNames[Math.floor(Math.random() * threatNames.length)] : null;
        }
        const bx = cx + Math.cos(b.a) * r * b.dist;
        const by = cy + Math.sin(b.a) * r * b.dist;
        const alpha = b.life * 0.7;
        const color = b.type === 'threat' ? '230,80,80'
                    : b.type === 'warn' ? '240,179,75'
                    : '90,219,128';
        // Pulse ring
        const pulseR = 6 + Math.sin(b.pulse) * 4;
        ctx.beginPath();
        ctx.arc(bx, by, pulseR, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(${color},${alpha * 0.2})`;
        ctx.lineWidth = 1;
        ctx.stroke();
        // Glow
        const grdBlip = ctx.createRadialGradient(bx, by, 0, bx, by, 14);
        grdBlip.addColorStop(0, `rgba(${color},${alpha * 0.25})`);
        grdBlip.addColorStop(1, `rgba(${color},0)`);
        ctx.fillStyle = grdBlip;
        ctx.beginPath();
        ctx.arc(bx, by, 14, 0, Math.PI * 2);
        ctx.fill();
        // Dot
        ctx.beginPath();
        ctx.arc(bx, by, b.size, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${color},${alpha})`;
        ctx.fill();
        // Label
        if (b.label && b.life > 0.5) {
          ctx.fillStyle = `rgba(${color},${alpha * 0.6})`;
          ctx.font = '9px "JetBrains Mono", monospace';
          ctx.textAlign = 'center';
          ctx.fillText(b.label, bx, by - b.size - 6);
        }
      });
      requestAnimationFrame(draw);
    }
    draw();
  }

  // ── Tmux Section ──
  function runTmux() {
    const alertEl = document.getElementById('tmuxAlerts');
    const investEl = document.getElementById('tmuxInvest');
    const complianceEl = document.getElementById('tmuxCompliance');
    if (!alertEl && !investEl && !complianceEl) return;

    const alerts = [
      { text: '[ALERT] sshd brute-force 203.0.113.42', sev: 'high' },
      { text: '[INFO]  file integrity check passed', sev: 'info' },
      { text: '[WARN]  cert expired in 7d: *.trace.dev', sev: 'warn' },
      { text: '[ALERT] DNS tunnel detected: 10.0.0.88', sev: 'high' },
      { text: '[ALERT] CVE-2026-31337 exploit attempt', sev: 'critical' },
      { text: '[INFO]  log shipping rate: 1423 eps', sev: 'info' },
      { text: '[WARN]  unusual outbound: 45.33.32.156:8443', sev: 'warn' },
      { text: '[ALERT] mimikatz activity on WIN-BACKUP', sev: 'critical' },
    ];
    const invest = [
      'trace investigate 203.0.113.42',
      '  |- source: SIEM alert #8821',
      '  |- playbook: ip-reputation',
      '  |- vt_lookup: malicious (7/72)',
      '  |- abuseipdb: confirmed attacker',
      '  └─ confidence: 72%',
      '',
      'trace investigate CVE-2026-31337',
      '  └─ playbook: cve-lookup',
      '     |- CVSS: 9.4 (Critical)',
      '     |- affecting: nginx 1.24.x',
      '     └─ patches: available',
    ];
    const compliance = [
      'PCI DSS v4.0 - Score: 12/14',
      '  ├─ 1.2.5 Access control     OK',
      '  ├─ 2.2.7 Insecure proto     WARN',
      '  ├─ 6.2  Patch mgmt          OK',
      '  └─ 8.3.2 MFA                OK',
      '',
      'SOC 2 - Score: 21/24',
      '  ├─ CC6.1 Logical access     OK',
      '  └─ CC7.2 Monitoring         OK',
    ];

    function typeInto(el, lines) {
      if (!el) return;
      let lineIdx = 0, charIdx = 0;
      function tick() {
        if (lineIdx >= lines.length) return;
        const line = lines[lineIdx];
        if (charIdx === 0 && lineIdx > 0) el.innerHTML += '\n';
        if (charIdx < line.length) {
          el.innerHTML += line[charIdx];
          charIdx++;
          setTimeout(tick, 6 + Math.random() * 10);
        } else { lineIdx++; charIdx = 0; setTimeout(tick, 150); }
      }
      tick();
    }

    if (alertEl) {
      let alertIdx = 0;
      function appendAlert() {
        const a = alerts[alertIdx % alerts.length];
        const color = a.sev === 'critical' ? '#e85050'
                    : a.sev === 'high' ? '#f0b34b'
                    : a.sev === 'warn' ? '#5aa0fa'
                    : 'rgba(255,255,255,0.35)';
        const span = document.createElement('div');
        span.style.cssText = `opacity:0;transition:opacity .3s;color:${color}`;
        span.textContent = a.text;
        alertEl.appendChild(span);
        requestAnimationFrame(() => span.style.opacity = '1');
        alertIdx++;
        while (alertEl.children.length > 12) alertEl.removeChild(alertEl.firstChild);
        setTimeout(appendAlert, 1200 + Math.random() * 2000);
      }
      for (let i = 0; i < 6; i++) {
        const a = alerts[i % alerts.length];
        const color = a.sev === 'critical' ? '#e85050'
                    : a.sev === 'high' ? '#f0b34b'
                    : a.sev === 'warn' ? '#5aa0fa'
                    : 'rgba(255,255,255,0.35)';
        const span = document.createElement('div');
        span.style.cssText = `opacity:1;color:${color}`;
        span.textContent = a.text;
        alertEl.appendChild(span);
      }
      setTimeout(appendAlert, 2000);
    }
    typeInto(investEl, invest);
    typeInto(complianceEl, compliance);
  }

  // ── Flow Section ──
  function runFlow() {
    const c = document.getElementById('flowCanvas');
    if (!c) return;
    const wrap = document.getElementById('flowCanvasWrap');
    if (!wrap) return;
    const ctx = c.getContext('2d');

    const nodes = [
      { id: 'logs',    label: 'Log Sources',      x: 0.2, y: 0.5,  color: '#5adb80' },
      { id: 'siem',    label: 'SIEM Engine',       x: 0.4, y: 0.5,  color: '#5aa0fa' },
      { id: 'dispatch',label: 'Dispatch Agent',    x: 0.6, y: 0.28, color: '#f0b34b' },
      { id: 'archive', label: 'Archive Agent',     x: 0.6, y: 0.5,  color: '#c084fc' },
      { id: 'sift',    label: 'Sift Agent',        x: 0.6, y: 0.72, color: '#5adb80' },
      { id: 'response',label: 'Response Agent',    x: 0.8, y: 0.28, color: '#e85050' },
      { id: 'notify',  label: 'Notifier',          x: 0.8, y: 0.72, color: '#f0b34b' },
    ];
    const edges = [
      { from: 'logs', to: 'siem' },
      { from: 'siem', to: 'dispatch' },
      { from: 'siem', to: 'archive' },
      { from: 'siem', to: 'sift' },
      { from: 'dispatch', to: 'response' },
      { from: 'dispatch', to: 'notify' },
      { from: 'sift', to: 'dispatch' },
      { from: 'archive', to: 'dispatch' },
    ];

    let w, h, nodePositions = {}, flowPhase = 0;
    function resize() {
      const rect = wrap.getBoundingClientRect();
      w = c.width = rect.width;
      h = c.height = Math.max(360, w * 0.5);
      c.style.height = h + 'px';
      nodePositions = {};
      nodes.forEach(n => { nodePositions[n.id] = { x: n.x * w, y: n.y * h }; });
    }
    resize(); window.addEventListener('resize', resize);

    function draw() {
      ctx.clearRect(0, 0, w, h);
      // Grid dots
      ctx.fillStyle = 'rgba(255,255,255,0.025)';
      for (let x = 0; x < w; x += 36) {
        for (let y = 0; y < h; y += 36) {
          ctx.beginPath(); ctx.arc(x, y, 0.8, 0, Math.PI * 2); ctx.fill();
        }
      }
      // Edges
      edges.forEach((e, i) => {
        const from = nodePositions[e.from], to = nodePositions[e.to];
        if (!from || !to) return;
        const progress = (flowPhase + i * 0.14) % 1;
        const mx = from.x + (to.x - from.x) * progress;
        const my = from.y + (to.y - from.y) * progress;
        ctx.beginPath();
        ctx.moveTo(from.x, from.y);
        ctx.lineTo(to.x, to.y);
        ctx.strokeStyle = `rgba(255,255,255,${0.06 + Math.sin(flowPhase * 2 + i) * 0.015})`;
        ctx.lineWidth = 0.8;
        ctx.stroke();
        // Data packet
        ctx.beginPath(); ctx.arc(mx, my, 3, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(90,160,250,0.6)';
        ctx.fill();
        const grd = ctx.createRadialGradient(mx, my, 0, mx, my, 10);
        grd.addColorStop(0, 'rgba(90,160,250,0.15)');
        grd.addColorStop(1, 'rgba(90,160,250,0)');
        ctx.fillStyle = grd;
        ctx.beginPath(); ctx.arc(mx, my, 10, 0, Math.PI * 2);
        ctx.fill();
      });
      // Nodes
      nodes.forEach(n => {
        const p = nodePositions[n.id];
        if (!p) return;
        const grd = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, 32);
        grd.addColorStop(0, n.color + '15');
        grd.addColorStop(1, n.color + '00');
        ctx.fillStyle = grd;
        ctx.beginPath(); ctx.arc(p.x, p.y, 32, 0, Math.PI * 2);
        ctx.fill();
        ctx.beginPath(); ctx.arc(p.x, p.y, 8, 0, Math.PI * 2);
        ctx.fillStyle = n.color;
        ctx.fill();
        ctx.beginPath(); ctx.arc(p.x, p.y, 12, 0, Math.PI * 2);
        ctx.strokeStyle = n.color + '40';
        ctx.lineWidth = 0.8;
        ctx.stroke();
        ctx.fillStyle = 'rgba(255,255,255,0.65)';
        ctx.font = '11px "JetBrains Mono", monospace';
        ctx.textAlign = 'center';
        ctx.fillText(n.label, p.x, p.y + 26);
      });
      flowPhase += 0.005;
      requestAnimationFrame(draw);
    }
    draw();
  }

  // ── Init ──
  document.addEventListener('DOMContentLoaded', function() {
    updateDownloadLinks();
    runTerminal();
    runRadar();
    runTmux();
    runFlow();
    runTUI();
    observeElements();
    setupCopy();
  });
})();
