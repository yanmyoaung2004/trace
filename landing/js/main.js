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
      { type: 'output', html: 'Trace — Multi-agent cybersecurity platform<br>Usage: trace [command]<br><br>Commands:<br>  serve         Start SIEM daemon<br>  investigate   Run security investigation<br>  case          Case management<br>  compliance    Compliance reporting (GDPR/HIPAA/PCI)<br>  server        Web dashboard<br>  hunt          Threat hunting' },
      { type: 'prompt', text: 'trace serve --siem --log-dir /var/log' },
      { type: 'output', html: '[siem] loaded 462 detection rules<br>[siem] loaded 1,567 decoders<br>[siem] engine started (poll: 5s)<br>[ALERT] sshd: authentication failed (severity: 5, mitre: T1110)<br>[ALERT] investigation <span class="tty-highlight">8cfb1e92</span> completed — playbook: ip-reputation' },
      { type: 'prompt', text: 'trace investigate 172.104.59.38 --playbook ip-reputation' },
      { type: 'output', html: 'Running playbook: ip-reputation<br>Investigation ID: <span class="tty-highlight">626f1bc8</span><br><br>Indicators:<br>  - <span class="tty-highlight">172.104.59.38</span> (abuseipdb.ip_reputation)<br>  - <span class="tty-highlight">172.104.59.38</span> (sift.vt_lookup)<br><br><span class="tty-success">Investigation completed. Confidence: 40%</span>' },
      { type: 'prompt', text: 'trace case list' },
      { type: 'output', html: 'ID        Title                                Status<br>──────── ─────────────────────────────────── ──────────<br>a24f4b4a  SIEM: Multiple failed login attempts   open<br>0c3afaa5  Phishing investigation — Q3 2026       resolved<br>d7c6d716  C:\\Windows\\System32\\notepad.exe         completed' },
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

  // ── Init ──
  document.addEventListener('DOMContentLoaded', function() {
    updateDownloadLinks();
    runTerminal();
    runTUI();
    observeElements();
    setupCopy();
  });
})();
