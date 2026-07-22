(function () {
  "use strict";

  var reduceMotion = window.matchMedia(
    "(prefers-reduced-motion: reduce)",
  ).matches;

  /* ---------------------------------------------------------
     Header state on scroll
  --------------------------------------------------------- */
  var header = document.getElementById("site-header");
  function updateHeader() {
    if (window.scrollY > 8) header.classList.add("scrolled");
    else header.classList.remove("scrolled");
  }
  updateHeader();
  window.addEventListener("scroll", updateHeader, { passive: true });

  /* ---------------------------------------------------------
     Mobile nav toggle
  --------------------------------------------------------- */
  var navToggle = document.getElementById("nav-toggle");
  var mainNav = document.getElementById("main-nav");
  if (navToggle && mainNav) {
    navToggle.addEventListener("click", function () {
      var open = mainNav.classList.toggle("open");
      navToggle.setAttribute("aria-expanded", open ? "true" : "false");
      if (open) {
        mainNav.style.display = "flex";
        mainNav.style.flexDirection = "column";
        mainNav.style.position = "absolute";
        mainNav.style.top = "66px";
        mainNav.style.left = "0";
        mainNav.style.right = "0";
        mainNav.style.padding = "18px 28px";
        mainNav.style.background = "rgba(10,12,16,0.98)";
        mainNav.style.borderBottom = "1px solid var(--border)";
        mainNav.style.gap = "16px";
      } else {
        mainNav.removeAttribute("style");
      }
    });

    mainNav.querySelectorAll("a").forEach(function (link) {
      link.addEventListener("click", function () {
        mainNav.classList.remove("open");
        mainNav.removeAttribute("style");
        navToggle.setAttribute("aria-expanded", "false");
      });
    });
  }

  /* ---------------------------------------------------------
     Scroll reveal
  --------------------------------------------------------- */
  var revealEls = document.querySelectorAll(".reveal");
  if ("IntersectionObserver" in window && !reduceMotion) {
    var io = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add("in-view");
            io.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.12, rootMargin: "0px 0px -40px 0px" },
    );
    revealEls.forEach(function (el) {
      io.observe(el);
    });
  } else {
    revealEls.forEach(function (el) {
      el.classList.add("in-view");
    });
  }

  /* ---------------------------------------------------------
     Animated stat count-up
  --------------------------------------------------------- */
  var statEls = document.querySelectorAll(".stat-num");
  function animateCount(el) {
    var target = parseInt(el.getAttribute("data-count"), 10) || 0;
    if (reduceMotion) {
      el.textContent = target;
      return;
    }
    var duration = 900;
    var start = null;
    function step(ts) {
      if (start === null) start = ts;
      var progress = Math.min((ts - start) / duration, 1);
      var eased = 1 - Math.pow(1 - progress, 3);
      el.textContent = Math.round(eased * target);
      if (progress < 1) requestAnimationFrame(step);
      else el.textContent = target;
    }
    requestAnimationFrame(step);
  }

  if ("IntersectionObserver" in window) {
    var statIo = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            animateCount(entry.target);
            statIo.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.4 },
    );
    statEls.forEach(function (el) {
      statIo.observe(el);
    });
  } else {
    statEls.forEach(animateCount);
  }

  /* ---------------------------------------------------------
     Copy terminal session to clipboard
  --------------------------------------------------------- */
  var copyBtn = document.getElementById("copy-btn");
  var terminalBody = document.getElementById("terminal-body");
  if (copyBtn && terminalBody) {
    copyBtn.addEventListener("click", function () {
      var text = terminalBody.innerText;
      var done = function () {
        var original = copyBtn.textContent;
        copyBtn.textContent = "Copied";
        setTimeout(function () {
          copyBtn.textContent = original;
        }, 1600);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard
          .writeText(text)
          .then(done)
          .catch(function () {
            copyBtn.textContent = "Press Ctrl+C";
            setTimeout(function () {
              copyBtn.textContent = "Copy";
            }, 1600);
          });
      }
    });
  }
})();
