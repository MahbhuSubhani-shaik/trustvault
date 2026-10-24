// Progressive enhancement only. Every page works without this file, and
// every check here is repeated on the server, which is the one that counts.
(function () {
  "use strict";

  // Busy state: <form data-busy="Signing in…"> disables its submit button and
  // swaps the label while the request runs, so a double click can't send twice.
  document.querySelectorAll("form[data-busy]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      if (form.dataset.sent) {
        event.preventDefault();
        return;
      }
      form.dataset.sent = "1";
      var button = event.submitter || form.querySelector("button[type=submit]");
      if (button) {
        button.dataset.label = button.textContent;
        button.textContent = form.dataset.busy;
        button.disabled = true;
        button.setAttribute("aria-busy", "true");
      }
    });
  });

  // Coming back with the browser's back button can restore a page with its
  // buttons still disabled. Put them back.
  window.addEventListener("pageshow", function (event) {
    if (!event.persisted) return;
    document.querySelectorAll("form[data-sent]").forEach(function (form) {
      delete form.dataset.sent;
      form.querySelectorAll("button[aria-busy]").forEach(function (button) {
        button.textContent = button.dataset.label;
        button.disabled = false;
        button.removeAttribute("aria-busy");
      });
    });
  });

  // The menu's "Search documents" link ends in #q: put the cursor in the box.
  function focusSearch() {
    var box = document.getElementById("q");
    if (location.hash === "#q" && box) box.focus();
  }
  focusSearch();
  window.addEventListener("hashchange", focusSearch);

  // Upload: show the chosen file, and stop a file over 10 MB before it is
  // sent (the server rejects it anyway; this just saves the wait).
  var fileInput = document.querySelector("input[type=file][data-max-bytes]");
  if (fileInput) {
    var status = document.getElementById("file-status");
    var zone = fileInput.closest(".dropzone");
    var defaultText = status.textContent;
    fileInput.addEventListener("change", function () {
      var file = fileInput.files[0];
      var tooBig = file && file.size > Number(fileInput.dataset.maxBytes);
      fileInput.setCustomValidity(tooBig ? "Files can be at most 10 MB." : "");
      status.classList.toggle("is-error", Boolean(tooBig));
      if (!file) status.textContent = defaultText;
      else if (tooBig) status.textContent = file.name + " is over 10 MB. Choose a smaller file.";
      else status.textContent = file.name + " · " + (file.size / 1024 / 1024).toFixed(2) + " MB · ready to upload";
    });
    ["dragenter", "dragover"].forEach(function (type) {
      fileInput.addEventListener(type, function () { zone.classList.add("is-dragging"); });
    });
    ["dragleave", "drop"].forEach(function (type) {
      fileInput.addEventListener(type, function () { zone.classList.remove("is-dragging"); });
    });
  }

  // Download: the server re-hashes the file before sending it. Show that
  // while it happens. A download doesn't leave the page, so reset after a bit.
  document.querySelectorAll("a[data-busy-link]").forEach(function (link) {
    var label = link.textContent;
    link.addEventListener("click", function () {
      link.textContent = link.dataset.busyLink;
      link.setAttribute("aria-busy", "true");
      setTimeout(function () {
        link.textContent = label;
        link.removeAttribute("aria-busy");
      }, 3000);
    });
  });

  // Register: tick the password rules as the user types.
  var password = document.getElementById("password");
  var rules = document.getElementById("password-rules");
  if (password && rules) {
    var checks = {
      length: function (v) { return v.length >= 12; },
      symbol: function (v) { return /[^A-Za-z]/.test(v); },
    };
    password.addEventListener("input", function () {
      rules.querySelectorAll("[data-rule]").forEach(function (item) {
        item.classList.toggle("is-met", checks[item.dataset.rule](password.value));
      });
    });
  }

  // Register: say "Passwords don't match" as soon as the confirm box is left.
  document.querySelectorAll("input[data-match]").forEach(function (confirm) {
    var original = document.getElementById(confirm.dataset.match);
    var message = document.getElementById(confirm.id + "-error");
    function check() {
      var mismatch = confirm.value !== "" && confirm.value !== original.value;
      confirm.setAttribute("aria-invalid", mismatch ? "true" : "false");
      if (mismatch) confirm.setAttribute("aria-describedby", message.id);
      if (message) message.hidden = !mismatch;
    }
    confirm.addEventListener("blur", check);
    original.addEventListener("input", function () { if (confirm.value) check(); });
  });
})();
