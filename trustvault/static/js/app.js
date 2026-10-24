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
