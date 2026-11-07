"use strict";

const STATUSES = new Set(["red_flags", "no_red_flags", "check_failed"]);
const BUTTON_TEXT = "Check this message";

const form = document.getElementById("form");
const message = document.getElementById("message");
const channel = document.getElementById("channel");
const sender = document.getElementById("sender");
const submit = document.getElementById("submit");
const status = document.getElementById("status");
const error = document.getElementById("error");
const result = document.getElementById("result");
const reasonsBlock = document.getElementById("reasons-block");
const reasons = document.getElementById("reasons");
let currentCheck = null;

function showError(text) {
  error.textContent = text;
  error.hidden = false;
  message.focus();
}

function clearOutput() {
  error.hidden = true;
  result.hidden = true;
  reasonsBlock.hidden = true;
  reasons.replaceChildren();
}

function showResult(data) {
  result.className = "result " + data.status;
  document.getElementById("result-text").textContent = data.text;
  reasons.replaceChildren(
    ...data.reasons.map((reason) => {
      const item = document.createElement("li");
      item.textContent = reason;
      return item;
    }),
  );
  reasonsBlock.hidden = data.reasons.length === 0;
  result.hidden = false;
  result.focus();
}

function resetButton() {
  status.textContent = "";
  submit.removeAttribute("aria-disabled");
  submit.textContent = BUTTON_TEXT;
}

// A result must only ever appear beside the message it was checked for, so any
// change to the message cancels a check in progress and clears the last result.
function discardCheck() {
  if (currentCheck) {
    currentCheck.abort();
    currentCheck = null;
    resetButton();
  }
  clearOutput();
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (currentCheck) return;
  const check = new AbortController();
  currentCheck = check;
  clearOutput();
  submit.setAttribute("aria-disabled", "true");
  submit.textContent = "Checking…";
  status.textContent = "Checking your message. This can take a minute.";
  try {
    const response = await fetch("/api/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: message.value, channel: channel.value, sender: sender.value }),
      signal: check.signal,
    });
    const data = await response.json();
    if (check !== currentCheck) return;
    if (response.ok && STATUSES.has(data.status)) {
      showResult(data);
    } else {
      showError(data.error || "We couldn't check this message. Please try again. Until then, don't click links or call numbers in the message.");
    }
  } catch {
    if (check !== currentCheck) return;
    showError("We couldn't reach the checker. Please try again. Until then, don't click links or call numbers in the message.");
  } finally {
    if (check === currentCheck) {
      currentCheck = null;
      resetButton();
    }
  }
});

for (const field of [message, channel, sender]) {
  field.addEventListener("input", discardCheck);
}

document.getElementById("clear").addEventListener("click", () => {
  message.value = "";
  channel.value = "";
  sender.value = "";
  discardCheck();
  message.focus();
});
