"use strict";

const TITLES = {
  red_flags: "Red flags found",
  no_red_flags: "No red flags found",
  check_failed: "We couldn't check this message",
};

const form = document.getElementById("form");
const message = document.getElementById("message");
const submit = document.getElementById("submit");
const error = document.getElementById("error");
const result = document.getElementById("result");
const reasonsBlock = document.getElementById("reasons-block");
const reasons = document.getElementById("reasons");

function showError(text) {
  error.textContent = text;
  error.hidden = false;
}

function clearOutput() {
  error.hidden = true;
  result.hidden = true;
  reasonsBlock.hidden = true;
  reasons.replaceChildren();
}

function showResult(data) {
  result.className = "result " + data.status;
  document.getElementById("result-title").textContent = TITLES[data.status];
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

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearOutput();
  submit.disabled = true;
  submit.textContent = "Checking…";
  try {
    const response = await fetch("/api/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: message.value }),
    });
    const data = await response.json();
    if (response.ok && data.status in TITLES) {
      showResult(data);
    } else {
      showError(data.error || "We couldn't check this message. Please try again.");
    }
  } catch {
    showError("We couldn't reach the checker. Please try again. Until then, don't click links or call numbers in the message.");
  } finally {
    submit.disabled = false;
    submit.textContent = "Check this message";
  }
});

document.getElementById("clear").addEventListener("click", () => {
  message.value = "";
  clearOutput();
  message.focus();
});
