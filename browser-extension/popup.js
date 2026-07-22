const API = "http://127.0.0.1:8787";
const status = document.getElementById("status");

async function token() {
  const saved = await chrome.storage.local.get("token");
  if (saved.token) return saved.token;
  const response = await fetch(`${API}/pair`, {method: "POST"});
  if (!response.ok) throw new Error("Start DataSniper on this computer first.");
  const data = await response.json();
  await chrome.storage.local.set({token: data.token});
  return data.token;
}

async function context() {
  const t = await token();
  const [profileResponse, taskResponse] = await Promise.all([
    fetch(`${API}/api/profile?token=${encodeURIComponent(t)}`),
    fetch(`${API}/api/next?token=${encodeURIComponent(t)}`)
  ]);
  if (!profileResponse.ok) throw new Error("Complete DataSniper onboarding first.");
  const profile = await profileResponse.json();
  const {task} = await taskResponse.json();
  if (!task) throw new Error("There is no task ready for automation.");
  return {t, profile, task};
}

async function record(t, taskId, result) {
  const response = await fetch(`${API}/api/task/${taskId}/transaction?token=${encodeURIComponent(t)}`, {
    method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(result)
  });
  if (!response.ok) throw new Error("The page ran, but DataSniper could not record the transaction.");
}

async function runPage(shouldSubmit) {
  const {t, profile, task} = await context();
  const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
  const expectedHost = new URL(task.url).hostname.replace(/^www\./, "");
  const actualHost = new URL(tab.url).hostname.replace(/^www\./, "");
  if (!(actualHost === expectedHost || actualHost.endsWith(`.${expectedHost}`))) {
    throw new Error(`Open ${task.broker_name}'s official task page first.`);
  }
  const [{result}] = await chrome.scripting.executeScript({
    target: {tabId: tab.id},
    func: (p, submit) => {
      const visible = (document.body?.innerText || "").toLowerCase();
      const normalized = value => String(value || "").trim().toLowerCase();
      const evidence = [p.full_name, p.address, p.city, p.email, p.phone]
        .map(normalized).filter(value => value.length >= 4);
      const hits = evidence.filter(value => visible.includes(value)).length;
      const matchScore = evidence.length ? Math.round((hits / evidence.length) * 100) : null;
      const controls = [...document.querySelectorAll("input, textarea, select")]
        .filter(el => !el.disabled && el.type !== "hidden");
      const candidates = {
        full_name: ["full name", "fullname", "name"], email: ["email"],
        phone: ["phone", "telephone", "mobile"], address: ["street", "address"],
        city: ["city"], state: ["state", "province"],
        postal_code: ["postal", "zipcode", "zip code", "zip"]
      };
      let filled = 0;
      for (const [field, aliases] of Object.entries(candidates)) {
        if (!p[field]) continue;
        const element = controls.find(el => {
          const label = el.labels ? [...el.labels].map(item => item.innerText).join(" ") : "";
          const text = `${el.name || ""} ${el.id || ""} ${el.placeholder || ""} ${el.getAttribute("aria-label") || ""} ${label}`.toLowerCase();
          return aliases.some(alias => text.includes(alias));
        });
        if (!element || ["checkbox", "radio", "submit", "button", "file"].includes(element.type)) continue;
        element.focus();
        element.value = p[field];
        element.dispatchEvent(new Event("input", {bubbles: true}));
        element.dispatchEvent(new Event("change", {bubbles: true}));
        filled += 1;
      }
      const captcha = Boolean(document.querySelector(
        'iframe[src*="captcha" i], .g-recaptcha, [class*="captcha" i], [id*="captcha" i], [data-sitekey]'
      )) || /verify you are human|complete the captcha|security challenge/.test(visible);
      const unresolved = controls.filter(el => el.required && !el.value && !el.checked);
      const consent = controls.filter(el => ["checkbox", "radio"].includes(el.type) && el.required && !el.checked);
      if (captcha) return {stage: "captcha", outcome: "blocked", page_url: location.href,
        match_score: matchScore, detail: `Filled ${filled} field(s); CAPTCHA requires you to complete it in this tab.`, automated: true};
      if (unresolved.length || consent.length) return {stage: "prefill", outcome: "needs_review", page_url: location.href,
        match_score: matchScore, detail: `Filled ${filled} field(s); ${unresolved.length} required field(s) or consent choice(s) need review.`, automated: true};
      if (!submit) return {stage: "prefill", outcome: "filled", page_url: location.href,
        match_score: matchScore, detail: `Filled ${filled} recognized field(s); submission was not requested.`, automated: true};
      const form = controls.find(el => el.form)?.form || document.querySelector("form");
      const submitter = form?.querySelector('button[type="submit"],input[type="submit"],button:not([type])');
      if (!form || !submitter) return {stage: "submission", outcome: "needs_review", page_url: location.href,
        match_score: matchScore, detail: `Filled ${filled} field(s), but no unambiguous submit control was found.`, automated: true};
      if (!form.checkValidity()) {
        form.reportValidity();
        return {stage: "submission", outcome: "needs_review", page_url: location.href,
          match_score: matchScore, detail: "The form failed browser validation and was left open for review.", automated: true};
      }
      form.requestSubmit(submitter);
      return {stage: "submission", outcome: "submitted", page_url: location.href,
        match_score: matchScore, detail: `Filled ${filled} field(s) and invoked the official form submission.`, automated: true};
    },
    args: [profile, shouldSubmit]
  });
  await record(t, task.id, result);
  status.textContent = result.outcome === "blocked" ? "CAPTCHA detected. Solve it in the page, then run again." : result.detail;
}

document.getElementById("next").addEventListener("click", async () => {
  try {
    const {task} = await context();
    await chrome.tabs.create({url: task.url});
  } catch (error) { status.textContent = error.message; }
});
document.getElementById("fill").addEventListener("click", () => runPage(false).catch(error => {status.textContent = error.message;}));
document.getElementById("automate").addEventListener("click", () => runPage(true).catch(error => {status.textContent = error.message;}));

(async () => {
  try { await fetch(`${API}/health`); await token(); status.textContent = "Connected. Ready to automate the next official request."; }
  catch { status.textContent = "DataSniper is not running. Open the local agent first."; }
})();
