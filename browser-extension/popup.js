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

async function ready() {
  try {
    const response = await fetch(`${API}/health`);
    if (!response.ok) throw new Error();
    await token();
    status.textContent = "Connected. The helper never submits a form for you.";
  } catch {
    status.textContent = "DataSniper is not running. Open the desktop agent first.";
  }
}

document.getElementById("next").addEventListener("click", async () => {
  try {
    const t = await token();
    const response = await fetch(`${API}/api/next?token=${encodeURIComponent(t)}`);
    const data = await response.json();
    if (!data.task) {
      status.textContent = "You are caught up.";
      return;
    }
    await chrome.tabs.create({url: data.task.url});
  } catch (error) {
    status.textContent = error.message;
  }
});

document.getElementById("fill").addEventListener("click", async () => {
  try {
    const t = await token();
    const profileResponse = await fetch(`${API}/api/profile?token=${encodeURIComponent(t)}`);
    const profile = await profileResponse.json();
    const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
    await chrome.scripting.executeScript({
      target: {tabId: tab.id},
      func: (p) => {
        const candidates = {
          full_name: ["name", "full_name", "fullname"],
          email: ["email", "email_address"],
          phone: ["phone", "telephone", "mobile"],
          address: ["address", "street", "street_address"],
          city: ["city"],
          state: ["state", "province"],
          postal_code: ["zip", "zipcode", "postal", "postal_code"]
        };
        const inputs = [...document.querySelectorAll("input, textarea, select")];
        for (const [field, aliases] of Object.entries(candidates)) {
          const value = p[field];
          if (!value) continue;
          const element = inputs.find(el => {
            const text = `${el.name || ""} ${el.id || ""} ${el.placeholder || ""} ${el.getAttribute("aria-label") || ""}`.toLowerCase();
            return aliases.some(alias => text.includes(alias));
          });
          if (!element) continue;
          element.focus();
          element.value = value;
          element.dispatchEvent(new Event("input", {bubbles: true}));
          element.dispatchEvent(new Event("change", {bubbles: true}));
        }
        alert("DataSniper filled the fields it recognized. Review everything carefully; it did not submit the form.");
      },
      args: [profile]
    });
    window.close();
  } catch (error) {
    status.textContent = error.message || "Could not fill this page.";
  }
});

ready();
