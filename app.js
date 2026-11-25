// crypt-keeper — password strength analyzer + generator
// 100% client-side. Passwords never leave the browser and nothing is stored.
// Pure logic is exported for tests; UI code is guarded for non-browser use.

export const COMMON_PASSWORDS = [
  "password", "123456", "123456789", "12345678", "12345", "123123", "111111",
  "1234567", "qwerty", "abc123", "password123", "password1", "1234567890",
  "12345678910", "iloveyou", "princess", "dragon", "monkey", "letmein",
  "football", "baseball", "sunshine", "master", "shadow", "superman",
  "batman", "trustno1", "welcome", "login", "admin", "passw0rd", "p@ssw0rd",
  "p@ssword", "starwars", "charlie", "aa123456", "donald", "freedom",
  "whatever", "qwerty123", "qwertyuiop", "1q2w3e4r", "1q2w3e", "zxcvbnm",
  "killer", "hockey", "george", "computer", "michelle", "jessica", "pepper",
  "11111111", "123321", "654321", "666666", "7777777", "88888888", "123qwe",
  "lovely", "hello", "secret", "internet", "samsung", "naruto", "lol123",
  "india123", "mumbai", "cricket", "vempire", "cryptkeeper",
];

const COMMON_SET = new Set(COMMON_PASSWORDS);

export const WORDLIST = [
  "amber", "anchor", "apex", "arcade", "arrow", "atlas", "aurora", "avenue",
  "bamboo", "banner", "basin", "beacon", "birch", "blizzard", "bloom", "bonfire",
  "breeze", "bridge", "brook", "cabin", "cactus", "canyon", "carbon", "cascade",
  "castle", "cedar", "chamber", "cipher", "citadel", "cliff", "cobalt", "comet",
  "compass", "copper", "coral", "cosmos", "crimson", "crystal", "dagger", "dawn",
  "delta", "desert", "diamond", "dune", "eagle", "echo", "ember", "emerald",
  "falcon", "fern", "fjord", "flame", "forest", "fortress", "frost", "galaxy",
  "garden", "glacier", "granite", "harbor", "hazel", "heron", "horizon", "hunter",
  "indigo", "iron", "island", "ivory", "jade", "jasper", "juniper", "karma",
  "lagoon", "lantern", "laurel", "lava", "lighthouse", "lilac", "lunar", "magnet",
  "mango", "maple", "marble", "meadow", "midnight", "mirror", "monsoon", "mosaic",
  "nebula", "nectar", "night", "nomad", "nova", "oak", "obsidian", "ocean",
  "onyx", "opal", "orbit", "orchid", "osprey", "otter", "owl", "panther",
  "pebble", "phoenix", "pine", "prism", "puma", "quartz", "quiver", "raven",
  "reef", "ridge", "river", "ruby", "sable", "saffron", "sage", "sapphire",
  "scarlet", "shadow", "sierra", "silver", "solar", "sparrow", "stone", "storm",
  "summit", "tide", "tiger", "topaz", "tundra", "twilight", "umbra", "valley",
  "velvet", "venom", "violet", "viper", "volcano", "walnut", "willow", "winter",
  "wolf", "zephyr", "zenith",
];

const KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"];
const SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "0123456789"];
const AMBIGUOUS = "Il1O0o";
const CHARSETS = {
  lowercase: "abcdefghijklmnopqrstuvwxyz",
  uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digits: "0123456789",
  symbols: "!@#$%^&*()-_=+[]{};:,.<>?/|~`",
};

function charsetSize(password) {
  let size = 0;
  if (/[a-z]/.test(password)) size += 26;
  if (/[A-Z]/.test(password)) size += 26;
  if (/[0-9]/.test(password)) size += 10;
  if (/[^A-Za-z0-9\s]/.test(password)) size += 32;
  if (/\s/.test(password)) size += 1;
  // Non-ASCII / other characters add a small extra pool.
  if (/[^\x00-\x7F]/.test(password)) size += 20;
  return size;
}

export function leetNormalize(value) {
  const map = { "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i", "+": "t" };
  return String(value).toLowerCase().split("").map((c) => map[c] || c).join("");
}

function stripTrailing(password) {
  return password.replace(/[^a-z]+$/i, "").toLowerCase();
}

export function isCommonPassword(password) {
  if (!password) return false;
  const lower = String(password).toLowerCase();
  if (COMMON_SET.has(lower)) return true;
  const leet = leetNormalize(password);
  if (COMMON_SET.has(leet)) return true;
  const stripped = stripTrailing(password);
  if (stripped && COMMON_SET.has(stripped)) return true;
  const strippedLeet = stripTrailing(leet);
  if (strippedLeet && COMMON_SET.has(strippedLeet)) return true;
  return false;
}

export function findSequences(password) {
  const lower = String(password).toLowerCase();
  const found = [];
  for (const seq of SEQUENCES) {
    const reversed = seq.split("").reverse().join("");
    for (const source of [seq, reversed]) {
      let run = "";
      let start = -1;
      for (let i = 0; i < lower.length; i++) {
        const idx = source.indexOf(lower[i]);
        if (idx === -1) { run = ""; start = -1; continue; }
        if (start === -1) { start = idx; run = lower[i]; continue; }
        if (idx === start + run.length) {
          run += lower[i];
          if (run.length >= 3) {
            // Record the maximal run once it ends; collect tentatively.
          }
        } else {
          if (run.length >= 3) found.push(run);
          start = idx; run = lower[i];
        }
      }
      if (run.length >= 3) found.push(run);
    }
  }
  return [...new Set(found)];
}

export function findKeyboardWalks(password) {
  const lower = String(password).toLowerCase();
  const found = [];
  for (const row of KEYBOARD_ROWS) {
    const reversed = row.split("").reverse().join("");
    for (const source of [row, reversed]) {
      for (let len = 3; len <= Math.min(source.length, lower.length); len++) {
        for (let i = 0; i + len <= source.length; i++) {
          const chunk = source.slice(i, i + len);
          if (lower.includes(chunk) && !found.some((f) => f.includes(chunk))) {
            found.push(chunk);
          }
        }
      }
    }
  }
  // Keep only maximal walks (drop sub-walks contained in a longer one).
  return found.filter((w, _, arr) => !arr.some((o) => o !== w && o.includes(w)));
}

export function findRepeats(password) {
  const found = [];
  const sameChar = String(password).match(/(.)\1{2,}/g);
  if (sameChar) found.push(...sameChar);
  // Repeated substring of length >= 2, e.g. abcabc
  const m = String(password).match(/(.{2,}?)\1+/);
  if (m && !found.includes(m[0])) found.push(m[0]);
  return found;
}

export function hasYearOrDatePattern(password) {
  const s = String(password);
  if (/(19|20)\d{2}/.test(s)) return true;
  if (/\b\d{1,2}[\/\-.]\d{1,2}([\/\-.]\d{2,4})?\b/.test(s)) return true;
  if (/\b(0?[1-9]|[12]\d|3[01])(0?[1-9]|1[0-2])(19|20)\d{2}\b/.test(s)) return true;
  return false;
}

export function estimateEntropy(password) {
  if (!password) return 0;
  const pw = String(password);
  const size = charsetSize(pw);
  if (size === 0) return 0;
  let entropy = pw.length * Math.log2(size);

  // Pattern penalties: predictable structure is cheaper to guess.
  const sequences = findSequences(pw);
  for (const s of sequences) entropy -= (s.length - 2) * 4;

  const walks = findKeyboardWalks(pw);
  for (const w of walks) entropy -= (w.length - 2) * 4;

  const repeats = findRepeats(pw);
  for (const r of repeats) entropy -= (r.length - 1) * 3;

  if (hasYearOrDatePattern(pw)) entropy -= 8;

  if (isCommonPassword(pw)) {
    // Common passwords live in tiny attacker dictionaries.
    entropy = Math.min(entropy, 12);
  }

  // Very short passwords cannot carry much entropy regardless of charset.
  entropy = Math.max(0, entropy);
  return Math.round(entropy * 10) / 10;
}

function formatCrackTime(seconds) {
  if (!isFinite(seconds)) return "effectively forever";
  if (seconds < 1) return "instantly";
  if (seconds < 60) return `${Math.round(seconds)} seconds`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
  if (seconds < 31557600) return `${Math.round(seconds / 86400)} days`;
  const years = seconds / 31557600;
  if (years < 100) return `${Math.round(years)} years`;
  if (years < 10000) return `${Math.round(years).toLocaleString("en-US")} years`;
  return "centuries (effectively forever)";
}

export function analyzePassword(password) {
  const pw = password == null ? "" : String(password);
  const findings = [];
  const add = (type, severity, message, fix) => findings.push({ type, severity, message, fix });

  const hasLower = /[a-z]/.test(pw);
  const hasUpper = /[A-Z]/.test(pw);
  const hasDigit = /[0-9]/.test(pw);
  const hasSymbol = /[^A-Za-z0-9\s]/.test(pw);
  const classes = [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length;

  const common = pw ? isCommonPassword(pw) : false;
  const sequences = pw ? findSequences(pw) : [];
  const walks = pw ? findKeyboardWalks(pw) : [];
  const repeats = pw ? findRepeats(pw) : [];
  const yearDate = pw ? hasYearOrDatePattern(pw) : false;

  if (!pw) {
    add("empty", "info", "Enter a password to analyze it.", "Type or paste a password above — it never leaves your browser.");
  } else {
    if (pw.length < 8) add("length", "critical", `Only ${pw.length} characters — too short.`, "Use at least 12 characters; 16+ is better.");
    else if (pw.length < 12) add("length", "warning", `${pw.length} characters — on the short side.`, "Aim for 12–16+ characters; length beats complexity.");
    else add("length", "ok", `${pw.length} characters — good length.`, "Keep it long; length is the strongest lever you have.");

    if (classes < 3) add("classes", "warning", `Uses only ${classes} character class${classes === 1 ? "" : "es"}.`, "Mix lowercase, uppercase, digits and symbols.");
    else add("classes", "ok", `Uses ${classes} character classes.`, "Good mix — keep it unpredictable.");

    if (common) add("common", "critical", "This is a common / dictionary password (including leetspeak variants).", "Never use common passwords — generate a random one below.");
    if (sequences.length) add("sequence", "warning", `Contains sequence(s): ${sequences.join(", ")}.`, "Avoid abc / 123 runs — they are guessed early.");
    if (walks.length) add("keyboard", "warning", `Contains keyboard walk(s): ${walks.join(", ")}.`, "Avoid qwerty-style keyboard patterns.");
    if (repeats.length) add("repeat", "warning", `Contains repeated pattern(s): ${repeats.join(", ")}.`, "Avoid repeated characters or repeated chunks.");
    if (yearDate) add("date", "warning", "Contains a year or date pattern.", "Avoid birth years and dates — attackers try them first.");
  }

  const entropy = estimateEntropy(pw);
  let score;
  if (!pw || common || entropy < 28) score = 0;
  else if (entropy < 40) score = 1;
  else if (entropy < 60) score = 2;
  else if (entropy < 80) score = 3;
  else score = 4;

  const labels = ["Very weak", "Weak", "Fair", "Strong", "Very strong"];
  const label = labels[score];
  const scorePercent = pw ? Math.max(4, Math.min(100, Math.round((entropy / 100) * 100))) : 0;

  // Offline fast-hash assumption: 10 billion guesses/second, average case = half the keyspace.
  const guessesPerSecond = 1e10;
  const crackTimeSeconds = pw ? Math.pow(2, Math.max(0, entropy - 1)) / guessesPerSecond : 0;

  return {
    password: pw,
    length: pw.length,
    entropy,
    score,
    label,
    scorePercent,
    isCommon: common,
    classes: { lowercase: hasLower, uppercase: hasUpper, digits: hasDigit, symbols: hasSymbol, count: classes },
    sequences,
    keyboardWalks: walks,
    repeats,
    hasYearOrDate: yearDate,
    crackTimeSeconds,
    crackTime: pw ? formatCrackTime(crackTimeSeconds) : "—",
    crackTimeAssumption: "Offline fast-hash attack at 10 billion guesses/second (average case).",
    findings,
  };
}

// Secure random integer in [0, max) using crypto.getRandomValues with rejection sampling.
export function randomInt(max) {
  if (!Number.isInteger(max) || max <= 0) throw new Error("max must be a positive integer");
  const cryptoObj = typeof crypto !== "undefined" ? crypto : null;
  if (!cryptoObj || typeof cryptoObj.getRandomValues !== "function") {
    throw new Error("crypto.getRandomValues is not available in this environment");
  }
  const limit = Math.floor(0xffffffff / max) * max;
  const buf = new Uint32Array(1);
  let value;
  do {
    cryptoObj.getRandomValues(buf);
    value = buf[0];
  } while (value >= limit);
  return value % max;
}

function secureShuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

export function generatePassword(options = {}) {
  const length = options.length ?? 16;
  const useLower = options.lowercase ?? true;
  const useUpper = options.uppercase ?? true;
  const useDigits = options.digits ?? true;
  const useSymbols = options.symbols ?? true;
  const excludeAmbiguous = options.excludeAmbiguous ?? false;

  if (!Number.isInteger(length) || length < 1) throw new Error("length must be a positive integer");

  const selected = [];
  if (useLower) selected.push(CHARSETS.lowercase);
  if (useUpper) selected.push(CHARSETS.uppercase);
  if (useDigits) selected.push(CHARSETS.digits);
  if (useSymbols) selected.push(CHARSETS.symbols);
  if (selected.length === 0) throw new Error("select at least one character class");

  const clean = (set) => (excludeAmbiguous ? set.split("").filter((c) => !AMBIGUOUS.includes(c)).join("") : set);
  const pools = selected.map(clean).filter((p) => p.length > 0);
  const all = pools.join("");

  const chars = [];
  // Guarantee at least one character from each selected class when length allows.
  if (length >= pools.length) {
    for (const pool of pools) chars.push(pool[randomInt(pool.length)]);
  }
  while (chars.length < length) chars.push(all[randomInt(all.length)]);
  return secureShuffle(chars).join("");
}

export function generatePassphrase(options = {}) {
  const wordCount = options.wordCount ?? options.words ?? options.count ?? 4;
  const separator = options.separator ?? "-";
  const capitalize = options.capitalize ?? false;
  const includeNumber = options.includeNumber ?? options.number ?? false;

  if (!Number.isInteger(wordCount) || wordCount < 1) throw new Error("wordCount must be a positive integer");

  const words = [];
  for (let i = 0; i < wordCount; i++) {
    let w = WORDLIST[randomInt(WORDLIST.length)];
    if (capitalize) w = w.charAt(0).toUpperCase() + w.slice(1);
    words.push(w);
  }
  let phrase = words.join(separator);
  if (includeNumber) phrase += String(randomInt(10));
  return phrase;
}

// ---------------------------------------------------------------------------
// UI (browser only)
// ---------------------------------------------------------------------------
if (typeof document !== "undefined") {
  const $ = (id) => document.getElementById(id);

  const init = () => {
    const pwInput = $("password-input");
    if (!pwInput) return;

    const toggleBtn = $("toggle-visibility");
    const meterFill = $("meter-fill");
    const meterLabel = $("meter-label");
    const entropyEl = $("entropy-value");
    const crackEl = $("crack-value");
    const findingsEl = $("findings-list");

    const renderAnalysis = () => {
      const result = analyzePassword(pwInput.value);
      if (meterFill) {
        meterFill.style.width = `${result.scorePercent}%`;
        meterFill.dataset.score = String(result.score);
      }
      if (meterLabel) meterLabel.textContent = pwInput.value ? `${result.label} · ${result.score}/4` : "—";
      if (entropyEl) entropyEl.textContent = pwInput.value ? `${result.entropy} bits` : "—";
      if (crackEl) crackEl.textContent = pwInput.value ? result.crackTime : "—";
      if (findingsEl) {
        findingsEl.innerHTML = "";
        for (const f of result.findings) {
          const li = document.createElement("li");
          li.className = `finding finding-${f.severity}`;
          const msg = document.createElement("span");
          msg.textContent = f.message;
          const fix = document.createElement("small");
          fix.textContent = f.fix;
          li.append(msg, fix);
          findingsEl.appendChild(li);
        }
      }
    };

    pwInput.addEventListener("input", renderAnalysis);
    renderAnalysis();

    if (toggleBtn) {
      toggleBtn.addEventListener("click", () => {
        const show = pwInput.type === "password";
        pwInput.type = show ? "text" : "password";
        toggleBtn.textContent = show ? "Hide" : "Show";
        toggleBtn.setAttribute("aria-pressed", String(show));
        pwInput.focus();
      });
    }

    // Generator
    const lengthRange = $("gen-length");
    const lengthValue = $("gen-length-value");
    const genOutput = $("gen-output");
    const genBtn = $("generate-btn");
    const copyBtn = $("copy-btn");
    const copyStatus = $("copy-status");
    const modePasswordBtn = $("mode-password");
    const modePassphraseBtn = $("mode-passphrase");
    const passwordOptions = $("password-options");
    const passphraseOptions = $("passphrase-options");
    let mode = "password";

    const setMode = (next) => {
      mode = next;
      if (passwordOptions) passwordOptions.hidden = next !== "password";
      if (passphraseOptions) passphraseOptions.hidden = next !== "passphrase";
      if (modePasswordBtn) modePasswordBtn.classList.toggle("active", next === "password");
      if (modePassphraseBtn) modePassphraseBtn.classList.toggle("active", next === "passphrase");
      generate();
    };

    const generate = () => {
      if (!genOutput) return;
      try {
        if (mode === "passphrase") {
          genOutput.value = generatePassphrase({
            wordCount: Number($("phrase-words")?.value ?? 4),
            separator: $("phrase-separator")?.value ?? "-",
            capitalize: Boolean($("phrase-capitalize")?.checked),
            includeNumber: Boolean($("phrase-number")?.checked),
          });
        } else {
          genOutput.value = generatePassword({
            length: Number(lengthRange?.value ?? 16),
            lowercase: Boolean($("opt-lowercase")?.checked),
            uppercase: Boolean($("opt-uppercase")?.checked),
            digits: Boolean($("opt-digits")?.checked),
            symbols: Boolean($("opt-symbols")?.checked),
            excludeAmbiguous: Boolean($("opt-ambiguous")?.checked),
          });
        }
        if (copyStatus) copyStatus.textContent = "";
      } catch (err) {
        genOutput.value = "";
        if (copyStatus) copyStatus.textContent = err.message;
      }
    };

    if (lengthRange && lengthValue) {
      lengthRange.addEventListener("input", () => { lengthValue.textContent = lengthRange.value; generate(); });
    }
    ["opt-lowercase", "opt-uppercase", "opt-digits", "opt-symbols", "opt-ambiguous",
     "phrase-words", "phrase-separator", "phrase-capitalize", "phrase-number"].forEach((id) => {
      const el = $(id);
      if (el) el.addEventListener("input", generate);
      if (el) el.addEventListener("change", generate);
    });
    if (genBtn) genBtn.addEventListener("click", generate);
    if (modePasswordBtn) modePasswordBtn.addEventListener("click", () => setMode("password"));
    if (modePassphraseBtn) modePassphraseBtn.addEventListener("click", () => setMode("passphrase"));

    if (copyBtn && genOutput) {
      copyBtn.addEventListener("click", async () => {
        if (!genOutput.value) return;
        try {
          await navigator.clipboard.writeText(genOutput.value);
          if (copyStatus) copyStatus.textContent = "Copied.";
        } catch {
          genOutput.select();
          document.execCommand("copy");
          if (copyStatus) copyStatus.textContent = "Copied.";
        }
      });
    }

    const useBtn = $("use-generated");
    if (useBtn && genOutput) {
      useBtn.addEventListener("click", () => { pwInput.value = genOutput.value; renderAnalysis(); pwInput.focus(); });
    }

    generate();
  };

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
}
