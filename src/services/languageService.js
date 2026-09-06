/**
 * languageService.js
 * Multi-Language Forensic Engine & Script Identification Service
 *
 * Engineered for AegisMail Digital Forensics. Detects primary and secondary
 * languages in email text, recognizes polyglot/mixed emails (e.g. English + Hindi),
 * identifies Unicode script families, detects Romanized Indic (Hinglish),
 * and provides forensic regional threat context.
 */

// Script Unicode blocks and character patterns
const SCRIPT_PATTERNS = [
  {
    language: "Telugu",
    code: "te",
    native: "తెలుగు",
    pattern: /[\u0C00-\u0C7F]/g,
    script: "Telugu",
    flag: "🇮🇳",
    region: "India (Telangana & Andhra Pradesh)",
  },
  {
    language: "Hindi",
    code: "hi",
    native: "हिन्दी",
    pattern: /[\u0900-\u097F]/g,
    script: "Devanagari",
    flag: "🇮🇳",
    region: "India (National / Northern & Central States)",
  },
  {
    language: "Tamil",
    code: "ta",
    native: "தமிழ்",
    pattern: /[\u0B80-\u0BFF]/g,
    script: "Tamil",
    flag: "🇮🇳",
    region: "India (Tamil Nadu & Puducherry) / Sri Lanka",
  },
  {
    language: "Kannada",
    code: "kn",
    native: "ಕನ್ನಡ",
    pattern: /[\u0C80-\u0CFF]/g,
    script: "Kannada",
    flag: "🇮🇳",
    region: "India (Karnataka)",
  },
  {
    language: "Malayalam",
    code: "ml",
    native: "മലയാളം",
    pattern: /[\u0D00-\u0D7F]/g,
    script: "Malayalam",
    flag: "🇮🇳",
    region: "India (Kerala & Lakshadweep)",
  },
  {
    language: "Bengali",
    code: "bn",
    native: "বাংলা",
    pattern: /[\u0980-\u09FF]/g,
    script: "Bengali",
    flag: "🇮🇳",
    region: "India (West Bengal, Tripura, Assam) / Bangladesh",
  },
  {
    language: "Gujarati",
    code: "gu",
    native: "ગુજરાતી",
    pattern: /[\u0A80-\u0AFF]/g,
    script: "Gujarati",
    flag: "🇮🇳",
    region: "India (Gujarat)",
  },
  {
    language: "Punjabi",
    code: "pa",
    native: "ਪੰਜਾਬੀ",
    pattern: /[\u0A00-\u0A7F]/g,
    script: "Gurmukhi",
    flag: "🇮🇳",
    region: "India (Punjab & Chandigarh)",
  },
  {
    language: "Odia",
    code: "or",
    native: "ଓଡ଼ିଆ",
    pattern: /[\u0B00-\u0B7F]/g,
    script: "Odia",
    flag: "🇮🇳",
    region: "India (Odisha)",
  },
  {
    language: "Urdu",
    code: "ur",
    native: "اردو",
    pattern: /[\u0600-\u06FF\u0750-\u077F\uFB50-\uFDFF\uFE70-\uFEFF]/g,
    script: "Arabic / Perso-Arabic",
    flag: "🇮🇳",
    region: "India / South Asia / Middle East",
  },
  {
    language: "Russian",
    code: "ru",
    native: "Русский",
    pattern: /[\u0400-\u04FF]/g,
    script: "Cyrillic",
    flag: "🇷🇺",
    region: "Eastern Europe / Central Asia",
  },
  {
    language: "Chinese",
    code: "zh",
    native: "中文",
    pattern: /[\u4E00-\u9FFF]/g,
    script: "Hanzi / CJK",
    flag: "🇨🇳",
    region: "East Asia (China / Taiwan)",
  },
  {
    language: "Japanese",
    code: "ja",
    native: "日本語",
    pattern: /[\u3040-\u309F\u30A0-\u30FF]/g,
    script: "Kana (Hiragana & Katakana)",
    flag: "🇯🇵",
    region: "Japan",
  },
  {
    language: "Korean",
    code: "ko",
    native: "한국어",
    pattern: /[\uAC00-\uD7AF\u1100-\u11FF]/g,
    script: "Hangul",
    flag: "🇰🇷",
    region: "Korea",
  },
  {
    language: "English",
    code: "en",
    native: "English",
    pattern: /[a-zA-Z]/g,
    script: "Latin",
    flag: "🌐",
    region: "International / Global Standard",
  },
];

// Common Hinglish / Romanized Indic trigger tokens in Latin text
const HINGLISH_TOKENS = [
  "aapka", "apka", "khata", "karein", "karo", "karna", "jaldi", "turant",
  "paisa", "paise", "rupaye", "bhejo", "adhikari", "sarkar", "namaskar",
  "dhanyawad", "suvidha", "aavedan", "shulk", "suchna", "panjikaran",
  "yojna", "aabhar", "kripya", "cheyandi", "chudandi", "pannunga",
];

// Specific Marathi lexical clues within Devanagari script
const MARATHI_MARKERS = [
  "आहे", "नाही", "करा", "झाले", "पुढील", "कृपया", "खाते", "शासकीय", "पाहिजे", "दिनांक", "बँक"
];

/**
 * Strips technical noise from text prior to linguistic analysis:
 * - URLs, web domains, and email addresses
 * - Base64 and hexadecimal payloads
 * - HTML and XML markup
 * - Standard RFC 822 header keys
 */
function sanitizeTextForAnalysis(raw = "") {
  if (!raw || typeof raw !== "string") return "";

  return raw
    // Strip HTML/XML tags
    .replace(/<[^>]+>/g, " ")
    // Strip URLs and links
    .replace(/https?:\/\/[^\s"'<>]+/gi, " ")
    // Strip email addresses
    .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, " ")
    // Strip hexadecimal and long base64 strings (>= 20 chars without spaces)
    .replace(/\b[A-Fa-f0-9]{20,}\b/g, " ")
    .replace(/\b[A-Za-z0-9+/=]{25,}\b/g, " ")
    // Strip common email header labels
    .replace(/\b(Message-ID|MIME-Version|Content-Type|Received|X-Mailer|DKIM-Signature):/gi, " ")
    // Normalize whitespace
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Counts characters matching a given regex pattern.
 */
function countCharacters(text, pattern) {
  const matches = text.match(pattern);
  return matches ? matches.length : 0;
}

/**
 * Checks for Marathi distinctive vocabulary when Devanagari script is predominant.
 */
function checkMarathiPresence(text) {
  if (!text) return false;
  let matches = 0;
  for (const marker of MARATHI_MARKERS) {
    if (text.includes(marker)) matches++;
  }
  return matches >= 2;
}

/**
 * Detects Hinglish (Hindi written in Roman / Latin script).
 */
function detectHinglish(cleanText, englishCount) {
  if (englishCount < 20) return false;
  const words = cleanText.toLowerCase().split(/[\s,.;:!?()"-]+/);
  let matched = 0;
  for (const token of HINGLISH_TOKENS) {
    if (words.includes(token)) matched++;
  }
  return matched >= 2;
}

/**
 * Main Multi-Language Detection Engine.
 * Analyzes subject and body text to identify primary language, polyglot distribution,
 * script families, and threat attribution context.
 *
 * @param {string} text - Raw subject + body text
 * @returns {object} Comprehensive multi-language forensic profile
 */
export function detectLanguage(text = "") {
  const cleanText = sanitizeTextForAnalysis(text);

  if (!cleanText || cleanText.length === 0) {
    return createEmptyProfile();
  }

  // Count characters per script/language pattern
  const rawCounts = SCRIPT_PATTERNS.map((item) => ({
    language: item.language,
    code: item.code,
    native: item.native,
    script: item.script,
    flag: item.flag,
    region: item.region,
    count: countCharacters(cleanText, item.pattern),
  })).filter((item) => item.count > 0);

  // If Devanagari script was detected, check if Marathi vocabulary is dominant
  const devanagariEntry = rawCounts.find((r) => r.language === "Hindi");
  if (devanagariEntry && devanagariEntry.count > 15) {
    if (checkMarathiPresence(cleanText)) {
      devanagariEntry.language = "Marathi";
      devanagariEntry.code = "mr";
      devanagariEntry.native = "मराठी";
      devanagariEntry.region = "India (Maharashtra & Goa)";
    }
  }

  // Calculate total relevant characters
  const totalCount = rawCounts.reduce((acc, curr) => acc + curr.count, 0);

  if (totalCount === 0) {
    return createEmptyProfile();
  }

  // Sort descending by character frequency
  rawCounts.sort((a, b) => b.count - a.count);

  // Calculate percentage and filter out trivial noise (< 2% or < 4 characters unless total is small)
  const languagesWithPercentages = rawCounts.map((lang) => {
    const percentage = Math.round((lang.count / totalCount) * 100);
    return {
      ...lang,
      percentage,
    };
  });

  const significantLanguages = languagesWithPercentages.filter(
    (l) => l.percentage >= 4 || l.count >= 6
  );

  const activeLanguages = significantLanguages.length > 0 ? significantLanguages : languagesWithPercentages;
  const primaryLang = activeLanguages[0] || {
    language: "Unknown",
    code: "und",
    native: "Unknown",
    script: "Undetermined",
    flag: "🌐",
    region: "Unspecified",
    count: 0,
    percentage: 100,
  };

  // Check for Romanized Indic / Hinglish
  const englishEntry = rawCounts.find((r) => r.language === "English");
  const isHinglish = englishEntry ? detectHinglish(cleanText, englishEntry.count) : false;

  // Determine if email is multilingual
  // An email is multilingual if there are 2 or more distinct languages with >= 8% share each
  const isMultilingual = activeLanguages.length > 1 && activeLanguages[1].percentage >= 8;

  // Build human-readable summary
  const summary = activeLanguages
    .slice(0, 3)
    .map((l) => `${l.language} (${l.percentage}%)`)
    .join(", ") + (isHinglish ? " [Hinglish Cues]" : "");

  // Calculate confidence score (based on character volume and margin)
  let confidence = 85;
  if (totalCount > 100) confidence += 8;
  if (primaryLang.percentage > 80) confidence += 6;
  if (primaryLang.percentage < 50) confidence -= 10;
  confidence = Math.min(Math.max(confidence, 60), 99);

  // Unique scripts detected
  const uniqueScripts = Array.from(new Set(activeLanguages.map((l) => l.script))).join(", ");

  // Forensic Regional Threat Context
  const threatContext = generateLinguisticThreatContext(primaryLang, isMultilingual, isHinglish, activeLanguages);

  // Return rich object with toString() for backward compatibility
  const profile = {
    primary: primaryLang.language,
    primaryCode: primaryLang.code,
    primaryNative: primaryLang.native,
    primaryScript: primaryLang.script,
    primaryFlag: primaryLang.flag,
    primaryRegion: primaryLang.region,
    confidence,
    isMultilingual,
    isHinglish,
    totalCharactersAnalyzed: totalCount,
    languages: activeLanguages,
    summary,
    script: uniqueScripts,
    threatContext,

    // Backward compatibility: when coerced to a string, returns primary language name
    toString() {
      return this.primary;
    },
    valueOf() {
      return this.primary;
    },
  };

  return profile;
}

/**
 * Returns fallback profile for empty or undetermined inputs.
 */
function createEmptyProfile() {
  const profile = {
    primary: "English",
    primaryCode: "en",
    primaryNative: "English",
    primaryScript: "Latin",
    primaryFlag: "🌐",
    primaryRegion: "International Standard",
    confidence: 70,
    isMultilingual: false,
    isHinglish: false,
    totalCharactersAnalyzed: 0,
    languages: [
      {
        language: "English",
        code: "en",
        native: "English",
        script: "Latin",
        flag: "🌐",
        region: "International",
        count: 0,
        percentage: 100,
      },
    ],
    summary: "English (Default)",
    script: "Latin",
    threatContext: "Standard English linguistic profile without regional script anomalies.",
    toString() {
      return this.primary;
    },
    valueOf() {
      return this.primary;
    },
  };
  return profile;
}

/**
 * Generates forensic insights explaining how the detected language/script
 * relates to cyber threat tactics (social engineering, evasion, regional targeting).
 */
function generateLinguisticThreatContext(primary, isMultilingual, isHinglish, languages) {
  if (isHinglish) {
    return "Adversary uses Romanized Hindi (Hinglish) phrasing. This tactic is prevalent in Indian banking and KYC fraud campaigns to evade English-only keyword filters while establishing authentic tone with victims.";
  }

  if (isMultilingual) {
    const nonEnglish = languages.filter((l) => l.language !== "English");
    if (nonEnglish.length > 0) {
      return `Polyglot message detected (${languages.map((l) => l.language).join(" + ")}). Threat actors frequently wrap regional vernacular lures in English corporate templates to bypass traditional secure email gateways.`;
    }
    return "Multilingual content detected with mixed character distribution across multiple language blocks.";
  }

  switch (primary.language) {
    case "Hindi":
    case "Marathi":
      return "Devanagari script detected. Frequently correlated with Indian government portal spoofing, income tax refund scams, or regional banking OTP coercion.";
    case "Telugu":
      return "Telugu script detected. Correlated with regional Indian public sector, welfare subsidy, and localized banking fraud vectors.";
    case "Tamil":
      return "Tamil script detected. Correlated with state-specific banking notices and localized recruitment/lottery deception campaigns.";
    case "Kannada":
      return "Kannada script detected. Typical in localized corporate vendor or IT hub impersonation targeting Karnataka entities.";
    case "Malayalam":
      return "Malayalam script detected. Often seen in diaspora remittance, Gulf employment scam lures, and localized cooperative bank fraud.";
    case "Bengali":
      return "Bengali script detected. Correlated with cross-border South Asian financial phishing and localized utility bill fraud.";
    case "Gujarati":
      return "Gujarati script detected. Prevalent in trade merchant, invoicing, and local commercial enterprise phishing.";
    case "Punjabi":
      return "Gurmukhi script detected. Prevalent in immigration, visa processing, and agricultural subsidy lures.";
    case "Urdu":
      return "Perso-Arabic script detected. Observed in cross-regional financial deception and community service spoofing.";
    case "Russian":
      return "Cyrillic script detected. Often associated with Eastern European bulletproof relays, PhaaS infrastructure, or ransomware coordination.";
    case "Chinese":
    case "Japanese":
    case "Korean":
      return "East Asian CJK script detected. Frequently utilized in supply chain, manufacturing purchase order fraud, and international vendor impersonation.";
    case "English":
    default:
      return "Standard Latin script. Uniform global corporate profile; linguistic threat evaluation proceeds via semantic urgency and BEC cues.";
  }
}