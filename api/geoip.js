// Vercel Serverless Function Handler for /api/geoip

const serverGeoCache = new Map();

function normalizeIP(ip) {
  if (!ip || typeof ip !== "string") return "";
  let clean = ip.trim().replace(/[[\]]/g, "");
  if (clean.includes(".") && clean.includes(":") && !clean.includes("::")) {
    clean = clean.split(":")[0];
  }
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(clean)) {
    const parts = clean.split(".").map((p) => {
      const num = parseInt(p, 10);
      return isNaN(num) ? 0 : Math.min(255, Math.max(0, num));
    });
    clean = parts.join(".");
  }
  return clean;
}

function isPrivateIpAddress(ip) {
  if (!ip || typeof ip !== "string") return true;
  const clean = normalizeIP(ip);
  if (clean.includes(":")) {
    const l = clean.toLowerCase();
    return l === "::1" || l === "::" || l.startsWith("fe80:") || l.startsWith("fc00:") || l.startsWith("fd00:");
  }
  const parts = clean.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) return true;
  const [a, b] = parts;
  if (a === 0 || a === 127 || a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a >= 224) return true;
  return false;
}

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  const rawIp = req.query.ip || "";
  const ip = normalizeIP(rawIp);

  if (!ip) {
    return res.status(400).json({ error: "A valid IP address query parameter is required." });
  }

  if (serverGeoCache.has(ip)) {
    return res.status(200).json(serverGeoCache.get(ip));
  }

  if (isPrivateIpAddress(ip)) {
    const privateResponse = {
      ip,
      city: "Localhost / Internal Subnet",
      region: "Private RFC 1918",
      country_name: "Internal Network",
      country_code: "LOCAL",
      country_flag: "🔒",
      postal: "N/A",
      latitude: 0,
      longitude: 0,
      timezone: "UTC",
      isp: "Local Area Network (RFC 1918)",
      org: "Private Infrastructure",
      asn: "N/A",
      isPrivate: true,
      accuracyStatus: "Non-Routable RFC 1918 Address",
    };
    serverGeoCache.set(ip, privateResponse);
    return res.status(200).json(privateResponse);
  }

  // Provider 1: ipwho.is
  try {
    const liveRes = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`);
    if (liveRes.ok) {
      const data = await liveRes.json();
      if (data.success && (data.latitude || data.longitude)) {
        const geoResult = {
          ip,
          city: data.city || "Unknown City",
          region: data.region || data.region_code || "Unknown Region",
          country_name: data.country || "Unknown Country",
          country_code: data.country_code || "UN",
          country_flag: data.flag?.emoji || "🌐",
          postal: data.postal || "N/A",
          latitude: typeof data.latitude === "number" ? data.latitude : parseFloat(data.latitude) || 0,
          longitude: typeof data.longitude === "number" ? data.longitude : parseFloat(data.longitude) || 0,
          timezone: data.timezone?.id ? `${data.timezone.id} (${data.timezone.utc || "UTC"})` : "UTC",
          isp: data.connection?.isp || "Internet Service Provider",
          org: data.connection?.org || data.connection?.domain || "Network Host",
          asn: data.connection?.asn ? `AS${data.connection.asn}` : "N/A",
          isPrivate: false,
          accuracyStatus: "High-Precision GPS (ipwho.is)",
        };
        serverGeoCache.set(ip, geoResult);
        return res.status(200).json(geoResult);
      }
    }
  } catch {
    // Proceed to fallback
  }

  // Provider 2: freeipapi.com
  try {
    const fallbackRes = await fetch(`https://freeipapi.com/api/json/${encodeURIComponent(ip)}`);
    if (fallbackRes.ok) {
      const data = await fallbackRes.json();
      if (data.countryName && (data.latitude || data.longitude)) {
        const geoResult = {
          ip,
          city: data.cityName || "Unknown City",
          region: data.regionName || "Unknown Region",
          country_name: data.countryName || "Unknown Country",
          country_code: data.countryCode || "UN",
          country_flag: "🌐",
          postal: data.zipCode || "N/A",
          latitude: typeof data.latitude === "number" ? data.latitude : parseFloat(data.latitude) || 0,
          longitude: typeof data.longitude === "number" ? data.longitude : parseFloat(data.longitude) || 0,
          timezone: data.timeZone || (Array.isArray(data.timeZones) ? data.timeZones[0] : "UTC"),
          isp: data.asnOrganization || "Public ISP",
          org: data.asnOrganization || `IPv${data.ipVersion || 4} Node`,
          asn: data.asn ? `AS${data.asn}` : "N/A",
          isPrivate: false,
          accuracyStatus: "Standard Precision (freeipapi)",
        };
        serverGeoCache.set(ip, geoResult);
        return res.status(200).json(geoResult);
      }
    }
  } catch {
    // Proceed to fallback
  }

  return res.status(502).json({ error: "Unable to resolve geolocation from upstream providers." });
}
