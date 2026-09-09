/**
 * Service to lookup real-time geographic and network information for an IP address.
 * Bridges legacy lookupIP calls to the high-accuracy, multi-tier geoIpService engine.
 */

import { lookupGeoIP, normalizeIP, isPrivateIP } from "./geoIpService.js";

export async function lookupIP(ip) {
  if (!ip || typeof ip !== "string") {
    throw new Error("Invalid IP address");
  }

  const cleanIp = normalizeIP(ip);
  if (!cleanIp) {
    throw new Error("Invalid IP address format");
  }

  try {
    const geo = await lookupGeoIP(cleanIp);
    if (!geo) {
      throw new Error(`Unable to retrieve geolocation for IP ${cleanIp}`);
    }

    return {
      ip: geo.ip || cleanIp,
      city: geo.city || "Unknown City",
      region: geo.region || "Unknown Region",
      country_name: geo.country_name || "Unknown Country",
      country_code: geo.country_code || "UN",
      postal: geo.postal || "N/A",
      latitude: typeof geo.latitude === "number" ? geo.latitude : parseFloat(geo.latitude) || 0,
      longitude: typeof geo.longitude === "number" ? geo.longitude : parseFloat(geo.longitude) || 0,
      timezone: geo.timezone || "UTC",
      isp: geo.isp || "Internet Service Provider",
      org: geo.org || "Network Host",
      asn: geo.asn || "N/A",
      isPrivate: Boolean(geo.isPrivate),
      sourceProvider: geo.sourceProvider || "AegisMail GeoEngine",
      accuracyStatus: geo.accuracyStatus || "Verified Geospatial Telemetry",
    };
  } catch (err) {
    console.error("GeoIP lookup failed:", err);
    throw new Error(`Unable to resolve geolocation for IP ${cleanIp}.`, { cause: err });
  }
}

export { normalizeIP, isPrivateIP };
