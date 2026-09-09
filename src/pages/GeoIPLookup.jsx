import { useState, useEffect, useCallback, useMemo } from "react";
import {
  Globe2,
  Search,
  MapPin,
  Radio,
  Compass,
  ExternalLink,
  ShieldCheck,
  Activity,
} from "lucide-react";
import ModulePage from "../components/ModulePage";
import Globe3D from "../components/Globe3D";
import { lookupGeoIP, normalizeIP } from "../services/geoIpService";

export default function GeoIPLookup({ analysis }) {
  const extractedIPs = useMemo(
    () => (analysis?.extractedIPs || []).map((ip) => normalizeIP(ip)).filter(Boolean),
    [analysis?.extractedIPs]
  );
  const [ipInput, setIpInput] = useState(extractedIPs[0] || "");
  const [loading, setLoading] = useState(false);
  const [geoData, setGeoData] = useState(null);
  const [error, setError] = useState(null);
  const [recentLookups, setRecentLookups] = useState([]);

  const handleLookup = useCallback(
    async (ipToQuery) => {
      const rawIp = (ipToQuery || ipInput || extractedIPs[0] || "").trim();
      const targetIp = normalizeIP(rawIp);
      if (!targetIp) {
        setError("Please enter a valid IPv4 or IPv6 address.");
        return;
      }

      setLoading(true);
      setError(null);

      try {
        const data = await lookupGeoIP(targetIp);
        if (data) {
          setGeoData(data);
          setRecentLookups((prev) => {
            const filtered = prev.filter((item) => item.ip !== data.ip);
            return [data, ...filtered].slice(0, 5);
          });
        } else {
          setError("Unable to resolve GeoIP location for this address. Please verify the IP.");
        }
      } catch (err) {
        console.error("GeoIP lookup failed:", err);
        setError("Unable to resolve GeoIP location for this address. Please check your internet connection.");
      } finally {
        setLoading(false);
      }
    },
    [ipInput, extractedIPs]
  );

  useEffect(() => {
    let isMounted = true;
    if (extractedIPs.length > 0) {
      const initialIp = extractedIPs[0];
      setIpInput(initialIp);
      lookupGeoIP(initialIp)
        .then((data) => {
          if (isMounted && data) {
            setGeoData(data);
            setRecentLookups((prev) => {
              const filtered = prev.filter((item) => item.ip !== data.ip);
              return [data, ...filtered].slice(0, 5);
            });
          }
        })
        .catch((err) => {
          console.warn("Initial IP lookup failed:", err);
        });
    }
    return () => {
      isMounted = false;
    };
  }, [analysis?.id, extractedIPs]);

  return (
    <ModulePage
      title="3D GeoIP Radar & Network Intelligence"
      subtitle="Interactive 3D geospatial mapping, hop routing trace, and autonomous system numbers (ASN) telemetry."
      icon={<Globe2 size={28} />}
    >
      <div className="main-grid" style={{ marginBottom: "24px" }}>
        {/* LOOKUP INPUT PANEL */}
        <div className="panel" style={{ gridColumn: "span 2" }}>
          <h3>IP Investigation & Routing Trace</h3>
          <p>Enter an IPv4/IPv6 address or select an IP extracted from the analyzed email headers.</p>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleLookup();
            }}
            style={{ display: "flex", gap: "10px", marginTop: "16px" }}
          >
            <input
              type="text"
              placeholder="e.g. 193.35.16.214 or 8.8.8.8"
              value={ipInput}
              onChange={(e) => setIpInput(e.target.value)}
              style={{
                flex: 1,
                padding: "12px 14px",
                borderRadius: "8px",
                border: "1px solid #d9e0ea",
                fontSize: "14px",
              }}
            />

            <button className="primary-button" type="submit" disabled={loading}>
              <Search size={16} />
              {loading ? "Resolving..." : "Lookup IP"}
            </button>
          </form>

          {error && (
            <div
              style={{
                marginTop: "12px",
                color: "#dc2626",
                background: "#fef2f2",
                border: "1px solid #fecaca",
                padding: "10px 14px",
                borderRadius: "6px",
                fontSize: "13px",
              }}
            >
              {error}
            </div>
          )}

          {/* EXTRACTED IPS FROM EMAIL */}
          {extractedIPs.length > 0 && (
            <div style={{ marginTop: "20px" }}>
              <span style={{ fontSize: "12px", fontWeight: "700", color: "#64748b", textTransform: "uppercase" }}>
                IPs Extracted from Analyzed Email:
              </span>
              <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", marginTop: "8px" }}>
                {extractedIPs.map((ip, i) => (
                  <button
                    key={i}
                    className="secondary-button"
                    style={{ padding: "6px 12px", fontSize: "12px", fontFamily: "monospace" }}
                    onClick={() => {
                      setIpInput(ip);
                      handleLookup(ip);
                    }}
                  >
                    <Radio size={12} /> {ip}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* RECENT LOOKUPS */}
        <div className="panel">
          <h3 style={{ fontSize: "16px" }}>Recent Queries</h3>
          {recentLookups.length === 0 ? (
            <p style={{ marginTop: "12px" }}>No recent investigations.</p>
          ) : (
            <div style={{ marginTop: "12px", display: "grid", gap: "8px" }}>
              {recentLookups.map((item, idx) => (
                <div
                  key={idx}
                  onClick={() => {
                    setIpInput(item.ip);
                    setGeoData(item);
                  }}
                  style={{
                    padding: "8px 12px",
                    borderRadius: "6px",
                    background: "#f8fafc",
                    border: "1px solid #e2e8f0",
                    cursor: "pointer",
                    display: "flex",
                    justifyContent: "space-between",
                    fontSize: "12px",
                  }}
                >
                  <strong style={{ fontFamily: "monospace" }}>{item.ip}</strong>
                  <span style={{ color: "#64748b" }}>
                    {item.city}, {item.country_code}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* 3D WORLD GLOBE SECTION */}
      <div className="panel" style={{ padding: "20px", marginBottom: "24px" }}>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: "16px",
            flexWrap: "wrap",
            gap: "10px",
          }}
        >
          <div>
            <h3 style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <Compass size={20} color="#2563eb" /> 3D Earth Geospatial Radar (Cesium / WebGL)
            </h3>
            <p style={{ margin: "2px 0 0" }}>
              Interactive spherical visualization plotting resolved physical coordinates in 3D space.
            </p>
          </div>

          {geoData && !geoData.isPrivate && (
            <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
              <span
                style={{
                  padding: "6px 14px",
                  borderRadius: "20px",
                  background: "#0d2741",
                  border: "1px solid #38bdf8",
                  color: "#38bdf8",
                  fontSize: "12px",
                  fontWeight: "700",
                  fontFamily: "monospace",
                }}
              >
                TARGET: {geoData.ip} ({typeof geoData.latitude === "number" ? geoData.latitude.toFixed(4) : geoData.latitude}°,{" "}
                {typeof geoData.longitude === "number" ? geoData.longitude.toFixed(4) : geoData.longitude}°)
              </span>

              {geoData.accuracyStatus && (
                <span
                  style={{
                    padding: "4px 10px",
                    borderRadius: "20px",
                    background: "#f0fdf4",
                    border: "1px solid #86efac",
                    color: "#166534",
                    fontSize: "11px",
                    fontWeight: "600",
                  }}
                >
                  {geoData.accuracyStatus}
                </span>
              )}
            </div>
          )}
        </div>

        {/* 3D GLOBE CANVAS COMPONENT */}
        <Globe3D geoData={geoData} />
      </div>

      {/* GEOIP DETAILS RESULT */}
      {geoData && (
        <div className="panel">
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: "16px",
              flexWrap: "wrap",
              gap: "8px",
            }}
          >
            <h3 style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <MapPin size={20} /> Geolocation & Network Details: {geoData.ip}
            </h3>

            <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
              <span
                style={{
                  padding: "4px 10px",
                  borderRadius: "6px",
                  fontSize: "12px",
                  fontWeight: "700",
                  background: geoData.isPrivate ? "#fef3c7" : "#dcfce7",
                  color: geoData.isPrivate ? "#b45309" : "#15803d",
                }}
              >
                {geoData.isPrivate ? "Internal / Private IP" : "Public Routable IP"}
              </span>

              {geoData.googleMapsUrl && (
                <a
                  href={geoData.googleMapsUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="secondary-button"
                  style={{ padding: "4px 10px", fontSize: "12px", display: "flex", alignItems: "center", gap: "4px" }}
                >
                  <ExternalLink size={12} /> Google Maps
                </a>
              )}
            </div>
          </div>

          {geoData.isPrivate && (
            <div
              style={{
                marginBottom: "16px",
                padding: "12px 16px",
                borderRadius: "8px",
                background: "#fffbeb",
                border: "1px solid #fde68a",
                color: "#92400e",
                fontSize: "13px",
                display: "flex",
                alignItems: "center",
                gap: "8px",
              }}
            >
              <ShieldCheck size={16} />
              <span>
                <strong>RFC 1918 Private Address:</strong> This IP belongs to an internal local area network or loopback
                interface and cannot be geolocated to a physical global coordinate on the public internet.
              </span>
            </div>
          )}

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
              gap: "16px",
              background: "#f8fafc",
              padding: "20px",
              borderRadius: "8px",
            }}
          >
            <div>
              <span style={{ fontSize: "12px", color: "#64748b" }}>Country:</span>
              <strong style={{ display: "block", color: "#1e293b", fontSize: "15px" }}>
                {geoData.country_name} ({geoData.country_code})
              </strong>
            </div>

            <div>
              <span style={{ fontSize: "12px", color: "#64748b" }}>City / Region:</span>
              <strong style={{ display: "block", color: "#1e293b", fontSize: "15px" }}>
                {geoData.city}, {geoData.region}
              </strong>
            </div>

            <div>
              <span style={{ fontSize: "12px", color: "#64748b" }}>Organization / ISP:</span>
              <strong style={{ display: "block", color: "#1e293b", fontSize: "15px" }}>
                {geoData.org || geoData.isp}
              </strong>
            </div>

            <div>
              <span style={{ fontSize: "12px", color: "#64748b" }}>ASN:</span>
              <strong style={{ display: "block", color: "#1e293b", fontSize: "15px" }}>
                {geoData.asn}
              </strong>
            </div>

            <div>
              <span style={{ fontSize: "12px", color: "#64748b" }}>Coordinates:</span>
              <strong style={{ display: "block", color: "#1e293b", fontSize: "15px" }}>
                {typeof geoData.latitude === "number" ? geoData.latitude.toFixed(4) : geoData.latitude}°,{" "}
                {typeof geoData.longitude === "number" ? geoData.longitude.toFixed(4) : geoData.longitude}°
              </strong>
            </div>

            <div>
              <span style={{ fontSize: "12px", color: "#64748b" }}>Timezone:</span>
              <strong style={{ display: "block", color: "#1e293b", fontSize: "15px" }}>
                {geoData.timezone}
              </strong>
            </div>

            <div>
              <span style={{ fontSize: "12px", color: "#64748b" }}>Resolution Source:</span>
              <strong style={{ display: "flex", alignItems: "center", gap: "4px", color: "#2563eb", fontSize: "14px" }}>
                <Activity size={14} /> {geoData.sourceProvider || "High-Accuracy GeoEngine"}
              </strong>
            </div>
          </div>
        </div>
      )}
    </ModulePage>
  );
}
