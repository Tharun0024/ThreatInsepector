import { useEffect, useRef } from "react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";

// Fix Leaflet default marker icon issue
delete (L.Icon.Default.prototype as any)._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon-2x.png",
  iconUrl: "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon.png",
  shadowUrl: "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png",
});

interface ThreatMapProps {
  lat: number;
  lng: number;
  ipAddress: string;
  city: string;
  country: string;
}

const ThreatMap = ({ lat, lng, ipAddress, city, country }: ThreatMapProps) => {
  const mapRef = useRef<L.Map | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!containerRef.current || mapRef.current) return;

    // Initialize map
    const map = L.map(containerRef.current).setView([lat, lng], 8);
    mapRef.current = map;

    // Add tile layer
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
    }).addTo(map);

    // Add marker with white text popup
    const marker = L.marker([lat, lng]).addTo(map);
    marker.bindPopup(`
      <div style="font-size: 12px; color: #000000;">
        <p style="font-weight: 600; margin-bottom: 4px; color: #000000;">${ipAddress}</p>
        <p style="color: #333333;">${city}, ${country}</p>
      </div>
    `);

    // Cleanup
    return () => {
      if (mapRef.current) {
        mapRef.current.remove();
        mapRef.current = null;
      }
    };
  }, [lat, lng, ipAddress, city, country]);

  return <div ref={containerRef} className="h-[300px] rounded-lg" />;
};

export default ThreatMap;
