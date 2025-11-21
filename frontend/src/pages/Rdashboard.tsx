import { useLocation, useNavigate } from "react-router-dom";
import { useEffect, useState } from "react";
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";
import { Button } from "@/components/ui/button";
import RiskBadge from "@/components/RiskBadge";
import SummaryCard from "@/components/SummaryCard";
import ThreatMap from "@/components/ThreatMap";
import { Doughnut, Bar } from "react-chartjs-2";
import {
  Chart as ChartJS,
  ArcElement,
  CategoryScale,
  LinearScale,
  BarElement,
  Title as ChartTitle,
  Tooltip,
  Legend
} from "chart.js";
import { ArrowLeft, Download, Shield, Network, Globe, Building } from "lucide-react";

ChartJS.register(
  ArcElement,
  CategoryScale,
  LinearScale,
  BarElement,
  ChartTitle,
  Tooltip,
  Legend
);

const exportBatchPDF = (batchResults: any[]) => {
  const doc = new jsPDF({ orientation: "portrait", unit: "pt", format: "a4" });
  let y = 40;
  doc.setFont("helvetica", "bold").setFontSize(22);
  doc.text("Batch Threat Analysis Report", 40, y);
  doc.setFontSize(12).setFont("helvetica", "normal");
  doc.text(`Report Generated: ${new Date().toLocaleString()}`, 40, (y += 20));
  batchResults.forEach((result, idx) => {
    doc.setFont("helvetica", "bold").setFontSize(14);
    doc.text(`Result #${idx + 1}: ${result.ip}`, 40, (y += 30));
    doc.setFont("helvetica", "normal").setFontSize(11);
    autoTable(doc, {
      startY: y + 5,
      margin: { left: 40 },
      head: [["Field", "Value"]],
      body: [
        ["Risk Level", result.risk_level],
        ["Risk Score", result.scores?.risk_engine_score ?? "-"],
        ["AbuseIPDB Score", result.scores?.abuse_score ?? "-"],
        ["TOR", result.classification?.TOR ? "Detected" : "Clear"],
        ["VPN", result.classification?.VPN ? "Detected" : "Clear"],
        ["Proxy", result.classification?.Proxy ? "Detected" : "Clear"],
        ["Country", result.geolocation?.country ?? "-"],
        ["City", result.geolocation?.city ?? "-"],
        ["Provider", result.isp?.provider ?? "-"],
        ["ASN", result.isp?.asn ?? "-"],
      ],
      showHead: "firstPage",
      theme: "grid",
      tableWidth: 350,
      styles: { font: "helvetica", fontSize: 11 }
    });
    y = (doc as any).lastAutoTable.finalY || doc.internal.pageSize.height - 40;
    autoTable(doc, {
      startY: y + 5,
      margin: { left: 40 },
      head: [["Threat Explanations"]],
      body: (result.risk_explanation || []).map((reason: string) => [reason]),
      showHead: "firstPage",
      theme: "grid",
      tableWidth: 350,
      styles: { font: "helvetica", fontSize: 10 }
    });
    y = (doc as any).lastAutoTable.finalY || doc.internal.pageSize.height - 40;
    if (doc.internal.pageSize.height - y < 100) {
      doc.addPage();
      y = 40;
    }
  });
  doc.save("batch-threat-report.pdf");
};

const exportBatchJSON = (results: any[]) => {
  const blob = new Blob([JSON.stringify(results, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "batch-threat-report.json";
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
};

const Rdashboard = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const batchResults = location.state?.batchResults || [];
  const [expanded, setExpanded] = useState<number | null>(null);

  useEffect(() => {
    if (!Array.isArray(batchResults) || batchResults.length === 0) {
      navigate("/logs");
    }
  }, [batchResults, navigate]);

  if (!Array.isArray(batchResults) || batchResults.length === 0) return null;

  return (
    <div className="min-h-screen bg-background">
      <div className="border-b border-border bg-card/50 sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <Button variant="ghost" onClick={() => navigate("/logs")}>
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back to Logs
          </Button>
          <div className="flex gap-3">
            <Button variant="secondary" onClick={() => exportBatchPDF(batchResults)}>
              <Download className="w-4 h-4 mr-2" /> PDF
            </Button>
            <Button variant="secondary" onClick={() => exportBatchJSON(batchResults)}>
              <Download className="w-4 h-4 mr-2" /> JSON
            </Button>
          </div>
        </div>
      </div>
      <div className="container mx-auto px-4 py-8">
        <h2 className="text-3xl font-bold text-foreground mb-6">Batch Threat Analysis Results</h2>
        {expanded !== null ? (
          <div>
            <Button
              variant="outline"
              className="mb-4"
              onClick={() => setExpanded(null)}
            >
              <ArrowLeft className="w-4 h-4 mr-2" />
              Back to List
            </Button>
            {(() => {
              const analysis = batchResults[expanded];
              const riskLevel = analysis.risk_level || "Medium";
              const classification = analysis.classification || {};
              const geolocation = analysis.geolocation || {};
              const isp = analysis.isp || {};
              const ipAddress = analysis.ip || "";
              const port = analysis.port || "";
              const dateTime = analysis.timestamp || "";
              const incidentType = analysis.incident_type || "";
              const riskScore = analysis.scores?.risk_engine_score ?? "-";
              const abuseScore = analysis.scores?.abuse_score ?? "-";

              const riskScoreData = {
                labels: ["Low Risk", "Medium Risk", "High Risk"],
                datasets: [
                  {
                    data: analysis.risk_distribution
                      ? [
                          analysis.risk_distribution.Low || 0,
                          analysis.risk_distribution.Medium || 0,
                          analysis.risk_distribution.High || 0,
                        ]
                      : [30, 50, 20],
                    backgroundColor: [
                      "rgba(34, 197, 94, 0.9)",
                      "rgba(251, 191, 36, 0.9)",
                      "rgba(239, 68, 68, 0.9)",
                    ],
                    borderColor: [
                      "rgba(34, 197, 94, 1)",
                      "rgba(251, 191, 36, 1)",
                      "rgba(239, 68, 68, 1)",
                    ],
                    borderWidth: 3,
                    hoverOffset: 15,
                  },
                ],
              };

              const threatFactorsData = {
                labels:
                  (analysis.factor_scores || []).map((f: any) => f.label) ||
                  ["TOR/VPN", "Blocklists", "Geolocation", "Port Activity", "History"],
                datasets: [
                  {
                    label: "Threat Score",
                    data:
                      (analysis.factor_scores || []).map((f: any) => f.value) ||
                      [75, 40, 20, 60, 35],
                    backgroundColor: [
                      "rgba(99, 102, 241, 0.8)",
                      "rgba(168, 85, 247, 0.8)",
                      "rgba(236, 72, 153, 0.8)",
                      "rgba(14, 165, 233, 0.8)",
                      "rgba(34, 211, 238, 0.8)",
                    ],
                    borderColor: [
                      "rgba(99, 102, 241, 1)",
                      "rgba(168, 85, 247, 1)",
                      "rgba(236, 72, 153, 1)",
                      "rgba(14, 165, 233, 1)",
                      "rgba(34, 211, 238, 1)",
                    ],
                    borderWidth: 2,
                  },
                ],
              };

              const chartOptions = {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                  legend: {
                    labels: {
                      color: "#ffffff",
                      font: { size: 13 },
                    },
                  },
                  tooltip: {
                    backgroundColor: "rgba(0, 0, 0, 0.9)",
                    titleColor: "#ffffff",
                    bodyColor: "#ffffff",
                    borderColor: "rgba(99, 102, 241, 0.5)",
                    borderWidth: 1,
                  },
                },
                scales: {
                  y: {
                    ticks: { color: "#ffffff" },
                    grid: { color: "rgba(255,255,255,0.1)" },
                  },
                  x: {
                    ticks: { color: "#ffffff" },
                    grid: { color: "rgba(255,255,255,0.1)" },
                  },
                },
              };

              return (
                <div className="bg-background rounded-lg mb-4 p-4 border border-muted-foreground">
                  <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
                    <SummaryCard title="Risk Level" icon={Shield}>
                      <div className="space-y-2">
                        <RiskBadge level={riskLevel} className="w-full justify-center" />
                        <p className="text-sm text-muted-foreground">
                          Based on multiple threat indicators
                        </p>
                      </div>
                    </SummaryCard>
                    <SummaryCard title="Classification" icon={Network}>
                      <div className="space-y-2">
                        <div className="flex justify-between text-sm">
                          <span className="text-muted-foreground">TOR:</span>
                          <span
                            className={classification.TOR ? "text-destructive" : "text-success"}
                          >
                            {classification.TOR ? "Detected" : "Clear"}
                          </span>
                        </div>
                        <div className="flex justify-between text-sm">
                          <span className="text-muted-foreground">VPN:</span>
                          <span
                            className={classification.VPN ? "text-warning" : "text-success"}
                          >
                            {classification.VPN ? "Detected" : "Clear"}
                          </span>
                        </div>
                        <div className="flex justify-between text-sm">
                          <span className="text-muted-foreground">Proxy:</span>
                          <span
                            className={classification.Proxy ? "text-warning" : "text-success"}
                          >
                            {classification.Proxy ? "Detected" : "Clear"}
                          </span>
                        </div>
                      </div>
                    </SummaryCard>
                    <SummaryCard title="Geolocation" icon={Globe}>
                      <div className="space-y-2">
                        <div className="flex items-center gap-2">
                          <span className="text-2xl">{geolocation.flag || "🏳️"}</span>
                          <div>
                            <p className="font-semibold text-foreground">
                              {geolocation.country}
                            </p>
                            <p className="text-sm text-muted-foreground">
                              {geolocation.city}
                            </p>
                          </div>
                        </div>
                        <p className="text-xs text-muted-foreground font-mono">
                          {typeof geolocation.lat === "number" &&
                          typeof geolocation.lon === "number"
                            ? `${geolocation.lat.toFixed(4)}, ${geolocation.lon.toFixed(4)}`
                            : "No coordinates"}
                        </p>
                      </div>
                    </SummaryCard>
                    <SummaryCard title="ISP Details" icon={Building}>
                      <div className="space-y-2">
                        <div>
                          <p className="text-sm text-muted-foreground">Provider</p>
                          <p className="font-semibold text-foreground">{isp.provider}</p>
                        </div>
                        <div>
                          <p className="text-sm text-muted-foreground">ASN</p>
                          <p className="font-mono text-sm text-primary">{isp.asn}</p>
                        </div>
                      </div>
                    </SummaryCard>
                  </div>

                  <div className="grid lg:grid-cols-2 gap-6 mb-8">
                    <div className="bg-card border-border p-4 rounded-lg">
                      <h3 className="text-lg font-semibold text-foreground mb-4">
                        Geographic Location
                      </h3>
                      <ThreatMap
                        lat={geolocation.lat}
                        lng={geolocation.lon}
                        ipAddress={ipAddress}
                        city={geolocation.city}
                        country={geolocation.country}
                      />
                    </div>
                    <div className="bg-card border-border p-4 rounded-lg">
                      <h3 className="text-lg font-semibold text-foreground mb-4">
                        Risk Distribution
                      </h3>
                      <div className="h-[300px]">
                        {/* @ts-ignore */}
                        <Doughnut
                          data={riskScoreData}
                          options={{ ...chartOptions, scales: undefined }}
                        />
                      </div>
                    </div>
                  </div>

                  <div className="bg-card border-border p-4 rounded-lg mb-8">
                    <h3 className="text-lg font-semibold text-foreground mb-4">
                      Threat Factor Analysis
                    </h3>
                    <div className="h-[300px]">
                      {/* @ts-ignore */}
                      <Bar data={threatFactorsData} options={chartOptions} />
                    </div>
                  </div>

                  <div className="bg-card border-border p-4 rounded-lg">
                    <h3 className="text-lg font-semibold text-foreground mb-2">
                      Intelligence Sources and Explanations
                    </h3>
                    <ul className="space-y-2">
                      {(analysis.risk_explanation || []).map((reason: string, idx2: number) => (
                        <li
                          key={idx2}
                          className="bg-muted/30 p-3 rounded-lg text-sm text-foreground"
                          style={{ fontFamily: "inherit" }}
                        >
                          {reason}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              );
            })()}
          </div>
        ) : (
          <div className="grid gap-5">
            {batchResults.map((res: any, idx: number) => (
              <div key={res.ip + idx} className="bg-card border-border rounded-lg p-4 shadow">
                <div className="flex flex-wrap gap-4 justify-between items-center mb-2">
                  <div>
                    <span className="mr-2 font-mono text-primary">{res.ip}</span>
                    <RiskBadge level={res.risk_level} />
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setExpanded(idx)}
                  >
                    Show Details
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default Rdashboard;
