import { useLocation, useNavigate } from "react-router-dom";
import { useEffect, useState, useRef } from "react";
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";
import html2canvas from "html2canvas";
import { Chart as ChartJS, ArcElement, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend } from "chart.js";
import { Doughnut, Bar } from "react-chartjs-2";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import SummaryCard from "@/components/SummaryCard";
import RiskBadge from "@/components/RiskBadge";
import ThreatMap from "@/components/ThreatMap";
import { Shield, Globe, Building, Network, ChevronDown, ChevronUp, ArrowLeft, Download } from "lucide-react";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";

ChartJS.register(ArcElement, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

const ResultsDashboard = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const analysis = location.state?.analysis;
  const [isEnrichmentOpen, setIsEnrichmentOpen] = useState(false);
  const enrichmentRef = useRef(null);

  useEffect(() => {
    if (!analysis) {
      navigate("/");
    }
  }, [analysis, navigate]);

  if (!analysis) return null;

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
      (analysis.factor_scores || []).map((f) => f.label) ||
      ["TOR/VPN", "Blocklists", "Geolocation", "Port Activity", "History"],
    datasets: [
      {
        label: "Threat Score",
        data:
          (analysis.factor_scores || []).map((f) => f.value) ||
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

  // PDF: Build a report with correct y coordination using autoTable chaining
  const handleDownloadPDF = () => {
    const doc = new jsPDF({ orientation: "portrait", unit: "pt", format: "a4" });
    const marginLeft = 40;
    let y = 40;

    doc.setFont("helvetica", "bold");
    doc.setFontSize(22);
    doc.text("Threat Analysis Report", marginLeft, y);
    y += 18;

    doc.setFontSize(12);
    doc.setFont("helvetica", "normal");
    doc.text(`Report Generated: ${new Date().toLocaleString()}`, marginLeft, (y += 18));
    doc.text(`IP Address: ${ipAddress}`, marginLeft, (y += 18));
    if (port) doc.text(`Port: ${port}`, marginLeft, (y += 16));
    if (dateTime) doc.text(`Timestamp: ${dateTime}`, marginLeft, (y += 16));
    if (incidentType) doc.text(`Incident Type: ${incidentType}`, marginLeft, (y += 16));

    doc.setFont("helvetica", "bold");
    doc.text("Summary", marginLeft, (y += 30));
    doc.setFont("helvetica", "normal");
    doc.text(`Risk Level: ${riskLevel}`, marginLeft, (y += 18));
    doc.text(`Risk Score: ${riskScore}`, marginLeft, (y += 16));
    doc.text(`AbuseIPDB Score: ${abuseScore}`, marginLeft, (y += 16));

    // Classification Table
    doc.setFont("helvetica", "bold");
    doc.text("Classification", marginLeft, (y += 25));
    doc.setFont("helvetica", "normal");
    autoTable(doc, {
      startY: (doc as any).lastAutoTable?.finalY ? (doc as any).lastAutoTable.finalY + 10 : y + 10,
      margin: { left: marginLeft },
      theme: "grid",
      head: [["Type", "Status"]],
      body: [
        ["TOR", classification.TOR ? "Detected" : "Clear"],
        ["VPN", classification.VPN ? "Detected" : "Clear"],
        ["Proxy", classification.Proxy ? "Detected" : "Clear"],
      ],
      headStyles: { fillColor: [51, 65, 85], textColor: [255, 255, 255] },
      bodyStyles: { fillColor: [255, 255, 255], textColor: [51, 65, 85] },
      styles: { font: "helvetica", fontSize: 11 },
      tableWidth: 270,
    });

    // Geo/ISP Table
    doc.setFont("helvetica", "bold");
    doc.text("Geolocation / ISP", marginLeft, (doc as any).lastAutoTable.finalY + 25);
    doc.setFont("helvetica", "normal");
    autoTable(doc, {
      startY: (doc as any).lastAutoTable.finalY + 35,
      margin: { left: marginLeft },
      theme: "grid",
      head: [["Field", "Value"]],
      body: [
        ["Country", geolocation.country || "-"],
        ["City", geolocation.city || "-"],
        ["Coordinates",
          typeof geolocation.lat === "number" && typeof geolocation.lon === "number"
            ? `${geolocation.lat}, ${geolocation.lon}` : "-"
        ],
        ["ASN", isp.asn || "-"],
        ["Provider", isp.provider || "-"],
      ],
      headStyles: { fillColor: [34, 197, 94], textColor: [255, 255, 255] },
      bodyStyles: { fillColor: [255, 255, 255], textColor: [51, 65, 85] },
      styles: { font: "helvetica", fontSize: 11 },
      tableWidth: 270,
    });

    // Risk Distribution Table
    doc.setFont("helvetica", "bold");
    doc.text("Risk Distribution", marginLeft, (doc as any).lastAutoTable.finalY + 25);
    doc.setFont("helvetica", "normal");
    autoTable(doc, {
      startY: (doc as any).lastAutoTable.finalY + 35,
      margin: { left: marginLeft },
      theme: "grid",
      head: [["Level", "Count"]],
      body: [
        ["Low", String(analysis.risk_distribution?.Low ?? "-")],
        ["Medium", String(analysis.risk_distribution?.Medium ?? "-")],
        ["High", String(analysis.risk_distribution?.High ?? "-")]
      ],
      headStyles: { fillColor: [251, 191, 36], textColor: [51, 65, 85] },
      bodyStyles: { fillColor: [255, 255, 255], textColor: [51, 65, 85] },
      styles: { font: "helvetica", fontSize: 11 },
      tableWidth: 150,
    });

    // Threat Factors Table
    doc.setFont("helvetica", "bold");
    doc.text("Threat Factors", marginLeft, (doc as any).lastAutoTable.finalY + 25);
    doc.setFont("helvetica", "normal");
    autoTable(doc, {
      startY: (doc as any).lastAutoTable.finalY + 35,
      margin: { left: marginLeft },
      theme: "grid",
      head: [["Factor", "Score"]],
      body: (analysis.factor_scores || []).map(f => [f.label, String(f.value)]),
      headStyles: { fillColor: [99, 102, 241], textColor: [255, 255, 255] },
      bodyStyles: { fillColor: [255, 255, 255], textColor: [51, 65, 85] },
      styles: { font: "helvetica", fontSize: 11 },
      tableWidth: 280,
    });

    // Explanations Table
    doc.setFont("helvetica", "bold");
    doc.text("Intelligence Sources and Explanations", marginLeft, (doc as any).lastAutoTable.finalY + 25);
    doc.setFont("helvetica", "normal");
    autoTable(doc, {
      startY: (doc as any).lastAutoTable.finalY + 35,
      margin: { left: marginLeft },
      theme: "grid",
      head: [["Explanation"]],
      body: (analysis.risk_explanation || []).map(reason => [reason]),
      headStyles: { fillColor: [99, 102, 241], textColor: [255, 255, 255], fontSize: 13 },
      bodyStyles: { fillColor: [243, 244, 246], textColor: [51, 65, 85], fontSize: 11 },
      styles: { font: "helvetica" },
      columnStyles: { 0: { cellWidth: 470 } }
    });

    doc.save(`threat-report_${ipAddress || "unknown"}.pdf`);
  };

  // JSON download handler
  const handleDownloadReport = () => {
    if (!analysis) return;
    const blob = new Blob([JSON.stringify(analysis, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `threat-report_${ipAddress || "unknown"}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header with Download buttons */}
      <div className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Button
              variant="ghost"
              onClick={() => navigate("/")}
              className="text-foreground hover:text-primary"
            >
              <ArrowLeft className="w-4 h-4 mr-2" />
              Back
            </Button>
            <div>
              <h1 className="text-2xl font-bold text-foreground">
                Threat Analysis Results
              </h1>
              <p className="text-sm text-muted-foreground">
                IP:{" "}
                <span className="font-mono text-primary">{ipAddress}</span>
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <RiskBadge level={riskLevel} />
            <Button
              variant="secondary"
              className="ml-1 flex gap-1"
              onClick={handleDownloadPDF}
              title="Download PDF"
            >
              <Download className="w-4 h-4" /> PDF
            </Button>
            <Button
              variant="secondary"
              className="ml-1 flex gap-1"
              onClick={handleDownloadReport}
              title="Download JSON"
            >
              <Download className="w-4 h-4" /> JSON
            </Button>
          </div>
        </div>
      </div>

      <div className="container mx-auto px-4 py-8">
        {/* Summary Cards */}
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
                  className={
                    classification.TOR ? "text-destructive" : "text-success"
                  }
                >
                  {classification.TOR ? "Detected" : "Clear"}
                </span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">VPN:</span>
                <span
                  className={
                    classification.VPN ? "text-warning" : "text-success"
                  }
                >
                  {classification.VPN ? "Detected" : "Clear"}
                </span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Proxy:</span>
                <span
                  className={
                    classification.Proxy ? "text-warning" : "text-success"
                  }
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
                  ? `${geolocation.lat.toFixed(4)}, ${geolocation.lon.toFixed(
                      4
                    )}`
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

        {/* Map and Charts */}
        <div className="grid lg:grid-cols-2 gap-6 mb-8">
          <Card className="bg-card border-border p-4">
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
          </Card>
          <Card className="bg-card border-border p-4">
            <h3 className="text-lg font-semibold text-foreground mb-4">
              Risk Distribution
            </h3>
            <div className="h-[300px]">
              <Doughnut
                data={riskScoreData}
                options={{ ...chartOptions, scales: undefined }}
              />
            </div>
          </Card>
        </div>

        {/* Threat Factors Chart */}
        <Card className="bg-card border-border p-4 mb-8">
          <h3 className="text-lg font-semibold text-foreground mb-4">
            Threat Factor Analysis
          </h3>
          <div className="h-[300px]">
            <Bar data={threatFactorsData} options={chartOptions} />
          </div>
        </Card>

        {/* Enrichment Data */}
        <Collapsible
          open={isEnrichmentOpen}
          onOpenChange={setIsEnrichmentOpen}
        >
          <Card className="bg-card border-border">
            <CollapsibleTrigger className="w-full p-4 flex items-center justify-between hover:bg-muted/30 transition-colors">
              <h3 className="text-lg font-semibold text-foreground">
                Enrichment Data & Sources
              </h3>
              {isEnrichmentOpen ? (
                <ChevronUp className="w-5 h-5 text-muted-foreground" />
              ) : (
                <ChevronDown className="w-5 h-5 text-muted-foreground" />
              )}
            </CollapsibleTrigger>
            <CollapsibleContent>
              <div
                ref={enrichmentRef}
                className="p-4 space-y-4 border-t border-border"
              >
                <div>
                  <h4 className="font-semibold text-foreground mb-2">
                    Input Data
                  </h4>
                  <div className="bg-muted/30 p-3 rounded-lg space-y-1 text-sm">
                    <p>
                      <span className="text-muted-foreground">IP Address:</span>
                      <span className="font-mono text-primary">
                        {ipAddress}
                      </span>
                    </p>
                    {port && (
                      <p>
                        <span className="text-muted-foreground">Port:</span>
                        <span className="font-mono">{port}</span>
                      </p>
                    )}
                    {dateTime && (
                      <p>
                        <span className="text-muted-foreground">
                          Timestamp:
                        </span>
                        {dateTime}
                      </p>
                    )}
                    {incidentType && (
                      <p>
                        <span className="text-muted-foreground">
                          Incident Type:
                        </span>
                        {incidentType}
                      </p>
                    )}
                  </div>
                </div>
                <div>
                  <h4 className="font-semibold text-foreground mb-2">
                    Intelligence Sources and Explanations
                  </h4>
                  <div className="space-y-2">
                    {(analysis.risk_explanation || []).map((reason, idx) => (
                      <div
                        key={idx}
                        className="bg-muted/30 p-3 rounded-lg text-sm text-foreground"
                        style={{ fontFamily: "inherit" }}
                      >
                        {reason}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </CollapsibleContent>
          </Card>
        </Collapsible>
      </div>
    </div>
  );
};

export default ResultsDashboard;
