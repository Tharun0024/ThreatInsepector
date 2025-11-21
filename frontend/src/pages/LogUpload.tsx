import { useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Shield, Upload, FileText, Search, ArrowLeft } from "lucide-react";
import { toast } from "sonner";
import IPTable from "@/components/IPTable";
import axios from "axios";

const API_BASE = "https://threatinsepector-2.onrender.com";
//http://localhost:8000
const LogUpload = () => {
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [logContent, setLogContent] = useState("");
  const [extractedIPs, setExtractedIPs] = useState<Array<{ ip: string; port?: string; timestamp?: string; incidentType?: string }>>([]);
  const [isProcessing, setIsProcessing] = useState(false);

  // Handle file selection and upload .txt/.log
  const handleFileSelect = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = event.target.files?.[0];
    if (selectedFile) {
      const fileExtension = selectedFile.name.split(".").pop()?.toLowerCase();
      if (fileExtension !== "txt" && fileExtension !== "log") {
        toast.error("Please upload a .txt or .log file");
        return;
      }
      setFile(selectedFile);
      await uploadLogToBackend(selectedFile);
    }
  };

  // Uploads to backend and gets extracted IPs/results
  const uploadLogToBackend = async (file: File) => {
    setIsProcessing(true);
    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = await axios.post(`${API_BASE}/upload_logs`, formData);
      setIsProcessing(false);

      if (response.data && Array.isArray(response.data.extracted_ips)) {
        setExtractedIPs(response.data.extracted_ips);
        toast.success(`Extracted ${response.data.extracted_ips.length} unique IP addresses`);
      }

      const reader = new FileReader();
      reader.onload = (e) => {
        setLogContent(e.target?.result as string);
      };
      reader.readAsText(file);

    } catch (error) {
      setIsProcessing(false);
      toast.error("Error uploading log file");
      setExtractedIPs([]);
    }
  };

  // Analyze one IP (single analysis)
  const handleAnalyzeIP = async (
    ip: string,
    port?: string,
    timestamp?: string,
    incidentType?: string
  ) => {
    try {
      const formData = new FormData();
      formData.append("ip", ip);
      formData.append("protocol", "tcp");
      formData.append("country", "Unknown");
      formData.append("port", port || "");
      formData.append("timestamp", timestamp || "");
      formData.append("incident_type", incidentType || "");

      const response = await axios.post(`${API_BASE}/analyze`, formData);
      if (response.data) {
        navigate("/results", {
          state: { analysis: response.data },
        });
      } else {
        toast.error("No analysis data returned from backend");
      }
    } catch (e) {
      toast.error("Error analyzing IP address");
    }
  };

  // Batch analysis (analyze all)
  const handleAnalyzeAll = async () => {
    if (extractedIPs.length === 0) {
      toast.error("No IP addresses to analyze");
      return;
    }
    try {
      const response = await axios.post(`${API_BASE}/analyze_batch`, { ip_entries: extractedIPs });
      if (response.data && Array.isArray(response.data.results)) {
        navigate("/results-batch", { state: { batchResults: response.data.results } });
      } else {
        toast.error("Failed to get batch analysis");
      }
    } catch (error) {
      toast.error("Batch analysis failed");
    }
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Navigation */}
      <nav className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="w-8 h-8 text-primary" />
              <h1 className="text-2xl font-bold text-foreground">OpenThreat Inspector</h1>
            </div>
            <div className="flex items-center gap-4">
              <Button
                variant="ghost"
                onClick={() => navigate("/")}
                className="text-foreground hover:text-primary"
              >
                <ArrowLeft className="w-4 h-4 mr-2" />
                Back to Analyzer
              </Button>
            </div>
          </div>
        </div>
      </nav>

      <div className="container mx-auto px-4 py-12">
        <div className="text-center mb-8">
          <h2 className="text-4xl font-bold text-foreground mb-4">Log File Analysis</h2>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Upload server logs to automatically extract and analyze IP addresses for threat intelligence
          </p>
        </div>

        {/* Upload Card */}
        <div className="max-w-4xl mx-auto space-y-6">
          <Card className="bg-card border-border shadow-glow-primary">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Upload className="w-6 h-6 text-primary" />
                Upload Log File
              </CardTitle>
              <CardDescription>
                Supports .txt and .log files. We'll automatically extract IP addresses from your logs.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileSelect}
                accept=".txt,.log"
                className="hidden"
              />
              <div
                onClick={() => fileInputRef.current?.click()}
                className="border-2 border-dashed border-border hover:border-primary transition-colors rounded-lg p-12 text-center cursor-pointer bg-muted/10 hover:bg-muted/20"
              >
                <FileText className="w-16 h-16 text-primary mx-auto mb-4" />
                <p className="text-lg font-semibold text-foreground mb-2">
                  {file ? file.name : "Click to upload or drag and drop"}
                </p>
                <p className="text-sm text-muted-foreground">
                  Supported formats: .txt, .log (max 10MB)
                </p>
              </div>
              {isProcessing && (
                <div className="mt-4 flex items-center justify-center gap-2 text-primary">
                  <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-primary" />
                  <span>Processing file...</span>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Log Preview */}
          {logContent && (
            <Card className="bg-card border-border">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <FileText className="w-5 h-5 text-primary" />
                  Log Preview
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="bg-muted/30 p-4 rounded-lg max-h-60 overflow-y-auto">
                  <pre className="text-sm text-muted-foreground font-mono whitespace-pre-wrap">
                    {logContent.split("\n").slice(0, 20).join("\n")}
                    {logContent.split("\n").length > 20 && "\n... (truncated)"}
                  </pre>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Extracted IPs */}
          {extractedIPs.length > 0 && (
            <Card className="bg-card border-border">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="flex items-center gap-2">
                    <Search className="w-5 h-5 text-primary" />
                    Extracted IP Addresses ({extractedIPs.length})
                  </CardTitle>
                  <Button
                    onClick={handleAnalyzeAll}
                    className="bg-primary text-primary-foreground hover:bg-primary/90"
                  >
                    Analyze All IPs
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
               <IPTable
               data={extractedIPs}
               onAnalyze={({ ip, port, timestamp, incidentType }) =>
               handleAnalyzeIP(ip, port, timestamp, incidentType)
               }
              />


              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
};

export default LogUpload;
