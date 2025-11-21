import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Shield, Search, FileText, Menu } from "lucide-react";
import { toast } from "sonner";
import axios from "axios";

const API_BASE = "https://threatinsepector-2.onrender.com";
//http://localhost:8000

const Index = () => {
  const navigate = useNavigate();
  const [ipAddress, setIpAddress] = useState("");
  const [port, setPort] = useState("");
  const [dateTime, setDateTime] = useState("");
  const [incidentType, setIncidentType] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  const handleAnalyze = async () => {
    if (!ipAddress) {
      toast.error("Please enter an IP address");
      return;
    }
    // Basic IP validation
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (!ipRegex.test(ipAddress)) {
      toast.error("Please enter a valid IP address");
      return;
    }
    setIsAnalyzing(true);
    toast.info("Analyzing IP address...");

    try {
      const formData = new FormData();
      formData.append("ip", ipAddress);
      formData.append("protocol", "http");        // You can add a protocol dropdown if you want
      formData.append("country", "US");           // Add country dropdown if needed
      if (port) formData.append("port", port);
      if (dateTime) formData.append("timestamp", dateTime);
      if (incidentType) formData.append("incident_type", incidentType);

      const response = await axios.post(`${API_BASE}/analyze`, formData);
      setIsAnalyzing(false);
      toast.success("Analysis complete!");
      // Pass backend results to /results page using state
      navigate("/results", {
        state: {
          analysis: response.data,
        },
      });
    } catch (e) {
      setIsAnalyzing(false);
      toast.error("Error during analysis.");
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
            <div className="hidden md:flex items-center gap-4">
              <Button
                variant="ghost"
                onClick={() => navigate("/")}
                className="text-foreground hover:text-primary"
              >
                <Search className="w-4 h-4 mr-2" />
                Analyzer
              </Button>
              <Button
                variant="ghost"
                onClick={() => navigate("/logs")}
                className="text-foreground hover:text-primary"
              >
                <FileText className="w-4 h-4 mr-2" />
                Log Upload
              </Button>
            </div>
            <Button variant="ghost" size="icon" className="md:hidden">
              <Menu className="w-6 h-6" />
            </Button>
          </div>
        </div>
      </nav>
      {/* Hero Section */}
      <div className="container mx-auto px-4 py-12">
        <div className="text-center mb-12">
          <h2 className="text-5xl font-bold text-foreground mb-4 bg-gradient-to-r from-primary to-secondary bg-clip-text text-transparent">
            IP THREAT INTELLIGENCE PLATFORM
          </h2>

          <p className="text-xl text-muted-foreground max-w-2xl mx-auto leading-relaxed py-2">
               Comprehensive threat analysis powered by open-source intelligence. Analyze IP addresses,
               detect threats, and enhance your security posture.
          </p>

        </div>
        {/* Main Analysis Card */}
        <div className="max-w-2xl mx-auto">
          <Card className="bg-card border-border shadow-glow-primary">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-2xl">
                <Shield className="w-6 h-6 text-primary" />
                IP Threat Analyzer
              </CardTitle>
              <CardDescription className="text-muted-foreground">
                Enter IP address details to perform comprehensive threat analysis including TOR/VPN
                detection, geolocation, and risk scoring.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* IP Address Input */}
              <div className="space-y-2">
                <Label htmlFor="ip" className="text-foreground font-semibold">
                  IP Address *
                </Label>
                <Input
                  id="ip"
                  type="text"
                  placeholder="192.168.1.1"
                  value={ipAddress}
                  onChange={(e) => setIpAddress(e.target.value)}
                  className="bg-input border-border text-foreground font-mono"
                />
              </div>
              {/* Port Input */}
              <div className="space-y-2">
                <Label htmlFor="port" className="text-foreground font-semibold">
                  Port (Optional)
                </Label>
                <Input
                  id="port"
                  type="text"
                  placeholder="8080"
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                  className="bg-input border-border text-foreground font-mono"
                />
              </div>
              {/* Date/Time Input */}
              <div className="space-y-2">
                <Label htmlFor="datetime" className="text-foreground font-semibold">
                  Date/Time (Optional)
                </Label>
                <Input
                  id="datetime"
                  type="datetime-local"
                  value={dateTime}
                  onChange={(e) => setDateTime(e.target.value)}
                  className="bg-input border-border text-foreground"
                />
              </div>
              {/* Incident Type Dropdown */}
              <div className="space-y-2">
                <Label htmlFor="incident" className="text-foreground font-semibold">
                  Incident Type (Optional)
                </Label>
                <Select value={incidentType} onValueChange={setIncidentType}>
                  <SelectTrigger className="bg-input border-border text-foreground">
                    <SelectValue placeholder="Select incident type" />
                  </SelectTrigger>
                  <SelectContent className="bg-popover border-border">
                    <SelectItem value="bruteforce">Brute Force Attack</SelectItem>
                    <SelectItem value="malware">Malware Distribution</SelectItem>
                    <SelectItem value="phishing">Phishing Attempt</SelectItem>
                    <SelectItem value="ddos">DDoS Attack</SelectItem>
                    <SelectItem value="scanning">Port Scanning</SelectItem>
                    <SelectItem value="intrusion">Intrusion Attempt</SelectItem>
                    <SelectItem value="other">Other</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              {/* Analyze Button */}
              <Button
                onClick={handleAnalyze}
                disabled={isAnalyzing}
                className="w-full bg-primary text-primary-foreground hover:bg-primary/90 shadow-glow-primary text-lg py-6"
              >
                {isAnalyzing ? (
                  <>
                    <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-primary-foreground mr-2" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Search className="w-5 h-5 mr-2" />
                    Analyze Now
                  </>
                )}
              </Button>
            </CardContent>
          </Card>
          {/* Features Grid */}
          <div className="grid md:grid-cols-3 gap-4 mt-8">
            <Card className="bg-card/50 border-border">
              <CardContent className="pt-6">
                <h3 className="font-semibold text-foreground mb-2">TOR/VPN Detection</h3>
                <p className="text-sm text-muted-foreground">
                  Identify anonymization services and proxy connections
                </p>
              </CardContent>
            </Card>
            <Card className="bg-card/50 border-border">
              <CardContent className="pt-6">
                <h3 className="font-semibold text-foreground mb-2">Geolocation</h3>
                <p className="text-sm text-muted-foreground">
                  Precise IP location mapping with ISP details
                </p>
              </CardContent>
            </Card>
            <Card className="bg-card/50 border-border">
              <CardContent className="pt-6">
                <h3 className="font-semibold text-foreground mb-2">Risk Scoring</h3>
                <p className="text-sm text-muted-foreground">
                  Multi-factor threat assessment and risk analysis
                </p>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Index;
