import { Badge } from "@/components/ui/badge";
import { Shield, AlertTriangle, AlertOctagon } from "lucide-react";

interface RiskBadgeProps {
  level?: string;
  className?: string;
}

const config = {
  low: {
    label: "Low Risk",
    variant: "default" as const,
    icon: Shield,
    className: "bg-success/20 text-success border-success/50 hover:bg-success/30",
  },
  medium: {
    label: "Medium Risk",
    variant: "default" as const,
    icon: AlertTriangle,
    className: "bg-warning/20 text-warning border-warning/50 hover:bg-warning/30",
  },
  high: {
    label: "High Risk",
    variant: "default" as const,
    icon: AlertOctagon,
    className: "bg-destructive/20 text-destructive border-destructive/50 hover:bg-destructive/30",
  },
};

const fallback = {
  label: "Unknown Risk",
  icon: Shield,
  className: "bg-muted text-muted-foreground border-muted/50",
};

const RiskBadge = ({ level, className }: RiskBadgeProps) => {
  // Normalize/defend against undefined or unexpected case
  const normalizedLevel = typeof level === "string" ? level.toLowerCase() : "unknown";
  const { label, icon: Icon, className: badgeClassName } = config[normalizedLevel] || fallback;

  return (
    <Badge variant="outline" className={`${badgeClassName} ${className ?? ""} px-3 py-1.5 text-sm font-semibold`}>
      <Icon className="w-4 h-4 mr-1.5" />
      {label}
    </Badge>
  );
};

export default RiskBadge;
