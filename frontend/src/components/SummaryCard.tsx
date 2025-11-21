import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { LucideIcon } from "lucide-react";
import { ReactNode } from "react";

interface SummaryCardProps {
  title: string;
  icon: LucideIcon;
  children: ReactNode;
  className?: string;
}

const SummaryCard = ({ title, icon: Icon, children, className }: SummaryCardProps) => {
  return (
    <Card className={`bg-card border-border shadow-lg hover:shadow-glow-primary transition-all duration-300 ${className}`}>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-lg font-semibold">
          <Icon className="w-5 h-5 text-primary" />
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
};

export default SummaryCard;
