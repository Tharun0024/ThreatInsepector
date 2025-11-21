import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Search } from "lucide-react";

interface IPData {
  ip: string;
  port?: string;
  timestamp?: string;
  incidentType?: string;
}

interface IPTableProps {
  data: IPData[];
  onAnalyze?: (ip: string) => void;
}

const IPTable = ({ data, onAnalyze }: IPTableProps) => {
  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <Table>
        <TableHeader>
          <TableRow className="bg-muted/50 hover:bg-muted/70">
            <TableHead className="text-foreground font-semibold">IP Address</TableHead>
            <TableHead className="text-foreground font-semibold">Port</TableHead>
            <TableHead className="text-foreground font-semibold">Timestamp</TableHead>
            <TableHead className="text-foreground font-semibold">Incident Type</TableHead>
            <TableHead className="text-right text-foreground font-semibold">Action</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {data.length === 0 ? (
            <TableRow>
              <TableCell colSpan={5} className="text-center text-muted-foreground py-8">
                No IP addresses found
              </TableCell>
            </TableRow>
          ) : (
            data.map((row, index) => (
              <TableRow key={index} className="hover:bg-muted/30 transition-colors">
                <TableCell className="font-mono text-primary">{row.ip}</TableCell>
                <TableCell className="text-muted-foreground">{row.port || "-"}</TableCell>
                <TableCell className="text-muted-foreground">{row.timestamp || "-"}</TableCell>
                <TableCell className="text-muted-foreground">{row.incidentType || "-"}</TableCell>
                <TableCell className="text-right">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => onAnalyze?.(row.ip)}
                    className="border-primary/50 text-primary hover:bg-primary/10"
                  >
                    <Search className="w-4 h-4 mr-1" />
                    Analyze
                  </Button>
                </TableCell>
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>
    </div>
  );
};

export default IPTable;
