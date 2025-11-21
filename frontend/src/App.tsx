import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Index from "./pages/Index";
import ResultsDashboard from "./pages/ResultsDashboard";
import LogUpload from "./pages/LogUpload";
import NotFound from "./pages/NotFound";
import Rdashboard from "./pages/Rdashboard";
import ScrollToTop from "@/components/ui/ScrollToTop"; // <-- scroll to top on route change

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <ScrollToTop /> {/* <-- Ensures top of page after each nav */}
        <Routes>
          <Route path="/" element={<Index />} />
          <Route path="/results" element={<ResultsDashboard />} />
          <Route path="/logs" element={<LogUpload />} />
          <Route path="/results-batch" element={<Rdashboard />} />
          {/* Add all custom routes above the catch-all "*" route */}
          <Route path="*" element={<NotFound />} />
        </Routes>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
