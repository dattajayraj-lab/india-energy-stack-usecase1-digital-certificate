"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ThemeProvider } from "next-themes";
import { useState, type ReactNode } from "react";
import { Toaster } from "@/components/ui/sonner";
import { I18nProvider } from "@/lib/i18n";

export function Providers({ children }: { children: ReactNode }) {
  const [client] = useState(
    () => new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } }),
  );
  return (
    <ThemeProvider attribute="class" defaultTheme="system" enableSystem disableTransitionOnChange>
      <QueryClientProvider client={client}>
        <I18nProvider>
          {children}
          <Toaster />
        </I18nProvider>
      </QueryClientProvider>
    </ThemeProvider>
  );
}
