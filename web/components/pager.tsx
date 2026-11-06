"use client";

import { Button } from "@/components/ui/button";
import { useI18n } from "@/lib/i18n";

export function Pager({
  page,
  pageSize,
  total,
  onPage,
}: {
  page: number;
  pageSize: number;
  total: number;
  onPage: (page: number) => void;
}) {
  const { t } = useI18n();
  const pages = Math.max(1, Math.ceil(total / pageSize));
  return (
    <nav className="flex items-center justify-end gap-2" aria-label="Pagination">
      <span className="text-sm text-muted-foreground">
        {page} {t("pager.of")} {pages}
      </span>
      <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => onPage(page - 1)}>
        {t("pager.previous")}
      </Button>
      <Button variant="outline" size="sm" disabled={page >= pages} onClick={() => onPage(page + 1)}>
        {t("pager.next")}
      </Button>
    </nav>
  );
}
