"use client";

import { Button } from "@/components/ui/button";
import { ChevronLeft, ChevronRight } from "lucide-react";

interface PaginationProps {
  offset: number;
  limit: number;
  hasMore: boolean;
  onPrevious: () => void;
  onNext: () => void;
}

export function Pagination({ offset, limit, hasMore, onPrevious, onNext }: PaginationProps) {
  const page = Math.floor(offset / limit) + 1;
  return (
    <div className="flex items-center justify-between px-4 py-3 border-t">
      <p className="text-sm text-muted-foreground">Page {page}</p>
      <div className="flex gap-2">
        <Button variant="outline" size="sm" onClick={onPrevious} disabled={offset === 0}>
          <ChevronLeft className="h-4 w-4 mr-1" /> Previous
        </Button>
        <Button variant="outline" size="sm" onClick={onNext} disabled={!hasMore}>
          Next <ChevronRight className="h-4 w-4 ml-1" />
        </Button>
      </div>
    </div>
  );
}
