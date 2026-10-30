import React from "react";

export function SkeletonBox({ className = "h-4 w-full" }: { className?: string }) {
  return (
    <div
      className={`animate-pulse rounded bg-slate-200/80 ${className}`}
      aria-hidden="true"
    />
  );
}

export function SkeletonCard() {
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-6 shadow-xs space-y-4">
      <div className="flex items-center justify-between">
        <SkeletonBox className="h-5 w-1/3" />
        <SkeletonBox className="h-5 w-16" />
      </div>
      <SkeletonBox className="h-4 w-full" />
      <SkeletonBox className="h-4 w-5/6" />
      <div className="pt-2 flex gap-3">
        <SkeletonBox className="h-8 w-24 rounded-md" />
        <SkeletonBox className="h-8 w-24 rounded-md" />
      </div>
    </div>
  );
}

export function SkeletonTable({ rows = 4 }: { rows?: number }) {
  return (
    <div className="rounded-lg border border-slate-200 bg-white overflow-hidden shadow-xs">
      <div className="border-b border-slate-200 bg-slate-50 px-6 py-3 flex gap-4">
        <SkeletonBox className="h-4 w-28" />
        <SkeletonBox className="h-4 w-48" />
        <SkeletonBox className="h-4 w-20 ml-auto" />
      </div>
      <div className="divide-y divide-slate-100 p-2">
        {Array.from({ length: rows }).map((_, i) => (
          <div key={i} className="px-4 py-3 flex items-center justify-between gap-4">
            <div className="space-y-1 w-1/3">
              <SkeletonBox className="h-4 w-32" />
              <SkeletonBox className="h-3 w-20" />
            </div>
            <SkeletonBox className="h-4 w-1/3 hidden sm:block" />
            <SkeletonBox className="h-6 w-20 rounded" />
          </div>
        ))}
      </div>
    </div>
  );
}
