"use client";

import React, { useEffect, useRef } from "react";

const VIDEO_URL =
  "https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260729_102822_0e6c87e8-c141-4744-bf32-ad30db296371.mp4";

export function BackgroundVideo() {
  const videoRef = useRef<HTMLVideoElement | null>(null);

  useEffect(() => {
    let animId: number;
    let targetProgress = 0;
    let smoothedProgress = 0;

    const handleScroll = () => {
      const scrollY = window.scrollY;
      const maxScroll = Math.max(
        document.documentElement.scrollHeight - window.innerHeight,
        1
      );
      targetProgress = Math.min(Math.max(scrollY / maxScroll, 0), 1);
    };

    const updateFrame = () => {
      smoothedProgress += (targetProgress - smoothedProgress) * 0.12;
      const video = videoRef.current;
      if (video && video.duration && !isNaN(video.duration)) {
        const targetTime = smoothedProgress * (video.duration - 0.05);
        if (Math.abs(video.currentTime - targetTime) > 0.03) {
          video.currentTime = targetTime;
        }
      }
      animId = requestAnimationFrame(updateFrame);
    };

    window.addEventListener("scroll", handleScroll, { passive: true });
    handleScroll();
    animId = requestAnimationFrame(updateFrame);

    return () => {
      window.removeEventListener("scroll", handleScroll);
      cancelAnimationFrame(animId);
    };
  }, []);

  return (
    <div className="fixed inset-0 z-0 bg-[#0a0a0a] overflow-hidden pointer-events-none">
      <video
        ref={videoRef}
        src={VIDEO_URL}
        muted
        playsInline
        preload="auto"
        className="w-full h-full object-cover opacity-50"
      />
      {/* Dark cybersecurity overlay and vignette so UI content is always readable */}
      <div className="absolute inset-0 bg-[#0a0a0a]/75 backdrop-blur-[1px]" />
    </div>
  );
}
