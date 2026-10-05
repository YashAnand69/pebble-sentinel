import { useEffect } from "react";
export function useScrollReveals(reduced: boolean, refreshToken: number) {
  useEffect(() => {
    const elements = Array.from(
      document.querySelectorAll<HTMLElement>(
        ".section-heading, .decision-card, .pipeline article, .use-case-grid article, .mission-card, .console, .evidence-results, .limits, .ecosystem-cards > a, .install > div",
      ),
    );
    if (reduced || typeof IntersectionObserver === "undefined") {
      elements.forEach((element) => {
        element.dataset.revealState = "shown";
      });
      return;
    }
    let observer: IntersectionObserver | undefined;
    try {
      observer = new IntersectionObserver(
        (entries) => {
          entries.forEach((entry) => {
            if (!entry.isIntersecting) return;
            (entry.target as HTMLElement).dataset.revealState = "shown";
            observer?.unobserve(entry.target);
          });
        },
        { threshold: 0.1, rootMargin: "0px 0px -16px 0px" },
      );
      elements.forEach((element) => {
        element.classList.add("scroll-reveal");
        if (element.dataset.revealState === "shown") return;
        const siblingIndex = Array.from(
          element.parentElement?.children ?? [],
        ).indexOf(element);
        element.style.setProperty(
          "--reveal-delay",
          `${Math.max(0, siblingIndex % 4) * 65}ms`,
        );
        if (element.getBoundingClientRect().top < window.innerHeight - 24) {
          element.dataset.revealState = "shown";
        } else {
          element.dataset.revealState = "pending";
          observer?.observe(element);
        }
      });
    } catch {
      observer?.disconnect();
      elements.forEach((element) => {
        element.dataset.revealState = "shown";
      });
    }
    return () => {
      observer?.disconnect();
      elements.forEach((element) => {
        if (element.dataset.revealState === "pending")
          delete element.dataset.revealState;
      });
    };
  }, [reduced, refreshToken]);
}
