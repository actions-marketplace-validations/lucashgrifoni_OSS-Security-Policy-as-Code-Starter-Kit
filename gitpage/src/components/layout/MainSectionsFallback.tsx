/**
 * Minimal placeholder while below-the-fold chunk loads (avoids layout jump).
 */
export function MainSectionsFallback() {
  return <div className="min-h-[30vh] w-full bg-transparent" aria-hidden />;
}
