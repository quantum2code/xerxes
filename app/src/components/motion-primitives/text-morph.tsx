'use client';

// Adapted from Motion Primitives: https://motion-primitives.com/docs/text-morph
// Upstream: github.com/ibelick/motion-primitives/components/core/text-morph.tsx
// Local CSS and reduced-motion support; used only for short action labels.
import { AnimatePresence, motion } from 'motion/react';
import { useId, useMemo } from 'react';
import { useMotionPreference } from './use-motion-preference';

export function TextMorph({ children, className }: { children: string; className?: string }) {
  const id = useId();
  const reducedMotion = useMotionPreference();
  const characters = useMemo(() => {
    const counts: Record<string, number> = {};
    return children.split('').map((char) => {
      const key = char.toLowerCase();
      counts[key] = (counts[key] || 0) + 1;
      return { id: `${id}-${key}-${counts[key]}`, label: char === ' ' ? '\u00a0' : char };
    });
  }, [children, id]);

  if (reducedMotion) return <span className={className}>{children}</span>;
  return <span className={className} aria-label={children} style={{ position: 'relative', display: 'inline-block' }}>
    <AnimatePresence initial={false} mode="popLayout">
      {characters.map((character) => <motion.span
        key={character.id}
        layoutId={character.id}
        aria-hidden="true"
        style={{ display: 'inline-block' }}
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        transition={{ type: 'spring', stiffness: 400, damping: 35, mass: 0.4 }}
      >{character.label}</motion.span>)}
    </AnimatePresence>
  </span>;
}
