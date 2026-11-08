'use client';

// Adapted from Motion Primitives: https://motion-primitives.com/docs/transition-panel
// Upstream: github.com/ibelick/motion-primitives/components/core/transition-panel.tsx
// Uses local CSS instead of Tailwind; adds a motionless preference path.
import { forwardRef, type ReactNode } from 'react';
import { AnimatePresence, motion, useIsPresent, type Transition, type Variant } from 'motion/react';
import { useMotionPreference } from './use-motion-preference';

type TransitionPanelProps = {
  children: React.ReactNode[];
  activeIndex: number;
  className?: string;
  transition?: Transition;
  variants?: { enter: Variant; center: Variant; exit: Variant };
  // Reserve the largest variant's natural height (for non-interactive captions).
  // All variants remain mounted; do not use with duplicate IDs or form fields.
  size?: 'content' | 'largest';
};

const defaultVariants = {
  enter: { opacity: 0 },
  center: { opacity: 1 },
  exit: { opacity: 0, transition: { duration: 0.08 } },
};

const PanelFrame = forwardRef<HTMLDivElement, {
  children: ReactNode;
  variants: NonNullable<TransitionPanelProps['variants']>;
  transition: Transition;
}>(function PanelFrame({ children, variants, transition }, ref) {
  const present = useIsPresent();
  return <motion.div ref={ref} aria-hidden={!present || undefined} inert={!present || undefined}
    initial="enter" animate="center" exit="exit" variants={variants} transition={transition}
  >{children}</motion.div>;
});

export function TransitionPanel({ children, activeIndex, className, transition, variants, size = 'content' }: TransitionPanelProps) {
  const reducedMotion = useMotionPreference();
  if (size === 'largest') return <div className={className} style={{ display: 'grid', minWidth: 0 }}>
    {children.map((child, index) => <motion.div
      key={index}
      data-panel-active={index === activeIndex || undefined}
      aria-hidden={index !== activeIndex || undefined}
      inert={index !== activeIndex || undefined}
      style={{ gridArea: '1 / 1', minWidth: 0, visibility: index === activeIndex ? 'visible' : 'hidden' }}
      initial={false}
      animate={{ opacity: index === activeIndex ? 1 : 0 }}
      transition={{ duration: reducedMotion ? 0 : 0.14 }}
    >{child}</motion.div>)}
  </div>;
  if (reducedMotion) return <div className={className}>{children[activeIndex]}</div>;

  return <div className={className} style={{ position: 'relative' }}>
    {/* Outgoing content leaves normal flow as the incoming panel mounts in the
        same commit. Never insert the empty frame caused by sequential exits. */}
    <AnimatePresence initial={false} mode="popLayout">
      <PanelFrame
        key={activeIndex}
        variants={variants ?? defaultVariants}
        transition={transition ?? { duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
      >{children[activeIndex]}</PanelFrame>
    </AnimatePresence>
  </div>;
}
