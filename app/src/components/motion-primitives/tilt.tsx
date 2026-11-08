'use client';

// Adapted from Motion Primitives: https://motion-primitives.com/docs/tilt
// Uses pointer events and the existing hydration-safe reduced-motion preference.
import { useRef, type PointerEvent, type ReactNode } from 'react';
import { motion, useMotionTemplate, useMotionValue, useSpring, useTransform } from 'motion/react';
import { useMotionPreference } from './use-motion-preference';

export function Tilt({ children, className, rotationFactor = 6 }: {
  children: ReactNode;
  className?: string;
  rotationFactor?: number;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const reducedMotion = useMotionPreference();
  const x = useMotionValue(0);
  const y = useMotionValue(0);
  const spring = { stiffness: 180, damping: 26, mass: 0.6 };
  const xSpring = useSpring(x, spring);
  const ySpring = useSpring(y, spring);
  const rotateX = useTransform(ySpring, [-0.5, 0.5], [rotationFactor, -rotationFactor]);
  const rotateY = useTransform(xSpring, [-0.5, 0.5], [-rotationFactor, rotationFactor]);
  const transform = useMotionTemplate`perspective(900px) rotateX(${rotateX}deg) rotateY(${rotateY}deg)`;

  function move(event: PointerEvent<HTMLDivElement>) {
    if (reducedMotion || event.pointerType !== 'mouse' || !ref.current) return;
    const rect = ref.current.getBoundingClientRect();
    x.set((event.clientX - rect.left) / rect.width - 0.5);
    y.set((event.clientY - rect.top) / rect.height - 0.5);
  }

  function reset() { x.set(0); y.set(0); }

  return <motion.div
    ref={ref}
    className={className}
    style={{ transform: reducedMotion ? 'none' : transform, transformStyle: 'preserve-3d' }}
    onPointerMove={move}
    onPointerLeave={reset}
    onPointerCancel={reset}
  >{children}</motion.div>;
}
