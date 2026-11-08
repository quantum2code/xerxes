'use client';

import { Button as BaseButton } from '@base-ui/react/button';
import { Popover } from '@base-ui/react/popover';
import { Input } from '@base-ui/react/input';
import { ArrowUpRight, X } from 'lucide-react';
import { useRef } from 'react';
import clsx from 'clsx';
import { TransitionPanel } from '@/components/motion-primitives/transition-panel';

export { Input };

export function IconSwap({ active, children }: { active: boolean; children: [React.ReactNode, React.ReactNode] }) {
  return <span className="icon-swap" aria-hidden="true"><TransitionPanel activeIndex={active ? 1 : 0} variants={{ enter: { opacity: 0, scale: 0.7, filter: 'blur(2px)' }, center: { opacity: 1, scale: 1, filter: 'blur(0px)' }, exit: { opacity: 0, scale: 0.8, transition: { duration: 0.08 } } }}>{children}</TransitionPanel></span>;
}

export function Button({ className, variant = 'secondary', ...props }: BaseButton.Props & { variant?: 'primary' | 'secondary' | 'icon' }) {
  return <BaseButton className={clsx('button', `button-${variant}`, className)} {...props} />;
}

export function EvidencePopover({ children, title, preview }: {
  children: React.ReactNode;
  title: string;
  preview?: React.ReactNode;
}) {
  const triggerRef = useRef<HTMLButtonElement>(null);
  return <Popover.Root>
    <div className="evidence">
      <Popover.Trigger ref={triggerRef} className="evidence-trigger" openOnHover delay={240} closeDelay={160}>
        View evidence <ArrowUpRight size={15} />
      </Popover.Trigger>
    </div>
    <Popover.Portal>
      <Popover.Positioner
        className="evidence-positioner"
        anchor={() => triggerRef.current?.closest('[data-evidence-card]') ?? null}
        side="bottom"
        align="start"
        sideOffset={({ anchor }) => -anchor.height - 4}
        alignOffset={-4}
        positionMethod="fixed"
        collisionPadding={12}
        collisionAvoidance={{ side: 'shift', align: 'shift', fallbackAxisSide: 'none' }}
      >
        <Popover.Popup className="evidence-popup">
          <div className="evidence-popup-header">
            <Popover.Title>{title}</Popover.Title>
            <Popover.Close className="button button-icon" aria-label="Close evidence"><X size={16} /></Popover.Close>
          </div>
          {preview && <div className="evidence-preview detector-body">{preview}</div>}
          <div className="evidence-content">{children}</div>
        </Popover.Popup>
      </Popover.Positioner>
    </Popover.Portal>
  </Popover.Root>;
}
