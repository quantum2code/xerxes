# Xerxes frontend

Next.js App Router + React + Base UI. The frontend runs on port **3001**; the existing Express server stays on **3000**.

```sh
cd app
npm install
npm run dev
```

Run the backend separately using the instructions in `../server/README.md`. Open http://localhost:3001.

For a different backend origin, copy `.env.example` to `.env.local` and set `ANALYSIS_API_URL`. This is server-only. Requests pass through a bounded, no-store Next.js route; no CORS changes or browser-side provider credentials are needed.

```sh
npm run typecheck
npm run build
npm test
npm start
```

## UI structure

- `src/components/ui/primitives.tsx`: styled Base UI Button, Input, and Popover primitives.
- `src/components/analysis/workspace.tsx`: input, URL overview, assessment, and request states.
- `src/components/analysis/detector-card.tsx`: reusable detector cards with expandable evidence.
- `src/lib/analysis.ts`: frontend contract and validation.
- `src/app/globals.css`: charcoal/gold surfaces, tactile buttons, responsive layout, reduced-motion support.
- `src/app/interactions.css`: interaction timing, accessible contrast, evidence expansion, and container-width responsive refinements.
- `src/app/atmosphere.css`: static gold horizon, signal-stack lighting, and responsive diagram styling.
- `src/app/evidence-popover.css`: raised hover states and floating evidence expansions that preserve every card's grid footprint. Details open on hover intent or click/keyboard activation, stay within the viewport, and close with Escape, outside interaction, or the close button.
- `src/components/analysis/signal-diagram.tsx`: keyboard/touch/hover-accessible SVG exploration of the five checks. Plates paint bottom-to-top, while hit areas and keyboard order stay top-to-bottom. Before analysis it is an illustrative check preview; after analysis it displays real metrics and statuses. Loading is indeterminate, never fabricated per-check progress.
- `src/lib/signal-state.ts`: maps module diagnostics and assessment evidence to diagram labels and colors. Red requires a backend high-severity finding explicitly tied to that module; amber indicates review/warning. Incomplete/unconfigured checks remain distinct, and completed means checked—not safe. The most significant layer is selected on completion.

Diagram name, status, and explanation share one caption. Its variants occupy the same grid cell, reserving their largest natural height so layer selection cannot resize the assessment; inactive variants are invisible, inert, and hidden from assistive technology. Other panels mount incoming content immediately with outgoing panels removed from normal flow, avoiding exit-before-enter collapse frames. Regression tests sample card dimensions across animation frames at desktop, tablet, and mobile widths.
- `src/components/motion-primitives/`: adapted [Motion Primitives](https://motion-primitives.com) Transition Panel, Text Morph, and Tilt components, using Motion and local CSS rather than Tailwind. All have explicit reduced-motion paths.

Micro-interactions draw on the icon-swap, panel-reveal, and skeleton-to-content patterns shown at [transitions.dev](https://transitions.dev). No Pro assets or implementation code from that site are bundled. The external portfolio moodboard is inspiration only; it does not replace this application's dark palette or docked layout.

Scan state transitions are short and interruptible; model scores and risk levels are never tweened through invented intermediate values. Cancel stops waiting in the browser and aborts its request; upstream server work may already have started and is not guaranteed to stop. On mobile, completion focuses the report and scrolls it into view, without smooth scrolling when reduced motion is requested.

No example findings are presented as real results. The initial state is deliberately empty. Incomplete checks are not treated as passed. Model scores are not overall safety scores. Google attribution is displayed only for a matching Google Safe Browsing result.

The UI does not persist reports, load target favicons, or automatically visit submitted URLs. URLs can still contain sensitive data; configured backend providers may receive them. Google Fonts is currently used for typography, with local system fallbacks.
