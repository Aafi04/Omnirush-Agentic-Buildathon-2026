# AgentTrace visual QA report

This report records the before/after audit for the flagship frontend transformation. The
baseline screenshots were captured from `main` at `b46ef2a` in a detached worktree. The
after screenshots were captured from `feat/agenttrace-flagship-redesign` after the
production build and the real Chromium suite. Both runs used the same synthetic forensic
recording and the same Playwright viewport matrix.

## Screenshot evidence

| Viewport | Before | After |
| --- | --- | --- |
| 1440 × 1000 desktop | [before desktop](visual-qa/before-desktop.png) | [after desktop](visual-qa/after-desktop.png) |
| 768 × 1024 tablet | [before tablet](visual-qa/before-tablet.png) | [after tablet](visual-qa/after-tablet.png) |
| 390 × 844 mobile | [before mobile](visual-qa/before-mobile.png) | [after mobile](visual-qa/after-mobile.png) |

The captures are full-page screenshots of the loaded synthetic investigation. They include
the overview, policy replay, differences, timeline, evidence inspector, findings, coverage,
and report sections rather than a static marketing mockup.

## Concrete visual comparison

| Criterion | Before | After |
| --- | --- | --- |
| First 15-second comprehension | A compact hero and a mostly uniform stack of panels; the purpose and workflow were easy to miss. | The hero states “Forensic replay for autonomous agents”, scopes the six rules, and exposes the `Load → Inspect → Replay` workflow before the first trace is loaded. |
| Policy replay | Baseline and strict were text-heavy definition-list cards. | A data-driven decision-flow visualization, semantic distribution bars, independent intervention counts, and evidence-linked transition rows make the intervention boundary visible immediately. |
| Timeline | Flat rows with limited visual grouping. | Connected chronological rail, event-type icons, source-order indices, decision pills, selected state, search, and filter controls preserve density while adding scanability. |
| Evidence | Payload-first inspector with metadata mixed into the panel. | Context-first inspector with event/call identifiers, copy controls for safe IDs, policy explanation, coverage status, linked events, and a bounded sanitized payload excerpt. |
| Findings and coverage | Long collections with similar visual weight. | Rule findings, policy interventions, unknown coverage, and integrity warnings have separate semantic sections, labels, counters, and progressive disclosure. |
| Mobile | The two-column workbench stacked, but the hierarchy and controls were visually compressed. | Replay stages stack intentionally, controls become full-width, the evidence inspector follows the timeline, and the same workflow remains legible at 390px without horizontal overflow. |

## Accessibility and motion audit

- Real Chromium E2E: **5 passed**.
- Axe-core serious/critical violations: **0**.
- Keyboard path verified: Explore demo, replay policy selector, visible focus treatment,
  section navigation, and report anchor.
- Event identity remains keyboard-addressable and linked findings/differences focus the
  corresponding timeline event.
- Status, loading, error, export, and copy feedback use live regions where appropriate.
- Payload and evidence values remain React text nodes; no untrusted trace value is rendered
  as executable HTML.
- `prefers-reduced-motion: reduce` disables the spinner animation and transitions. There is
  no perpetual decorative animation.
- No remote fonts, analytics, third-party runtime assets, or new production dependencies
  were introduced.

## Bundle and performance measurements

The existing baseline build and the redesign build were both measured by Vite on the same
machine and dependency lockfile.

| Asset | Baseline raw | Baseline gzip | Redesign raw | Redesign gzip | Change gzip |
| --- | ---: | ---: | ---: | ---: | ---: |
| JavaScript | 206.65 kB | 64.76 kB | 228.86 kB | 69.94 kB | +5.18 kB |
| CSS | 14.31 kB | 4.16 kB | 35.02 kB | 8.06 kB | +3.90 kB |

The increase is the cost of the new information hierarchy, inline icon system, policy
visualization, responsive states, and accessibility treatments. It remains a single small
frontend bundle, adds no runtime dependency, and avoids per-event animation or remote asset
requests. The final real-browser suite confirmed no layout overflow at desktop, tablet, or
mobile widths.

## Verification commands

Run from the repository root:

```sh
python scripts/test.py
npm run build
npm run e2e
```

The final branch verification recorded 256 backend tests, 35 frontend tests, a successful
TypeScript check, a successful production build, and 5 Chromium E2E tests. Docker was not
run on the Windows host; the existing Linux GitHub CI/Docker workflow remains unchanged and
should be the final merge gate.

## Design review conclusion

The redesign is visually and behaviorally ready for review on the feature branch. It is safe
to merge after the Linux Docker/CI workflow passes for the final commit. No backend modules,
forensic rules, importer validation, policy semantics, report bytes, API contracts, or
deployment configuration were changed.
