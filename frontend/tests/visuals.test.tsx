import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { DecisionPill, Icon, MetricCard, PolicyFlow, PolicySummaryCard } from '../src/visuals';

const baselineCounts = { allow: 1, review: 2, block: 0 } as const;
const strictCounts = { allow: 0, review: 1, block: 2 } as const;

describe('redesign visual primitives', () => {
  it('gives named icons an accessible name and keeps decorative SVGs out of the tab sequence', () => {
    const { container, rerender } = render(<Icon name="shield-check" label="Policy verified" />);

    const namedIcon = screen.getByRole('img', { name: 'Policy verified' });
    expect(namedIcon).toHaveAttribute('viewBox', '0 0 24 24');
    expect(namedIcon).toHaveAttribute('focusable', 'false');
    expect(namedIcon.querySelector('title')).toHaveTextContent('Policy verified');

    rerender(<Icon name="shield-check" aria-hidden="true" />);
    const decorativeIcon = container.querySelector('svg');
    expect(decorativeIcon).toHaveAttribute('aria-hidden', 'true');
    expect(decorativeIcon).not.toHaveAttribute('role');
  });

  it('renders decision labels and preserves an explicit zero count', () => {
    const { container } = render(
      <div>
        <DecisionPill decision="allow" count={0} />
        <DecisionPill decision="review" count={2} />
        <DecisionPill decision="block" count={1} />
      </div>,
    );

    const pills = container.querySelectorAll('[data-decision]');
    expect(pills).toHaveLength(3);
    expect(pills[0]).toHaveAttribute('aria-label', 'Allow: 0');
    expect(pills[1]).toHaveAttribute('aria-label', 'Review: 2');
    expect(pills[2]).toHaveAttribute('aria-label', 'Block: 1');
    expect(pills[0]).toHaveTextContent(/Allow\s*0/);
    expect(pills[1]).toHaveTextContent(/Review\s*2/);
    expect(pills[2]).toHaveTextContent(/Block\s*1/);
  });

  it('labels metric cards by their heading and does not replace a zero value', () => {
    render(
      <MetricCard
        label="Recorded events"
        value={0}
        detail={<span>Exact source order</span>}
        icon="activity"
        tone="accent"
      />,
    );

    const metric = screen.getByRole('article', { name: 'Recorded events' });
    expect(metric).toHaveAttribute('data-value', '0');
    expect(within(metric).getByRole('heading', { name: 'Recorded events' })).toBeVisible();
    expect(metric).toHaveTextContent('0');
    expect(metric).toHaveTextContent('Exact source order');
  });

  it('exposes independent policy decision and intervention counts', () => {
    render(
      <PolicySummaryCard
        policy={{ policy_id: 'baseline', version: '2.0' }}
        counts={baselineCounts}
        interventions={{ rule_triggered: 3, unknown_action: 2 }}
        description="The same recording under the baseline policy."
      />,
    );

    const card = screen.getByRole('article', { name: 'baseline · v2.0' });
    const decisions = within(card).getByRole('list', { name: 'Policy decision counts' });
    expect(decisions).toHaveTextContent(/Allow\s*1/);
    expect(decisions).toHaveTextContent(/Review\s*2/);
    expect(decisions).toHaveTextContent(/Block\s*0/);
    expect(card.querySelector('[aria-label="Allow decisions: 1"]')).toBeInTheDocument();
    expect(card.querySelector('[aria-label="Review decisions: 2"]')).toBeInTheDocument();
    expect(card.querySelector('[aria-label="Block decisions: 0"]')).toBeInTheDocument();
    expect(card).toHaveTextContent(/Rule-triggered interventions\s*3/);
    expect(card).toHaveTextContent(/Unknown-action interventions\s*2/);
    expect(card).toHaveTextContent('Intervention categories can overlap.');
  });

  it('announces policy flow totals and per-decision distributions', () => {
    render(
      <PolicyFlow
        baseline={baselineCounts}
        strict={strictCounts}
        heading="Same-trace policy comparison"
        description="Two deterministic readings of one recording."
      />,
    );

    const flow = screen.getByRole('region', { name: 'Same-trace policy comparison' });
    const baselineChart = within(flow).getByRole('img', {
      name: 'Baseline: Allow 1, Review 2, Block 0; 3 total decisions',
    });
    const strictChart = within(flow).getByRole('img', {
      name: 'Strict: Allow 0, Review 1, Block 2; 3 total decisions',
    });

    expect(baselineChart).toHaveAttribute('data-total', '3');
    expect(strictChart).toHaveAttribute('data-total', '3');
    expect(baselineChart.querySelector('[data-decision="allow"]')).toHaveAttribute('data-count', '1');
    expect(baselineChart.querySelector('[data-decision="review"]')).toHaveAttribute('data-count', '2');
    expect(baselineChart.querySelector('[data-decision="block"]')).toHaveAttribute('data-count', '0');
    expect(within(flow).getByRole('list', { name: 'Baseline decision breakdown' })).toHaveTextContent(/Allow\s*1/);
    expect(within(flow).getByRole('list', { name: 'Strict decision breakdown' })).toHaveTextContent(/Block\s*2/);
  });

  it('makes an empty distribution explicit instead of inventing a decision', () => {
    render(<PolicyFlow baseline={{ allow: 0, review: 0, block: 0 }} strict={strictCounts} />);

    const flow = screen.getByRole('region', { name: 'Policy decision flow' });
    const baselineChart = within(flow).getByRole('img', {
      name: 'Baseline: Allow 0, Review 0, Block 0; 0 total decisions',
    });
    expect(baselineChart).toHaveAttribute('data-total', '0');
    expect(within(flow).getByText('No decisions')).toBeVisible();
  });

  it('keeps button and link wrappers keyboard reachable when they contain an icon', async () => {
    const user = userEvent.setup();
    render(
      <nav aria-label="Visual actions">
        <button type="button" aria-label="Inspect policy">
          <Icon name="search" aria-hidden="true" />
        </button>
        <a href="#policy-details">
          <Icon name="arrow-right" aria-hidden="true" />
          Policy details
        </a>
      </nav>,
    );

    const button = screen.getByRole('button', { name: 'Inspect policy' });
    const link = screen.getByRole('link', { name: 'Policy details' });
    expect(button).not.toHaveAttribute('tabindex', '-1');
    expect(link).not.toHaveAttribute('tabindex', '-1');
    button.focus();
    await user.tab();
    expect(link).toHaveFocus();
  });

  it('renders SVG- and payload-like strings as text rather than executable markup', () => {
    const payload = '<svg onload="window.__visualPayloadExecuted=true"><script>window.__visualPayloadExecuted=true</script><text>payload</text></svg>';
    render(
      <div>
        <MetricCard label="Payload preview" value={payload} detail={payload} />
        <DecisionPill decision="review" label={payload} count={0} />
        <PolicySummaryCard policy="baseline" counts={baselineCounts} description={payload} />
      </div>,
    );

    const metric = screen.getByRole('article', { name: 'Payload preview' });
    expect(metric.textContent).toContain(payload);
    expect(document.querySelector('script')).toBeNull();
    expect(document.querySelector('svg[onload]')).toBeNull();
    expect(document.querySelector('svg text')).toBeNull();
    expect(document.querySelector('[onload]')).toBeNull();
  });
});
