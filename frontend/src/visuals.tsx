import { useId, type ComponentPropsWithoutRef, type CSSProperties, type ReactNode } from 'react';
import type { Decision, PolicyRun } from './types';

/** The decision order is shared by summary cards, legends, and policy flow bars. */
export const DECISIONS = ['allow', 'review', 'block'] as const satisfies readonly Decision[];

export type DecisionCounts = Pick<PolicyRun['counts'], Decision>;

/**
 * Metadata is intentionally compatible with both the backend's snake_case fields
 * and the camelCase names commonly used by view-models.
 */
export interface InterventionMetadata {
  rule_triggered?: number;
  unknown_action?: number;
  ruleTriggered?: number;
  unknownAction?: number;
}

export const ICON_NAMES = [
  'activity',
  'alert',
  'alert-triangle',
  'arrow-right',
  'ban',
  'check',
  'chevron-down',
  'chevron-right',
  'clock',
  'file',
  'fingerprint',
  'layers',
  'lock',
  'search',
  'shield',
  'shield-alert',
  'shield-check',
  'terminal',
  'x',
  'zap',
] as const;

export type IconName = (typeof ICON_NAMES)[number];

export type IconProps = Omit<ComponentPropsWithoutRef<'svg'>, 'children' | 'title'> & {
  name: IconName;
  /** A short accessible name. Omit for a decorative icon. */
  label?: string;
  /** Alias for label when the icon is used as an image-like affordance. */
  title?: string;
  size?: number;
};

type IconGraphic = ReactNode;

const ICON_GRAPHICS: Record<IconName, IconGraphic> = {
  activity: (
    <>
      <path d="M3 12h3l2-7 4 14 2-7h5" />
      <path d="M3 19h18" opacity=".35" />
    </>
  ),
  alert: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 8v5" />
      <path d="M12 16h.01" />
    </>
  ),
  'alert-triangle': (
    <>
      <path d="m12 3 9 17H3L12 3Z" />
      <path d="M12 9v4" />
      <path d="M12 16h.01" />
    </>
  ),
  'arrow-right': (
    <>
      <path d="M4 12h15" />
      <path d="m14 6 6 6-6 6" />
    </>
  ),
  ban: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="m5.6 5.6 12.8 12.8" />
    </>
  ),
  check: <path d="m5 12 4 4L19 6" />,
  'chevron-down': <path d="m6 9 6 6 6-6" />,
  'chevron-right': <path d="m9 6 6 6-6 6" />,
  clock: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3 2" />
    </>
  ),
  file: (
    <>
      <path d="M6 3h8l4 4v14H6z" />
      <path d="M14 3v5h5M9 13h6M9 17h6" />
    </>
  ),
  fingerprint: (
    <>
      <path d="M12 11a2 2 0 0 1 2 2v2" />
      <path d="M8 15v-2a4 4 0 0 1 8 0v4" />
      <path d="M5 15v-2a7 7 0 0 1 14 0v2" />
      <path d="M8 20c-1.3-1.4-2-3.2-2-5M12 15v5M16 15v2a4 4 0 0 1-1 2.7" />
    </>
  ),
  layers: (
    <>
      <path d="m12 3 9 5-9 5-9-5 9-5Z" />
      <path d="m3 12 9 5 9-5M3 16l9 5 9-5" />
    </>
  ),
  lock: (
    <>
      <rect x="5" y="10" width="14" height="10" rx="2" />
      <path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3" />
    </>
  ),
  search: (
    <>
      <circle cx="10.5" cy="10.5" r="6.5" />
      <path d="m16 16 5 5" />
    </>
  ),
  shield: <path d="M12 3 20 6v5c0 5-3.4 8.3-8 10-4.6-1.7-8-5-8-10V6l8-3Z" />,
  'shield-alert': (
    <>
      <path d="M12 3 20 6v5c0 5-3.4 8.3-8 10-4.6-1.7-8-5-8-10V6l8-3Z" />
      <path d="M12 8v4M12 15h.01" />
    </>
  ),
  'shield-check': (
    <>
      <path d="M12 3 20 6v5c0 5-3.4 8.3-8 10-4.6-1.7-8-5-8-10V6l8-3Z" />
      <path d="m8 12 2.5 2.5L16 9" />
    </>
  ),
  terminal: (
    <>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="m7 9 3 3-3 3M13 15h4" />
    </>
  ),
  x: (
    <>
      <path d="m6 6 12 12M18 6 6 18" />
    </>
  ),
  zap: <path d="m13 2-9 12h7l-1 8 9-12h-7l1-8Z" />,
};

/**
 * Small, dependency-free inline icon set. Unknown names cannot reach this
 * component because IconName is a finite union and the glyph map is exhaustive.
 */
export function Icon({ name, size = 18, label, title, ...svgProps }: IconProps) {
  const titleId = useId();
  const suppliedAriaLabel = typeof svgProps['aria-label'] === 'string' ? svgProps['aria-label'] : undefined;
  const accessibleName = label ?? title ?? suppliedAriaLabel;
  const hasGeneratedTitle = Boolean(label ?? title);
  const isExplicitlyHidden = svgProps['aria-hidden'];

  return (
    <svg
      {...svgProps}
      width={svgProps.width ?? size}
      height={svgProps.height ?? size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      focusable="false"
      role={svgProps.role ?? (accessibleName ? 'img' : undefined)}
      aria-hidden={isExplicitlyHidden ?? (accessibleName ? undefined : true)}
      aria-labelledby={hasGeneratedTitle ? titleId : svgProps['aria-labelledby']}
    >
      {hasGeneratedTitle && <title id={titleId}>{label ?? title}</title>}
      {ICON_GRAPHICS[name]}
    </svg>
  );
}

const DECISION_LABELS: Record<Decision, string> = {
  allow: 'Allow',
  review: 'Review',
  block: 'Block',
};

const DECISION_ICONS: Record<Decision, IconName> = {
  allow: 'check',
  review: 'alert',
  block: 'ban',
};

function cx(...classes: Array<string | false | null | undefined>): string | undefined {
  const value = classes.filter(Boolean).join(' ');
  return value || undefined;
}

/** A compact, consistently coloured representation of a policy decision. */
export interface DecisionPillProps extends Omit<ComponentPropsWithoutRef<'span'>, 'children'> {
  decision: Decision;
  /** Overrides the human-readable decision label while retaining its tone. */
  label?: string;
  /** Optional count displayed after the decision label. Zero is intentionally shown. */
  count?: number;
  showIcon?: boolean;
}

export function DecisionPill({ decision, label, count, showIcon = true, className, ...spanProps }: DecisionPillProps) {
  const decisionLabel = label ?? DECISION_LABELS[decision];
  const accessibleLabel = count === undefined ? decisionLabel : `${decisionLabel}: ${count}`;

  return (
    <span
      {...spanProps}
      className={cx(
        'visual-decision-pill',
        `visual-decision-pill--${decision}`,
        'motion-safe:transition-colors',
        'motion-reduce:transition-none',
        className,
      )}
      data-decision={decision}
      aria-label={spanProps['aria-label'] ?? accessibleLabel}
    >
      {showIcon && <Icon name={DECISION_ICONS[decision]} size={14} aria-hidden="true" />}
      <span className="visual-decision-pill__label">{decisionLabel}</span>
      {count !== undefined && <span className="visual-decision-pill__count">{count}</span>}
    </span>
  );
}

export type MetricTone = 'neutral' | 'allow' | 'review' | 'block' | 'accent';

export interface MetricCardProps extends Omit<ComponentPropsWithoutRef<'article'>, 'children'> {
  label: string;
  value: number | string;
  detail?: ReactNode;
  icon?: IconName;
  tone?: MetricTone;
}

/** A data-only metric tile; it never hides a zero or substitutes placeholder data. */
export function MetricCard({ label, value, detail, icon, tone = 'neutral', className, ...articleProps }: MetricCardProps) {
  const headingId = useId();
  const labelledBy = articleProps['aria-labelledby'] ?? headingId;

  return (
    <article
      {...articleProps}
      className={cx(
        'visual-metric-card',
        `visual-metric-card--${tone}`,
        'motion-safe:transition-colors',
        'motion-reduce:transition-none',
        className,
      )}
      aria-labelledby={labelledBy}
      data-value={String(value)}
    >
      <header className="visual-metric-card__header">
        <h3 id={headingId}>{label}</h3>
        {icon && <Icon name={icon} size={16} aria-hidden="true" />}
      </header>
      <p className="visual-metric-card__value">{value}</p>
      {detail !== undefined && <div className="visual-metric-card__detail">{detail}</div>}
    </article>
  );
}

export type PolicyReference =
  | string
  | { policy_id: string; version?: string | number }
  | { id: string; version?: string | number }
  | { name: string; version?: string | number };

export interface PolicySummaryCardProps extends Omit<ComponentPropsWithoutRef<'article'>, 'children'> {
  policy: PolicyReference;
  counts: DecisionCounts;
  interventions?: InterventionMetadata;
  /** Alias for integrations that keep metadata separate from the policy run. */
  interventionMetadata?: InterventionMetadata;
  /** Direct aliases are useful when a caller already has flattened metadata. */
  ruleTriggered?: number;
  unknownAction?: number;
  description?: ReactNode;
}

function safeCount(value: number | undefined): number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : 0;
}

function policyDetails(policy: PolicyReference): { name: string; version?: string | number } {
  if (typeof policy === 'string') return { name: policy };
  if ('policy_id' in policy) return { name: policy.policy_id, version: policy.version };
  if ('id' in policy) return { name: policy.id, version: policy.version };
  return { name: policy.name, version: policy.version };
}

function interventionValue(
  metadata: InterventionMetadata | undefined,
  snake: 'rule_triggered' | 'unknown_action',
  camel: 'ruleTriggered' | 'unknownAction',
  direct: number | undefined,
): number {
  return safeCount(metadata?.[snake] ?? metadata?.[camel] ?? direct);
}

/**
 * A policy-level summary that keeps decisions and intervention categories
 * separate. Categories can overlap, so they are rendered as independent rows.
 */
export function PolicySummaryCard({
  policy,
  counts,
  interventions,
  interventionMetadata,
  ruleTriggered,
  unknownAction,
  description,
  className,
  ...articleProps
}: PolicySummaryCardProps) {
  const headingId = useId();
  const details = policyDetails(policy);
  const metadata = interventions ?? interventionMetadata;
  const labelledBy = articleProps['aria-labelledby'] ?? headingId;
  const ruleInterventions = interventionValue(metadata, 'rule_triggered', 'ruleTriggered', ruleTriggered);
  const unknownInterventions = interventionValue(metadata, 'unknown_action', 'unknownAction', unknownAction);

  return (
    <article
      {...articleProps}
      className={cx(
        'visual-policy-summary-card',
        'motion-safe:transition-colors',
        'motion-reduce:transition-none',
        className,
      )}
      aria-labelledby={labelledBy}
      data-policy-id={details.name}
      data-policy-version={details.version === undefined ? undefined : String(details.version)}
    >
      <header className="visual-policy-summary-card__header">
        <div>
          <p className="visual-policy-summary-card__eyebrow">Policy replay</p>
          <h3 id={headingId}>{details.name}{details.version !== undefined && ` · v${details.version}`}</h3>
        </div>
        <Icon name="shield-check" size={20} aria-hidden="true" />
      </header>
      {description !== undefined && <p className="visual-policy-summary-card__description">{description}</p>}

      <div className="visual-policy-summary-card__decisions" role="list" aria-label="Policy decision counts">
        {DECISIONS.map(decision => {
          const count = safeCount(counts[decision]);
          return (
            <div className="visual-policy-summary-card__decision" role="listitem" key={decision}>
              <DecisionPill decision={decision} />
              <strong aria-label={`${DECISION_LABELS[decision]} decisions: ${count}`}>{count}</strong>
            </div>
          );
        })}
      </div>

      <dl className="visual-policy-summary-card__interventions">
        <div>
          <dt>Rule-triggered interventions</dt>
          <dd>{ruleInterventions}</dd>
        </div>
        <div>
          <dt>Unknown-action interventions</dt>
          <dd>{unknownInterventions}</dd>
        </div>
      </dl>
      <p className="visual-policy-summary-card__note">Intervention categories can overlap.</p>
    </article>
  );
}

export interface PolicyFlowProps extends Omit<ComponentPropsWithoutRef<'section'>, 'children'> {
  baseline: DecisionCounts;
  strict: DecisionCounts;
  baselineLabel?: string;
  strictLabel?: string;
  heading?: string;
  description?: ReactNode;
}

function percentage(value: number, total: number): number {
  return total > 0 ? Math.round((value / total) * 1000) / 10 : 0;
}

function distributionLabel(label: string, counts: DecisionCounts, total: number): string {
  return `${label}: ${DECISIONS.map(decision => `${DECISION_LABELS[decision]} ${safeCount(counts[decision])}`).join(', ')}; ${total} total decisions`;
}

/**
 * Compares two policy distributions. Segment widths, totals, and percentages
 * are derived entirely from the numeric baseline/strict props.
 */
export function PolicyFlow({
  baseline,
  strict,
  baselineLabel = 'Baseline',
  strictLabel = 'Strict',
  heading = 'Policy decision flow',
  description,
  className,
  ...sectionProps
}: PolicyFlowProps) {
  const headingId = useId();
  const labelledBy = sectionProps['aria-labelledby'] ?? headingId;
  const stages = [
    { label: baselineLabel, counts: baseline },
    { label: strictLabel, counts: strict },
  ];

  const renderStage = ({ label, counts }: (typeof stages)[number]) => {
    const values = DECISIONS.map(decision => safeCount(counts[decision]));
    const total = values.reduce((sum, value) => sum + value, 0);
    const labelForChart = distributionLabel(label, counts, total);

    return (
      <article className="visual-policy-flow__stage" data-policy={label.toLowerCase()} key={label}>
        <header className="visual-policy-flow__stage-header">
          <h3>{label}</h3>
          <strong>{total}</strong>
          <span>decisions</span>
        </header>
        <div
          className="visual-policy-flow__bar"
          role="img"
          aria-label={labelForChart}
          data-total={String(total)}
        >
          {total > 0 ? (
            DECISIONS.map(decision => {
              const count = safeCount(counts[decision]);
              const share = percentage(count, total);
              const style: CSSProperties = { flexBasis: `${share}%` };
              return (
                <span
                  className={cx(
                    'visual-policy-flow__segment',
                    `visual-policy-flow__segment--${decision}`,
                    'motion-safe:transition-[flex-basis,opacity]',
                    'motion-reduce:transition-none',
                  )}
                  key={decision}
                  style={style}
                  data-decision={decision}
                  data-count={String(count)}
                  data-share={`${share}%`}
                  aria-hidden="true"
                />
              );
            })
          ) : (
            <span className="visual-policy-flow__empty" aria-hidden="true">No decisions</span>
          )}
        </div>
        <ul className="visual-policy-flow__breakdown" aria-label={`${label} decision breakdown`}>
          {DECISIONS.map(decision => {
            const count = safeCount(counts[decision]);
            return (
              <li key={decision}>
                <DecisionPill decision={decision} />
                <strong>{count}</strong>
                <span>{percentage(count, total)}%</span>
              </li>
            );
          })}
        </ul>
      </article>
    );
  };

  return (
    <section
      {...sectionProps}
      className={cx('visual-policy-flow', 'motion-reduce:animate-none', className)}
      aria-labelledby={labelledBy}
    >
      <header className="visual-policy-flow__header">
        <h2 id={headingId}>{heading}</h2>
        {description !== undefined && <p>{description}</p>}
      </header>
      <div className="visual-policy-flow__stages">
        {renderStage(stages[0])}
        <div className="visual-policy-flow__connector" aria-hidden="true">
          <Icon name="arrow-right" size={20} />
        </div>
        {renderStage(stages[1])}
      </div>
    </section>
  );
}
