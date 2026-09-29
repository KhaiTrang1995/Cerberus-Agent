'use client'

/**
 * Multi mute: the findings like the one being muted, in groups, for a person
 * to confirm. Opened from the Multi mute button next to every Mute.
 *
 * Everything the model wrote (its read of the seed, a group's title and why,
 * a row's why and quote) is labelled "AI suggestion" and rendered as plain
 * text. What is pre-ticked was decided by code, never by the model alone.
 */
import { useCallback, useState, type ReactNode } from 'react'
import { ChevronDown, ChevronRight, Loader2, RotateCcw } from 'lucide-react'
import { Modal } from '@/components/ui/Modal/Modal'
import { useToast } from '@/components/ui'
import { FeatureModelGate } from '@/components/shared/FeatureModelGate'
import { NodeIdCell } from '../RedZoneTables/nodeId'
import type { MutedNodesFocus } from '../MutedNodes/mutedNodes'
import { MuteButton } from './MuteButton'
import {
  cleanText, exclusionWords, groupHeading, isMutedOutcome, kindFindings, muteRuleKindFor, outcomeWords,
  REASON_WORDS, ROWS_PER_PAGE, verdictTooltip,
  type MultiMuteGroup, type MultiMuteMember, type MultiMuteOptions, type MultiMuteSeed,
} from './multiMuteModel'
import { useMultiMute, type ActivityEntry, type MultiMuteState } from './useMultiMute'
import styles from './MultiMuteModal.module.css'

export interface MultiMuteModalProps {
  projectId: string
  userId: string | null
  seed: MultiMuteSeed
  options: MultiMuteOptions
  /** Unmount the modal. */
  onDone: () => void
  /** Refresh the graph and every table. */
  notifyMuted: () => void
  onViewMuted?: (focus?: MutedNodesFocus) => void
  /** Open Mute Rules at a catalog kind. */
  onOpenMuteRules?: (kind: string) => void
}

const SEV_CLASS: Record<string, string> = {
  critical: styles.sevCritical,
  high: styles.sevHigh,
  medium: styles.sevMedium,
  low: styles.sevLow,
  info: styles.sevInfo,
}

const VERDICT_CLASS: Record<string, string> = {
  match: styles.verdictMatch,
  maybe: styles.verdictMaybe,
  no: styles.verdictNo,
}

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n.toLocaleString()} ${n === 1 ? one : many}`
}

function AiTag() {
  return <span className={styles.aiTag}>AI suggestion</span>
}

export function MultiMuteModal({
  projectId, userId, seed, options, onDone, notifyMuted, onViewMuted, onOpenMuteRules,
}: MultiMuteModalProps) {
  const toast = useToast()
  const mm = useMultiMute({ projectId, userId, seed, onStale: notifyMuted })
  const { phase, result } = mm

  /**
   * Close, then tell the page once: one refresh, the drawer closed if its
   * node went, and one toast for everything muted here.
   */
  const finish = useCallback((after?: () => void) => {
    if (mm.busy) return
    mm.cancelLoading()
    const summary = mm.closeSummary()
    onDone()
    if (summary.muted.length > 0) {
      notifyMuted()
      if (summary.seedMuted) options.onSeedMuted?.()
      options.onMuted?.(summary.muted)
      let message = `Muted ${plural(summary.muted.length, 'finding')}.`
      if (summary.workItems > 0) {
        message += ` ${plural(summary.workItems, 'CypherFix item')} will update ` +
          `${summary.triageRunLive ? 'after the run in progress' : 'at the next triage run'}.`
      }
      const focus: MutedNodesFocus = summary.batches.length === 1
        ? { token: summary.batches[0] }
        : { mutedVia: 'multi' }
      toast.addToast({
        type: 'success',
        message,
        ...(onViewMuted ? { action: { label: 'View muted', onClick: () => onViewMuted(focus) } } : {}),
      })
    }
    after?.()
  }, [mm, onDone, notifyMuted, options, toast, onViewMuted])

  let body: ReactNode
  let footer: ReactNode = null
  if (phase.kind === 'gate') {
    body = (
      <FeatureModelGate
        featureId="multi_mute"
        userId={userId}
        inline
        confirmLabel="Save and run"
        message={phase.message}
        onSaved={model => void mm.run({ model })}
        onCancel={() => (phase.back ? mm.backToResults() : finish())}
      />
    )
  } else if (phase.kind === 'loading') {
    const compared = result
      ? `Comparing with ${result.pool.total.toLocaleString()} ${kindFindings(result.seed.kind)}.`
      : `Comparing "${cleanText(seed.name) || 'this finding'}" with the other findings of its kind.`
    body = (
      <div className={styles.loading} role="status">
        <Loader2 size={16} className={styles.spin} />
        <span>{compared} Asking {phase.model ?? 'your Multi mute model'}…</span>
      </div>
    )
    footer = (
      <button
        type="button"
        className="secondaryButton"
        onClick={() => {
          mm.cancelLoading()
          if (result) mm.backToResults()
          else finish()
        }}
      >
        Cancel
      </button>
    )
  } else if (phase.kind === 'error') {
    body = (
      <div className={styles.errorBox} role="alert">
        <span>{phase.message}</span>
        {phase.retry && (
          <button type="button" className="secondaryButton" onClick={() => void mm.run()}>
            <RotateCcw size={12} /> Retry
          </button>
        )}
      </div>
    )
    footer = <button type="button" className="secondaryButton" onClick={() => finish()}>Close</button>
  } else if (result) {
    body = (
      <Results
        mm={mm}
        onOpenMuteRules={onOpenMuteRules ? (kind => finish(() => onOpenMuteRules(kind))) : undefined}
      />
    )
    footer = <Footer mm={mm} onClose={() => finish()} />
  }

  return (
    <Modal
      isOpen
      onClose={() => finish()}
      title="Multi mute"
      size="large"
      closeOnOverlayClick={false}
      className={phase.kind === 'gate' ? styles.gateDialog : undefined}
      footer={footer}
    >
      <div className={styles.body}>{body}</div>
    </Modal>
  )
}

function Results({ mm, onOpenMuteRules }: { mm: MultiMuteState; onOpenMuteRules?: (kind: string) => void }) {
  const r = mm.result!
  const [whyOpen, setWhyOpen] = useState(false)
  const kindText = kindFindings(r.seed.kind)
  const excluded = Object.entries(r.pool.excluded ?? {}).filter(([, n]) => n > 0)
  const leftOut = excluded.reduce((sum, [, n]) => sum + n, 0)
  const seedOutcome = mm.outcomes.get(r.seed.key)
  const ruleKind = onOpenMuteRules ? muteRuleKindFor(r.seed) : null
  const readWhy = cleanText(r.read?.why)

  return (
    <>
      <div className={styles.seedBlock}>
        <div className={styles.titleRow}>
          <h3 className={styles.seedTitle}>Findings like &ldquo;{cleanText(r.seed.name) || r.seed.key}&rdquo;</h3>
          <span className={styles.modelLine}>
            Model: <span className={styles.modelId} title={r.model}>{r.model}</span>
            <span aria-hidden="true">·</span>
            <button
              type="button"
              className={styles.linkButton}
              onClick={mm.changeModel}
              disabled={mm.busy}
              aria-label="Change the Multi mute model"
            >
              Change
            </button>
          </span>
        </div>
        <div className={styles.meta}>
          {[r.seed.kind, r.seed.severity, r.seed.host].map(cleanText).filter(Boolean).join(' · ')}
        </div>
        {!r.seed.triaged && (
          <div className={styles.hint}>
            Run triage for better suggestions: without it only the raw scanner fields are compared.
          </div>
        )}
        {r.status === 'ok' && r.read && (
          <div className={styles.aiRead}>
            <AiTag />
            <span>AI read: {REASON_WORDS[r.read.reason] ?? 'unclear'}{readWhy ? `, ${readWhy}` : ''}</span>
          </div>
        )}
        {r.status === 'model_unreadable' && (
          <div className={styles.banner} role="alert">
            <span>The model&apos;s answer could not be read, so only the exact groups are shown, all unticked.</span>
            <button type="button" className={styles.linkButton} onClick={() => void mm.run()} disabled={mm.busy}>
              Retry
            </button>
          </div>
        )}
        {r.status !== 'empty_pool' && (
          <div className={styles.poolLine}>
            Compared with {r.pool.total.toLocaleString()} {kindText}
            {leftOut > 0 && (
              <>
                {' · '}{leftOut.toLocaleString()} left out (
                <button
                  type="button"
                  className={styles.linkButton}
                  aria-expanded={whyOpen}
                  onClick={() => setWhyOpen(o => !o)}
                >
                  why {whyOpen ? '▴' : '▾'}
                </button>)
              </>
            )}
            {r.pool.truncated && ' · only the closest were compared'}
          </div>
        )}
        {whyOpen && (
          <ul className={styles.whyList} aria-label="Why findings were left out">
            {excluded.map(([reason, n]) => (
              <li key={reason}>{n.toLocaleString()} {exclusionWords(reason)}</li>
            ))}
          </ul>
        )}
        <div className={styles.seedRow}>
          <label className={styles.checkLabel}>
            <input
              type="checkbox"
              checked={mm.includeSeed && mm.seedPending}
              disabled={!mm.seedPending || mm.busy}
              onChange={e => mm.setIncludeSeed(e.target.checked)}
            />
            Mute this finding too
          </label>
          {mm.seedPending ? (
            <MuteButton onClick={mm.muteSeed} disabled={mm.busy} title="Mute this finding alone, now" />
          ) : (
            <OutcomeTag outcome={seedOutcome} />
          )}
        </div>
      </div>

      {r.status === 'empty_pool' ? (
        <div className={styles.empty}>No other {kindText} to compare.</div>
      ) : r.groups.length === 0 ? (
        <div className={styles.empty}>No findings like this one were found. You can still mute it alone.</div>
      ) : (
        <div className={styles.groups}>
          {r.groups.map((group, i) => (
            <GroupCard
              key={group.id}
              group={group}
              mm={mm}
              defaultOpen={i === 0}
              ruleKind={ruleKind}
              onOpenMuteRules={onOpenMuteRules}
            />
          ))}
        </div>
      )}
    </>
  )
}

function GroupCard({ group, mm, defaultOpen, ruleKind, onOpenMuteRules }: {
  group: MultiMuteGroup
  mm: MultiMuteState
  defaultOpen: boolean
  ruleKind: string | null
  onOpenMuteRules?: (kind: string) => void
}) {
  const [open, setOpen] = useState(defaultOpen)
  const [openNo, setOpenNo] = useState(false)
  const heading = groupHeading(group)
  const selectedHere = mm.groupSelection(group).length
  const total = group.members.length + group.probably_not.length
  const title = cleanText(group.title)
  const why = cleanText(group.why)

  return (
    <section className={styles.group} aria-label={heading}>
      <div className={styles.groupHeader}>
        <button
          type="button"
          className={styles.groupToggle}
          aria-expanded={open}
          onClick={() => setOpen(o => !o)}
        >
          {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
          <span className={styles.groupTitle} title={heading}>{heading}</span>
        </button>
        {group.ai ? (
          <span className={styles.aiBadge} title="Grouped by the model alone; check each row">AI suggestion</span>
        ) : (
          <span className={styles.exactBadge} title="Matched by code on the stored fields">exact</span>
        )}
        <span className={styles.groupCount} aria-label={`${total} findings`}>{total}</span>
        <button
          type="button"
          className={styles.groupMute}
          disabled={mm.busy || selectedHere === 0}
          onClick={() => void mm.muteGroup(group)}
        >
          Mute {selectedHere} selected
        </button>
      </div>
      {((!group.ai && title) || why) && (
        <div className={styles.groupNotes}>
          {!group.ai && title && <div className={styles.aiText}><AiTag /><span>{title}</span></div>}
          {why && <div className={styles.aiText}><AiTag /><span>{why}</span></div>}
        </div>
      )}
      {open && (
        <div className={styles.groupBody}>
          <MemberRows members={group.members} group={group} mm={mm} />
          {group.probably_not.length > 0 && (
            <>
              <button
                type="button"
                className={styles.subToggle}
                aria-expanded={openNo}
                onClick={() => setOpenNo(o => !o)}
              >
                {openNo ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                Probably not ({group.probably_not.length})
              </button>
              {openNo && <MemberRows members={group.probably_not} group={group} mm={mm} />}
            </>
          )}
          {!group.ai && ruleKind && onOpenMuteRules && (
            <button
              type="button"
              className={`${styles.linkButton} ${styles.ruleLink}`}
              onClick={() => onOpenMuteRules(ruleKind)}
              disabled={mm.busy}
              title="These mutes hide what is here now; a Mute Rule also hides new matches from future scans"
            >
              Keep hiding new ones: create a Mute Rule
            </button>
          )}
        </div>
      )}
    </section>
  )
}

function MemberRows({ members, group, mm }: { members: MultiMuteMember[]; group: MultiMuteGroup; mm: MultiMuteState }) {
  const [shown, setShown] = useState(ROWS_PER_PAGE)
  if (members.length === 0) return null
  const rest = members.length - shown
  return (
    <>
      <div className={styles.rowsScroll}>
        <table className={styles.rows}>
          <tbody>
            {members.slice(0, shown).map(m => {
              const outcome = mm.outcomes.get(m.key)
              const done = outcome !== undefined
              const name = cleanText(m.name) || m.key
              const severity = cleanText(m.severity).toLowerCase()
              return (
                <tr key={m.key} className={done ? styles.rowDone : undefined} data-key={m.key}>
                  <td className={styles.checkCell}>
                    <input
                      type="checkbox"
                      aria-label={`Select ${name}`}
                      checked={!done && mm.selected.has(m.key)}
                      disabled={done || mm.busy}
                      onChange={() => mm.toggle(m.key)}
                    />
                  </td>
                  <td><NodeIdCell value={m.node_id} /></td>
                  <td className={styles.name}>{name}</td>
                  <td className={styles.host}>{cleanText(m.host) || '-'}</td>
                  <td>
                    <span className={`${styles.sev} ${SEV_CLASS[severity] ?? styles.sevInfo}`}>{severity || '-'}</span>
                  </td>
                  <td>
                    <span
                      className={`${styles.verdict} ${m.verdict ? VERDICT_CLASS[m.verdict] : styles.verdictNone}`}
                      title={verdictTooltip(m)}
                    >
                      {m.verdict ?? 'not judged'}
                    </span>
                  </td>
                  <td className={styles.actionCell}>
                    {done ? (
                      <OutcomeTag outcome={outcome} />
                    ) : (
                      <MuteButton onClick={() => mm.muteRow(m, group)} disabled={mm.busy} title="Mute this finding now" />
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      {rest > 0 && (
        <button
          type="button"
          className={`${styles.linkButton} ${styles.showMore}`}
          onClick={() => setShown(s => s + ROWS_PER_PAGE)}
        >
          Show more ({rest.toLocaleString()} left)
        </button>
      )}
    </>
  )
}

function OutcomeTag({ outcome }: { outcome: string | undefined }) {
  if (!outcome) return null
  return (
    <span className={isMutedOutcome(outcome) ? styles.outcomeMuted : styles.outcomeSkipped}>
      {outcomeWords(outcome)}
    </span>
  )
}

function ActivityLine({ entry, mm }: { entry: ActivityEntry; mm: MultiMuteState }) {
  const muted = entry.mutedKeys.length
  const undone = entry.undoneKeys.length
  return (
    <div className={styles.activityLine}>
      <span>
        {muted > 0 ? `Muted ${muted.toLocaleString()}` : 'Nothing muted'}
        {entry.skipped > 0 && ` · ${entry.skipped.toLocaleString()} skipped`}
      </span>
      {entry.undo === 'idle' && muted > undone && (
        <>
          <span aria-hidden="true">·</span>
          <button
            type="button"
            className={styles.linkButton}
            onClick={() => void mm.undo(entry.id)}
            disabled={mm.busy}
          >
            Undo
          </button>
        </>
      )}
      {entry.undo === 'running' && <span>· undoing…</span>}
      {entry.undo === 'done' && muted > 0 && (
        <span>· {undone === muted ? 'undone' : `${undone.toLocaleString()} of ${muted.toLocaleString()} undone; the rest changed since`}</span>
      )}
      {entry.error && <span className={styles.activityError} role="alert">{entry.error}</span>}
    </div>
  )
}

function Footer({ mm, onClose }: { mm: MultiMuteState; onClose: () => void }) {
  const total = mm.allSelection.length + (mm.includeSeed && mm.seedPending ? 1 : 0)
  return (
    <div className={styles.footer}>
      <div className={styles.activity} aria-live="polite">
        {mm.actionError && (
          <div className={styles.actionError} role="alert">
            <span>{mm.actionError.message}</span>
            {mm.actionError.rerun ? (
              <button type="button" className={styles.linkButton} onClick={() => void mm.run()} disabled={mm.busy}>
                Run Multi mute again
              </button>
            ) : (
              <button type="button" className={styles.linkButton} onClick={mm.dismissActionError}>Dismiss</button>
            )}
          </div>
        )}
        {mm.entries.map(entry => <ActivityLine key={entry.id} entry={entry} mm={mm} />)}
      </div>
      <div className={styles.footerActions}>
        <span className={styles.selectionCount}>
          {mm.allSelection.length.toLocaleString()} selected in {plural(mm.groupsWithSelection, 'group')}
        </span>
        <button type="button" className="secondaryButton" onClick={onClose} disabled={mm.busy}>Close</button>
        <button
          type="button"
          className="primaryButton"
          onClick={() => void mm.muteAll()}
          disabled={mm.busy || total === 0}
        >
          {mm.busy && <Loader2 size={12} className={styles.spin} />}
          Mute all selected ({total.toLocaleString()})
        </button>
      </div>
    </div>
  )
}
