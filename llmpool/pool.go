package llmpool

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	"github.com/Autumn-27/norma/llm"
)

// Member is one LLM profile in the chain, already built into a provider (wrapped
// with the recorder by the caller, so a failed attempt is still recorded under
// its own profile name).
type Member struct {
	ID       int64  // llm_profiles.id
	Name     string // profile name, for logs / UI
	Model    string
	Format   string // "anthropic" | "openai"
	Priority int    // the profile's configured priority (display only)
	Active   bool   // is_default (display only)
	// Rank is the ordering key the caller assigned: higher goes first, and members
	// sharing a Rank take turns leading (load-spreading across duplicate keys).
	// The caller encodes "active profile heads the chain" as a Rank above every
	// user-settable priority, so this type needs no policy of its own.
	Rank int
	// WindowTokens is the profile's context window in tokens. A member whose
	// window can't hold the request is skipped rather than made to fail on it.
	WindowTokens int
	Prov         llm.Provider
}

// RankActive is the Rank the caller gives the chain head (the active profile, or
// an explicitly bound one) so it always outranks any configured priority.
const RankActive = int(^uint(0)>>1) - 1

// ErrExhausted is returned when every member of the chain failed.
var ErrExhausted = errors.New("LLM 轮询：所有配置均不可用")

// Pool is an llm.Provider that fails over across an ordered chain of members.
// It is safe for concurrent use: members are immutable after construction and
// all mutable state lives in the shared Registry.
type Pool struct {
	members []*Member // in chain order (active first, then priority DESC)
	health  *Registry
	rr      atomic.Uint64 // rotates the starting point within an equal-priority group
}

// New builds a Pool over members (already in chain order). Returns nil when the
// chain is empty. A single-member chain is still a valid Pool — it just behaves
// exactly like the bare provider.
func New(members []*Member, health *Registry) *Pool {
	if len(members) == 0 {
		return nil
	}
	if health == nil {
		health = NewRegistry(nil, nil)
	}
	return &Pool{members: members, health: health}
}

// Members returns the chain in order (read-only).
func (p *Pool) Members() []*Member { return p.members }

// Head returns the first member of the chain.
func (p *Pool) Head() *Member { return p.members[0] }

// Stream implements llm.Provider with failover.
//
// The one hard rule: a member may only be abandoned BEFORE it has yielded any
// event. Once text or a tool_use has reached the caller, re-sending the same
// request to another model would duplicate output and corrupt the conversation
// history — so a mid-stream failure is surfaced as-is and left to the agent
// harness's resume logic. Fortunately the failures this exists for (402 no
// credit, 401 bad key, 429, 5xx) all surface during request establishment,
// before the body is read, so they always land in the safe window.
func (p *Pool) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	order := p.order(req)
	plan := attemptPlan(order)
	// 只有「带工具的 agent 回合」才开拒答探针：拒答保护的意义就在于——模型明明能
	// 动手，却回一句理由就停下。摘要/压缩/副问答这类无工具的内部调用不存在这种风险，
	// 保持原来的直通行为，避免动到它们的时序。
	guard := RefusalGuardEnabled() && len(req.Tools) > 0
	return func(yield func(llm.StreamEvent, error) bool) {
		var lastErr error
		refusals := 0
		lastRefusal := ""
		for ai, at := range plan {
			m := at.member
			attemptReq := withRefusalNudge(req, at.nudge)
			emitted := false
			var failed error

			// ── 拒答探针（EXSALA）：流一开始不直接交付，而是先扣住一小段，
			// 判断这一轮到底是「执行」还是「拒答」。只有确认不是拒答才放行，
			// 否则丢弃整段缓冲、换下一个成员带加固重放。
			var held []llm.StreamEvent
			decided := !guard // guard 关掉即等价于原来的直通行为
			var say, think strings.Builder
			sawTool := false
			deliver := func(ev llm.StreamEvent) bool {
				emitted = true
				return yield(ev, nil)
			}
			flushHeld := func() bool {
				for _, b := range held {
					if !deliver(b) {
						return false
					}
				}
				held = nil
				return true
			}
			abandonHeld := func() { held = nil }

			for ev, err := range m.Prov.Stream(ctx, attemptReq) {
				if err != nil {
					// 注意："已产出任何事件"（含被探针扣住的）都算已提交，与上游语义一致——
					// 一旦模型开始输出了，就不能再换成员重放，否则会重复一轮输出。
					if !emitted && len(held) == 0 && shouldFailover(ctx, err) {
						failed = err
						break // safe window: nothing reached the caller yet
					}
					if !decided {
						// 非故障转移错误且仍无输出：把扣住的事件原样交付后再报错。
						if !flushHeld() {
							return
						}
					}
					// 注意：这里必须带 err 交付，不能用 deliver（它固定传 nil）。
					emitted = true
					if !yield(ev, err) {
						return
					}
					return // 错误已交给调用方，本轮结束
				}

				if !decided {
					switch ev.Type {
					case llm.SEToolUseStart:
						sawTool = true
					case llm.SEToolInputJSON:
						if ev.Text != "" {
							sawTool = true
						}
					case llm.SETextDelta:
						say.WriteString(ev.Text)
					case llm.SEThinkingDelta:
						think.WriteString(ev.Text)
					}
					// 有工具调用 → 一定是在干活；正文已经不可能再是拒答（不再像任何拒答开场白，
					// 也没命中拒答措辞）→ 立即放行。两种情况都让流式恢复正常粒度，
					// 不会把正常回复拖到流结束。
					if sawTool || !couldStillBeRefusal(say.String()) || utf8.RuneCountInString(think.String()) >= refusalProbeMaxRunes {
						decided = true
						if !flushHeld() {
							return
						}
					} else {
						held = append(held, ev)
						continue
					}
				}
				if !deliver(ev) {
					return // caller stopped consuming (cancel / early exit)
				}
			}

			if failed == nil {
				if !decided {
					// 流正常结束却一直没放行 → 这是关键判定点：
					// 文本像拒答就丢掉重放，否则就是一句正常短回答，放行。
					if LooksLikeRefusal(say.String()) {
						refusals++
						lastRefusal = say.String()
						abandonHeld()
						log.Printf("[llmpool] 检测到拒答，配置 %q(%s) 加固等级 %d，换下一个重放：%s",
							m.Name, m.Model, at.nudge, clipRefusal(lastRefusal))
						if ai+1 < len(plan) {
							n := plan[ai+1]
							log.Printf("[llmpool] 拒答重放：%q(%s) → %q(%s)，加固等级 %d",
								m.Name, m.Model, n.member.Name, n.member.Model, n.nudge)
						}
						continue
					}
					if !flushHeld() {
						return
					}
				}
				p.health.Pass(m.ID) // completed (or failed in a non-failover way)
				return
			}
			lastErr = failed
			hard := isHardFailure(failed)
			if p.health.Trip(m.ID, trimErr(failed), hard) {
				log.Printf("[llmpool] 配置 %q(%s) 已熔断：%s", m.Name, m.Model, trimErr(failed))
			}
			if ai+1 < len(plan) {
				n := plan[ai+1]
				log.Printf("[llmpool] LLM 故障转移：%q(%s) → %q(%s)，原因：%s",
					m.Name, m.Model, n.member.Name, n.member.Model, trimErr(failed))
			}
		}
		if lastErr == nil {
			if refusals > 0 {
				log.Printf("[llmpool] 全部 %d 次尝试均被拒答（最后原文：%s）", refusals, clipRefusal(lastRefusal))
				yield(llm.StreamEvent{}, fmt.Errorf("%w（最后原文：%s）", ErrAllRefused, clipRefusal(lastRefusal)))
				return
			}
			lastErr = ErrExhausted
		}
		log.Printf("[llmpool] 轮询链已耗尽(%d 个配置全部失败)，最后错误：%s", len(plan), trimErr(lastErr))
		yield(llm.StreamEvent{}, fmt.Errorf("%w：%v", ErrExhausted, lastErr))
	}
}

// Complete implements llm.Provider with failover for non-streaming calls. A
// non-streaming request is atomic — it never delivers partial output — so every
// failover-eligible failure lands in the safe window and the next member can be
// tried without risk of duplicated output. Mirrors Stream's health-tripping and
// chain-exhaustion behavior.
func (p *Pool) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	order := p.order(req)
	plan := attemptPlan(order)
	guard := RefusalGuardEnabled() && len(req.Tools) > 0
	var lastErr error
	refusals := 0
	lastRefusal := ""
	for ai, at := range plan {
		m := at.member
		msg, sr, usage, err := m.Prov.Complete(ctx, withRefusalNudge(req, at.nudge))
		if err == nil {
			// 非流式响应是原子的：直接在返回前做一次拒答判定。
			if guard && len(msg.ToolUses()) == 0 && LooksLikeRefusal(msg.Text()) {
				refusals++
				lastRefusal = msg.Text()
				log.Printf("[llmpool] 检测到拒答(非流式)，配置 %q(%s) 加固等级 %d：%s",
					m.Name, m.Model, at.nudge, clipRefusal(lastRefusal))
				if ai+1 < len(plan) {
					n := plan[ai+1]
					log.Printf("[llmpool] 拒答重放：%q(%s) → %q(%s)，加固等级 %d",
						m.Name, m.Model, n.member.Name, n.member.Model, n.nudge)
				}
				continue
			}
			p.health.Pass(m.ID)
			return msg, sr, usage, nil
		}
		if !shouldFailover(ctx, err) {
			// Non-failover error (e.g. ctx cancel, deterministic 4xx): surface as-is
			// without tripping health, matching Stream's non-failover path.
			p.health.Pass(m.ID)
			return llm.Message{}, "", llm.Usage{}, err
		}
		lastErr = err
		hard := isHardFailure(err)
		if p.health.Trip(m.ID, trimErr(err), hard) {
			log.Printf("[llmpool] 配置 %q(%s) 已熔断：%s", m.Name, m.Model, trimErr(err))
		}
		if ai+1 < len(plan) {
			n := plan[ai+1]
			log.Printf("[llmpool] LLM 故障转移：%q(%s) → %q(%s)，原因：%s",
				m.Name, m.Model, n.member.Name, n.member.Model, trimErr(err))
		}
	}
	if lastErr == nil {
		if refusals > 0 {
			log.Printf("[llmpool] 全部 %d 次尝试均被拒答(非流式)（最后原文：%s）", refusals, clipRefusal(lastRefusal))
			return llm.Message{}, "", llm.Usage{}, fmt.Errorf("%w（最后原文：%s）", ErrAllRefused, clipRefusal(lastRefusal))
		}
		lastErr = ErrExhausted
	}
	log.Printf("[llmpool] 轮询链已耗尽(%d 个配置全部失败)，最后错误：%s", len(plan), trimErr(lastErr))
	return llm.Message{}, "", llm.Usage{}, fmt.Errorf("%w：%v", ErrExhausted, lastErr)
}

// order picks the members to try, in order: skip those in a cooling-off window
// and those whose context window can't hold this request, then rotate within each
// equal-priority group so same-priority profiles share the load. Never returns an
// empty slice — if everything is filtered out, the head of the chain is tried
// anyway, since stalling the engine is worse than one more failed request.
func (p *Pool) order(req llm.CompletionRequest) []*Member {
	est := estimateTokens(req)
	var open []*Member
	for _, m := range p.members {
		if p.health.IsOpen(m.ID) {
			continue
		}
		if m.WindowTokens > 0 && est > m.WindowTokens {
			continue // would 400 on length — not a useful failover target
		}
		open = append(open, m)
	}
	if len(open) == 0 {
		return p.members[:1] // last resort: probe the head rather than stall
	}
	return rotateGroups(open, p.rr.Add(1)-1)
}

// rotateGroups rotates each run of equal-ranked members by n, so profiles sharing
// a priority take turns going first (free load-spreading across duplicate keys).
// The chain head has its own Rank and always stays at the front.
func rotateGroups(in []*Member, n uint64) []*Member {
	out := make([]*Member, 0, len(in))
	for i := 0; i < len(in); {
		j := i + 1
		for j < len(in) && in[j].Rank == in[i].Rank {
			j++
		}
		g := in[i:j]
		if len(g) > 1 {
			off := int(n % uint64(len(g)))
			for k := range g {
				out = append(out, g[(k+off)%len(g)])
			}
		} else {
			out = append(out, g...)
		}
		i = j
	}
	return out
}

// statusRe pulls the HTTP status out of the SDK's error text, which is formatted
// as "<prefix>: status <code>: <body>" (norma/llm/retry.go). The SDK exposes no
// typed error, so the string is what we have.
var statusRe = regexp.MustCompile(`status (\d{3})`)

// statusOf returns the HTTP status carried by err, or 0 if it isn't one.
func statusOf(err error) int {
	m := statusRe.FindStringSubmatch(err.Error())
	if m == nil {
		return 0
	}
	code, _ := strconv.Atoi(m[1])
	return code
}

// shouldFailover reports whether err justifies trying the next profile.
//
// Never fails over on context cancellation — that's the user stopping a task or a
// task-level timeout, and burning a backup key on it would both waste credit and
// pollute the run's termination diagnosis. Never on 400 either: a malformed or
// over-long request fails identically everywhere.
func shouldFailover(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	switch code := statusOf(err); {
	case code == 0:
		return true // no status → transport-level failure (reset / DNS / timeout)
	case code == 400:
		return false // bad or over-long request: identical everywhere
	case code == 401, code == 402, code == 403, code == 404, code == 408, code == 429:
		return true
	case code >= 500:
		return true
	}
	return false
}

// isHardFailure reports whether the failure is deterministic (the profile will
// keep failing until a human fixes it) rather than transient. Hard failures open
// the breaker on the first occurrence.
func isHardFailure(err error) bool {
	switch statusOf(err) {
	case 401, 402, 403, 404:
		return true
	}
	return false
}

// trimErr shortens an error for logs/UI — provider bodies can be long.
func trimErr(err error) string {
	s := strings.TrimSpace(strings.ReplaceAll(err.Error(), "\n", " "))
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// estimateTokens roughly sizes a request so members whose context window clearly
// can't hold it are skipped. Deliberately crude (~3.5 chars/token) and biased to
// over-estimate slightly; it only needs to tell "fits" from "nowhere near".
func estimateTokens(req llm.CompletionRequest) int {
	n := 0
	for _, s := range req.System {
		n += len(s)
	}
	for _, m := range req.Messages {
		n += blocksLen(m.Content)
	}
	for _, t := range req.Tools {
		// InputSchema is a decoded map, so its serialized size isn't available
		// cheaply — charge a flat ~120 chars per top-level property instead.
		n += len(t.Name) + len(t.Description) + len(t.InputSchema)*120
	}
	return n * 2 / 7 // ≈ len/3.5
}

func blocksLen(bs []llm.ContentBlock) int {
	n := 0
	for _, b := range bs {
		n += len(b.Text) + len(b.Thinking) + len(b.Input) + len(b.Name)
		if len(b.Content) > 0 {
			n += blocksLen(b.Content)
		}
	}
	return n
}
