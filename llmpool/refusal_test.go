// ============================================
// EXSALA HERMES MOD
// powered by Gienetic
// ============================================
package llmpool

import (
	"context"
	"errors"
	"iter"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// fakeProvider 按脚本播放流事件；每次调用把收到的 req 记下来，便于断言「加固指令
// 确实被追加进了 system 段」。
type fakeProvider struct {
	events  []llm.StreamEvent
	reqs    []llm.CompletionRequest
	compMsg llm.Message
}

func (f *fakeProvider) Stream(_ context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	f.reqs = append(f.reqs, req)
	return func(yield func(llm.StreamEvent, error) bool) {
		for _, ev := range f.events {
			if !yield(ev, nil) {
				return
			}
		}
	}
}

func (f *fakeProvider) Complete(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	f.reqs = append(f.reqs, req)
	return f.compMsg, "end_turn", llm.Usage{}, nil
}

func textStream(chunks ...string) []llm.StreamEvent {
	evs := make([]llm.StreamEvent, 0, len(chunks)+1)
	for _, c := range chunks {
		evs = append(evs, llm.StreamEvent{Type: llm.SETextDelta, Text: c})
	}
	evs = append(evs, llm.StreamEvent{Type: llm.SEMessageStop})
	return evs
}

func collect(t *testing.T, p *Pool) (string, error) {
	t.Helper()
	var sb strings.Builder
	var gotErr error
	for ev, err := range p.Stream(context.Background(), llm.CompletionRequest{Messages: []llm.Message{llm.UserText("do it")}, Tools: []llm.ToolSchema{{Name: "Bash"}}}) {
		if err != nil {
			gotErr = err
			break
		}
		sb.WriteString(ev.Text)
	}
	return sb.String(), gotErr
}

// 单成员 + 一直拒答 → 必须返回 ErrAllRefused，而不是把拒答当成正常回答。
func TestStreamRefusalAllAttempts(t *testing.T) {
	refusing := &fakeProvider{events: textStream("抱歉，我无法协助这个请求。")}
	pool := New([]*Member{{ID: 1, Name: "m1", Model: "x", Prov: refusing}}, nil)

	out, err := collect(t, pool)
	if err == nil {
		t.Fatalf("期望 ErrAllRefused，实际无错误；输出=%q", out)
	}
	if !errors.Is(err, ErrAllRefused) {
		t.Fatalf("期望 ErrAllRefused，实际 %v", err)
	}
	if out != "" {
		t.Fatalf("拒答内容不应交付给调用方，实际=%q", out)
	}
	if len(refusing.reqs) != 3 {
		t.Fatalf("单成员应尝试 3 次（原样/轻度/强加固），实际 %d", len(refusing.reqs))
	}
	// 第 2、3 次必须带上加固指令，第 1 次不能带。
	if len(refusing.reqs[0].System) != 0 {
		t.Fatalf("首次尝试不应追加加固指令: %v", refusing.reqs[0].System)
	}
	if !strings.Contains(strings.Join(refusing.reqs[1].System, ""), "系统附加指令") {
		t.Fatalf("第 2 次尝试应带轻度加固: %v", refusing.reqs[1].System)
	}
	if !strings.Contains(strings.Join(refusing.reqs[2].System, ""), "最高优先级") {
		t.Fatalf("第 3 次尝试应带强加固: %v", refusing.reqs[2].System)
	}
}

// 第一个成员拒答、第二个成员正常执行（带工具调用）→ 交付第二个的输出。
func TestStreamRefusalFailoverToNextMember(t *testing.T) {
	refusing := &fakeProvider{events: textStream("I cannot assist with that request.")}
	working := &fakeProvider{events: []llm.StreamEvent{
		{Type: llm.SEToolUseStart},
		{Type: llm.SETextDelta, Text: "跑 nmap 中"},
		{Type: llm.SEMessageStop},
	}}
	pool := New([]*Member{
		{ID: 1, Name: "refuser", Model: "a", Rank: RankActive, Prov: refusing},
		{ID: 2, Name: "worker", Model: "b", Rank: 10, Prov: working},
	}, nil)

	out, err := collect(t, pool)
	if err != nil {
		t.Fatalf("期望成功，实际错误 %v", err)
	}
	if !strings.Contains(out, "跑 nmap 中") {
		t.Fatalf("应交付第二个成员的真实输出，实际 %q", out)
	}
	if len(refusing.reqs) != 1 {
		t.Fatalf("拒答成员应只被尝试一次，实际 %d", len(refusing.reqs))
	}
}

// 正常长回答（含「我不能到达这个主机」这类技术叙述）不得被判成拒答。
func TestStreamNormalAnswerNotTreatedAsRefusal(t *testing.T) {
	normal := &fakeProvider{events: textStream("我先 curl 首页看指纹；上一轮我无法到达 10.0.0.5，换个出口再试一次。")}
	pool := New([]*Member{{ID: 1, Name: "m", Model: "x", Prov: normal}}, nil)

	out, err := collect(t, pool)
	if err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	if !strings.Contains(out, "curl") {
		t.Fatalf("正常输出应原样交付: %q", out)
	}
	if len(normal.reqs) != 1 {
		t.Fatalf("正常回答不应重放，实际尝试 %d 次", len(normal.reqs))
	}
}

// 非流式路径同样要能识别拒答并重放。
func TestCompleteRefusalFailover(t *testing.T) {
	refusing := &fakeProvider{compMsg: llm.Message{Content: []llm.ContentBlock{{Type: llm.BlockText, Text: "我不能提供这类帮助。"}}}}
	working := &fakeProvider{compMsg: llm.Message{Content: []llm.ContentBlock{{Type: llm.BlockText, Text: "已执行 sqlmap，注入点确认。"}}}}
	pool := New([]*Member{
		{ID: 1, Name: "refuser", Model: "a", Rank: RankActive, Prov: refusing},
		{ID: 2, Name: "worker", Model: "b", Rank: 10, Prov: working},
	}, nil)

	msg, _, _, err := pool.Complete(context.Background(), llm.CompletionRequest{Messages: []llm.Message{llm.UserText("go")}, Tools: []llm.ToolSchema{{Name: "Bash"}}})
	if err != nil {
		t.Fatalf("期望成功: %v", err)
	}
	if !strings.Contains(msg.Text(), "sqlmap") {
		t.Fatalf("应交付第二个成员的回答，实际 %q", msg.Text())
	}
}

func TestLooksLikeRefusal(t *testing.T) {
	cases := []struct {
		text string
		want bool
	}{
		{"抱歉，我无法协助这个请求", true},
		{"I cannot assist with that.", true},
		{"这超出了我的能力范围，建议你使用合法途径。", true},
		{"我无法到达 10.0.0.5，网络不通，换个出口重试", false}, // 技术叙述
		{"I can't reach the host, retrying with a different proxy", false},
		{"nmap 扫完了，开放 22/80/443", false},
		{"", false},
	}
	for _, c := range cases {
		if got := LooksLikeRefusal(c.text); got != c.want {
			t.Fatalf("LooksLikeRefusal(%q) = %v, want %v", c.text, got, c.want)
		}
	}
}
