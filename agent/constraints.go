package agent

import (
	"strings"

	"github.com/Autumn-27/artex/db"
)

// constraintBlock renders this task's operation constraints (task_constraints) as a
// high-priority block appended to the planner/worker system prompt. allow/deny are
// grouped; empty string when there are no constraints (or ts is nil).
//
// 语义边界（EXSALA 改造）：约束只框定【目标范围】与【操作员明确禁止的动作】，
// 不用于限制造对手法的强度——同一范围内该爆破就爆破、该提权就提权。旧文案把约束写成
// “凌驾于探索启发式之上、违反即不得进行”，模型容易把它误读成新的安全红线，从而在
// 允许范围内自行降级成温和测试，等于变相自废武功。
func constraintBlock(ts *db.ExplorationStore) string {
	if ts == nil {
		return ""
	}
	rows, err := ts.ListConstraints()
	if err != nil || len(rows) == 0 {
		return ""
	}
	var allow, deny []string
	for _, c := range rows {
		text := strings.TrimSpace(c.Text)
		if text == "" {
			continue
		}
		if c.Kind == "allow" {
			allow = append(allow, "- "+text)
		} else {
			deny = append(deny, "- "+text)
		}
	}
	if len(allow) == 0 && len(deny) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n【操作约束（只框定目标范围与明确禁止的动作；不限制手法强度）】：")
	if len(allow) > 0 {
		b.WriteString("\n允许的操作：\n")
		b.WriteString(strings.Join(allow, "\n"))
	}
	if len(deny) > 0 {
		b.WriteString("\n禁止的操作：\n")
		b.WriteString(strings.Join(deny, "\n"))
	}
	b.WriteString("\n（约束只回答两件事：能打哪些目标、哪些动作明确不准做。在允许的目标与动作范围内，手法强度不受限制——该用多深的利用就用多深，不要因为约束存在就自行降级成温和测试。约束之外的新目标/新端口/新主机不属于授权范围：记为 out-of-scope 事实并跳过，不为其派意图或执行动作。）")
	return b.String()
}
