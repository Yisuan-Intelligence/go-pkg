package authz

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
)

// snapshotAdapter 把来源返回的规则加载到 Casbin；存储格式及业务映射留给来源实现。
type snapshotAdapter struct{ rules []Rule }

var _ persist.Adapter = (*snapshotAdapter)(nil)
var _ Authorizer = (*Engine)(nil)

func (a *snapshotAdapter) LoadPolicy(m model.Model) error {
	for _, rule := range a.rules {
		if rule.Type == "" || (rule.Type[0] != 'p' && rule.Type[0] != 'g') {
			return ErrInvalidPolicy
		}
		section := rule.Type[:1]
		assertion, err := m.GetAssertion(section, rule.Type)
		if err != nil {
			return fmt.Errorf("%w: policy type is not declared in model", ErrInvalidPolicy)
		}
		// 预先校验，防止底层错误包含完整策略值。角色规则可包含模型允许的附加字段。
		if (section == "p" && len(rule.Values) != len(assertion.Tokens)) || (section == "g" && len(rule.Values) < len(assertion.Tokens)) {
			return fmt.Errorf("%w: policy field count does not match model", ErrInvalidPolicy)
		}
		for _, value := range rule.Values {
			if !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
				return ErrInvalidPolicy
			}
		}
		// 数组加载保留标识原文，逗号、引号等字符不会被解释成 CSV 分隔符。
		fields := append([]string{rule.Type}, rule.Values...)
		if err := persist.LoadPolicyArray(fields, m); err != nil {
			return fmt.Errorf("authz.policy.load: %w", err)
		}
	}
	return nil
}

// 所有写方法明确拒绝；通用包不会自动建表或绕过调用方的事务和审计。
func (*snapshotAdapter) SavePolicy(model.Model) error                { return ErrReadOnly }
func (*snapshotAdapter) AddPolicy(string, string, []string) error    { return ErrReadOnly }
func (*snapshotAdapter) RemovePolicy(string, string, []string) error { return ErrReadOnly }
func (*snapshotAdapter) RemoveFilteredPolicy(string, string, int, ...string) error {
	return ErrReadOnly
}
