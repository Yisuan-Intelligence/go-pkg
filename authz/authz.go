// Package authz 封装 Casbin 的模型加载、只读策略适配和授权执行。
// 模型、请求字段和策略来源均由调用方提供，不依赖特定 RBAC 表、HTTP 框架或数据库。
package authz

import (
	"context"
	"errors"
	"fmt"

	"github.com/casbin/casbin/v3"
	"github.com/casbin/casbin/v3/model"
)

var (
	ErrInvalidPolicy = errors.New("authz: invalid policy rule")
	ErrMissingSource = errors.New("authz: policy source is required")
	ErrReadOnly      = errors.New("authz: snapshot adapter is read-only")
)

// Request 中参数的数量、顺序和类型由 Casbin 模型决定，可以包含 ABAC 属性对象。
// 来源实现不得修改请求参数；认证凭据不应作为授权请求传入。
type Request []any

// Rule 对应一条 Casbin 策略。Type 可以是模型声明的 p、p2、g、g2 等。
// Values 按模型声明的字段顺序排列，不由通用包解释账号、角色或权限。
type Rule struct {
	Type   string
	Values []string
}

// PolicySource 可由 SQL、内存或其他存储实现，返回完整或针对请求筛选的规则。
// Load 应尊重 context，保证一致性读取，并负责业务状态过滤；故障必须返回错误。
// 实现方需要支持并发读取，且返回后不得并发修改规则内容。空规则集合合法。
type PolicySource interface {
	Load(context.Context, Request) ([]Rule, error)
}

// SourceFunc 允许通过函数接入任意策略来源。
type SourceFunc func(context.Context, Request) ([]Rule, error)

func (f SourceFunc) Load(ctx context.Context, request Request) ([]Rule, error) {
	if f == nil {
		return nil, ErrMissingSource
	}
	return f(ctx, request)
}

// Authorizer 供调用方按接口依赖授权能力；参数约定由其注入的模型决定。
type Authorizer interface {
	Enforce(context.Context, ...any) (bool, error)
}

// Engine 保存不可变的模型模板。每次决策使用独立副本及最新策略，不共享可变 Enforcer。
// 无授权缓存；加入缓存时，调用方还需要设计跨实例失效和撤权一致性。
type Engine struct {
	template model.Model
	source   PolicySource
}

// New 解析受信任的 Casbin 模型，不读取策略存储。模型不能来自未经校验的客户端输入。
func New(modelText string, source PolicySource) (*Engine, error) {
	if source == nil {
		return nil, ErrMissingSource
	}
	m, err := model.NewModelFromString(modelText)
	if err != nil {
		return nil, fmt.Errorf("authz.model: %w", err)
	}
	return &Engine{template: m, source: source}, nil
}

// Enforce 按调用方模型计算授权。false,nil 表示拒绝，执行故障返回 false,error。
// 本包不验证会话、不操作业务表，也不提供策略写入或超级用户的默认绕过规则。
func (e *Engine) Enforce(ctx context.Context, values ...any) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	rules, err := e.source.Load(ctx, append(Request(nil), values...))
	if err != nil {
		return false, fmt.Errorf("authz.load: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	enforcer, err := casbin.NewEnforcer(e.template.Copy(), &snapshotAdapter{rules: rules})
	if err != nil {
		return false, fmt.Errorf("authz.enforcer: %w", err)
	}
	// 策略写入由调用方的管理入口完成，避免 Casbin 自动保存建立另一份数据源。
	enforcer.EnableAutoSave(false)
	allowed, err := enforcer.Enforce(values...)
	if err != nil {
		return false, fmt.Errorf("authz.enforce: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return allowed, nil
}
