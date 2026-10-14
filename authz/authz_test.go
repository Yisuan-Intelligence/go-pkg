package authz_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/Yisuan-Intelligence/go-pkg/authz"
)

const aclModel = `
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`

// 该模型使用任意工作空间和角色名称，与商城的用户、端和表完全无关。
const domainModel = `
[request_definition]
r = sub, dom, obj, act
[policy_definition]
p = sub, dom, obj, act
[role_definition]
g = _, _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.dom == p.dom && r.obj == p.obj && r.act == p.act && g(r.sub, p.sub, r.dom)
`

func engine(t *testing.T, model string, source authz.PolicySource) *authz.Engine {
	t.Helper()
	e, err := authz.New(model, source)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func fixed(rules ...authz.Rule) authz.PolicySource {
	return authz.SourceFunc(func(context.Context, authz.Request) ([]authz.Rule, error) { return rules, nil })
}

func check(t *testing.T, e *authz.Engine, expected bool, values ...any) {
	t.Helper()
	allowed, err := e.Enforce(context.Background(), values...)
	if err != nil || allowed != expected {
		t.Fatalf("authorization = %v, %v; want %v", allowed, err, expected)
	}
}

func TestACLWithArbitraryIdentifiersAndExactMatching(t *testing.T) {
	e := engine(t, aclModel, fixed(authz.Rule{Type: "p", Values: []string{"person,\"one\"", "document/*", "read"}}))
	check(t, e, true, "person,\"one\"", "document/*", "read")
	check(t, e, false, "person,\"one\"", "document/42", "read")
	check(t, e, false, "another-person", "document/*", "read")
	check(t, e, false, "person,\"one\"", "document/*", "write")
	check(t, engine(t, aclModel, fixed()), false, "person", "document", "read")
}

func TestCallerDefinedRolesAndDomainIsolation(t *testing.T) {
	e := engine(t, domainModel, fixed(
		authz.Rule{Type: "g", Values: []string{"person:one", "role:reviewer", "workspace:a"}},
		authz.Rule{Type: "p", Values: []string{"role:reviewer", "workspace:a", "article", "review"}},
		authz.Rule{Type: "p", Values: []string{"role:reviewer", "workspace:b", "article", "publish"}},
	))
	check(t, e, true, "person:one", "workspace:a", "article", "review")
	check(t, e, false, "person:one", "workspace:b", "article", "publish")
	check(t, e, false, "person:two", "workspace:a", "article", "review")
	check(t, e, false, "admin_owner", "workspace:a", "article", "review")
}

func TestABACAcceptsAttributeObjectsWithoutRoleRules(t *testing.T) {
	const abacModel = `
[request_definition]
r = sub, obj, act
[policy_definition]
p = act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == r.obj.Owner && r.act == p.act
`
	type document struct{ Owner string }
	e := engine(t, abacModel, fixed(authz.Rule{Type: "p", Values: []string{"edit"}}))
	check(t, e, true, "author", document{Owner: "author"}, "edit")
	check(t, e, false, "reader", document{Owner: "author"}, "edit")
	check(t, e, false, "author", document{Owner: "author"}, "delete")
}

func TestLatestPoliciesAndConcurrentDecisions(t *testing.T) {
	var mu sync.RWMutex
	enabled := true
	source := authz.SourceFunc(func(_ context.Context, request authz.Request) ([]authz.Rule, error) {
		mu.RLock()
		defer mu.RUnlock()
		if !enabled {
			return nil, nil
		}
		object := request[1].(string)
		return []authz.Rule{{Type: "p", Values: []string{"owner:" + object, object, "read"}}}, nil
	})
	e := engine(t, aclModel, source)
	check(t, e, true, "owner:document", "document", "read")
	mu.Lock()
	enabled = false
	mu.Unlock()
	check(t, e, false, "owner:document", "document", "read")
	mu.Lock()
	enabled = true
	mu.Unlock()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Go(func() {
			object := fmt.Sprintf("document:%d", i)
			for j := 0; j < 10; j++ {
				check(t, e, true, "owner:"+object, object, "read")
				check(t, e, false, "intruder", object, "read")
			}
		})
	}
	wg.Wait()
}

func TestConfigurationAndPolicyFailuresNeverAllow(t *testing.T) {
	if _, err := authz.New(aclModel, nil); !errors.Is(err, authz.ErrMissingSource) {
		t.Fatal("missing source was accepted")
	}
	if _, err := authz.New("invalid model", fixed()); err == nil {
		t.Fatal("invalid model was accepted")
	}
	storageError := errors.New("policy storage unavailable")
	e := engine(t, aclModel, authz.SourceFunc(func(context.Context, authz.Request) ([]authz.Rule, error) { return nil, storageError }))
	if allowed, err := e.Enforce(context.Background(), "owner", "document", "read"); allowed || !errors.Is(err, storageError) {
		t.Fatal("storage error did not propagate safely")
	}
	for _, rule := range []authz.Rule{
		{Type: "", Values: []string{"private-policy-value"}},
		{Type: "p7", Values: []string{"private-policy-value"}},
		{Type: "p", Values: []string{"private-policy-value"}},
		{Type: "g", Values: []string{"private-policy-value"}},
	} {
		e := engine(t, aclModel, fixed(rule))
		allowed, err := e.Enforce(context.Background(), "owner", "document", "read")
		if allowed || !errors.Is(err, authz.ErrInvalidPolicy) || strings.Contains(err.Error(), "private-policy-value") {
			t.Fatal("invalid rule was allowed or leaked values")
		}
	}
	if allowed, err := engine(t, aclModel, fixed()).Enforce(context.Background(), "owner"); allowed || err == nil {
		t.Fatal("request field count was not checked by model")
	}
}

func TestCancellationBeforeAndDuringLoading(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	called := false
	source := authz.SourceFunc(func(context.Context, authz.Request) ([]authz.Rule, error) {
		called = true
		cancel()
		return []authz.Rule{{Type: "p", Values: []string{"owner", "document", "read"}}}, nil
	})
	e := engine(t, aclModel, source)
	if allowed, err := e.Enforce(ctx, "owner", "document", "read"); allowed || !errors.Is(err, context.Canceled) || !called {
		t.Fatal("cancellation during loading was ignored")
	}
	called = false
	if allowed, err := e.Enforce(ctx, "owner", "document", "read"); allowed || !errors.Is(err, context.Canceled) || called {
		t.Fatal("canceled request reached policy source")
	}
}
