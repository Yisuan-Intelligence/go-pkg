package authz_test

import (
	"context"
	"fmt"

	"github.com/Yisuan-Intelligence/go-pkg/authz"
)

// 演示与商城无关的文档读取授权，示例也参与测试以保证公开接口可实际使用。
func ExampleNew() {
	source := authz.SourceFunc(func(context.Context, authz.Request) ([]authz.Rule, error) {
		return []authz.Rule{{Type: "p", Values: []string{"alice", "document:42", "read"}}}, nil
	})
	engine, err := authz.New(aclModel, source)
	if err != nil {
		panic(err)
	}
	allowed, err := engine.Enforce(context.Background(), "alice", "document:42", "read")
	fmt.Println(allowed, err)
	// Output: true <nil>
}
