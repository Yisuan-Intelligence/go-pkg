# 通用 Casbin 授权包

`authz` 依赖 Go 标准库和 Casbin。导入方式：

```go
import "github.com/Yisuan-Intelligence/go-pkg/authz"
```

调用方提供模型文本、策略来源与授权参数；包内没有商城表名、用户模型、后台/C 端枚举、Gin、GORM 或项目 `internal` 依赖。可以按同一接口接入 ACL、RBAC、ABAC 等 Casbin 模型。

包属于 `github.com/Yisuan-Intelligence/go-pkg` 模块，可通过 `github.com/Yisuan-Intelligence/go-pkg/authz` 导入。安装首个公开版本：

```sh
go get github.com/Yisuan-Intelligence/go-pkg@v0.1.0
```

要求 Go 1.26 或更新版本，Casbin 依赖为 v3.11.0。

## 调用方式

```go
modelText := `
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`

source := authz.SourceFunc(func(ctx context.Context, request authz.Request) ([]authz.Rule, error) {
    // 这里也可以调用自己的数据库或策略服务；无需使用商城的角色权限表。
    return []authz.Rule{
        {Type: "p", Values: []string{"alice", "document:42", "read"}},
    }, nil
})

engine, err := authz.New(modelText, source)
if err != nil {
    return err
}
allowed, err := engine.Enforce(ctx, "alice", "document:42", "read")
if err != nil {
    return err
}
if !allowed {
    // 调用方按自己的协议返回拒绝结果。
}
```

`Rule.Type` 是模型中声明的 `p`、`p2`、`g`、`g2` 等策略类型，`Values` 顺序由模型决定。`Enforce` 参数数量、顺序和类型也由模型决定；ABAC 模型可以传入具有公开属性的对象。模型是受信任的程序配置，不从未经校验的客户端请求直接加载。

`PolicySource.Load` 可以返回完整规则或按请求过滤后的规则，但必须保留决策所需的全部关系。来源实现负责业务状态过滤、并发读取与一致性；返回规则后不能再并发修改其内容。空规则集合的结果由调用方模型决定，例如示例中的允许规则模型默认拒绝。

## 执行与错误

- `New` 解析模型声明但不访问策略存储，声明解析错误立即返回；匹配表达式等执行错误由 `Enforce` 返回。
- 每次 `Enforce` 重新读取策略，复制不可变模型模板，创建请求独立的 Casbin 实例；多个请求不会串用可变策略。
- 不缓存授权结果或策略；存储的下一次读取能看到已提交变更，适合需要立即撤权的初期项目。每次构建实例存在计算开销，当前未做性能承诺；规模扩大后应先压测，再设计版本通知和多实例失效。
- `false, nil` 表示模型拒绝；读取、规则加载、执行或 context 取消错误返回 `false, error`，调用方不能把错误当作放行。
- `ErrInvalidPolicy` 表示规则类型或字段与模型不匹配；错误不包含该规则的完整字段值。
- 使用数组加载规则，保留逗号、引号等标识内容，不将其解释为 CSV 分隔符。

内部 Casbin Adapter 只读，写方法返回 `ErrReadOnly`，自动保存关闭。包不创建表、持久化规则、签发会话或输出业务日志。用户与角色管理、写入事务、身份验证、对象归属、日志及错误响应由调用方负责。

## 业务接入

调用方在自己的业务模块定义 Casbin 模型并实现 `PolicySource`。账号、角色、权限表映射和业务保护均由调用方维护；此仓库不包含特定项目的适配实现。

仓库包含独立测试，覆盖 ACL 精确匹配、任意工作空间的角色隔离、ABAC 属性对象、最新策略、并发决策、故障传播和 context 取消。

Casbin 模型和存储适配接口参考 [模型语法](https://casbin.apache.org/docs/model-syntax/) 与 [官方 Adapter 文档](https://casbin.apache.org/docs/adapters/)。
