# go-pkg

Yisuan Intelligence 的通用 Go 包。模块路径：`github.com/Yisuan-Intelligence/go-pkg`。

## 安装

要求 Go 1.26 或更新版本。

```sh
go get github.com/Yisuan-Intelligence/go-pkg@v0.1.0
```

## authz

基于 Casbin v3 的通用授权执行包，支持调用方定义 ACL、RBAC、ABAC 模型。

```go
import "github.com/Yisuan-Intelligence/go-pkg/authz"
```

调用方提供模型、策略来源和授权参数。包不依赖 HTTP 框架、数据库或业务表，不签发会话，不持久化策略。每次决策读取最新策略并使用独立实例；拒绝或执行故障均不会放行。

详细接口、使用示例与边界见 [authz 文档](authz/README.md)。

## 版本

整个仓库使用一个 Go module，共享版本号。首个公开版本为 `v0.1.0`，后续发布新的语义化版本；已发布标签不覆盖或移动。

本地开发完成后提交代码并推送分支，再推送版本标签。各使用方在自己的 `go.mod` 中固定所需版本。

## 许可证

[MIT](LICENSE)。Casbin 及其他依赖沿用各自许可证。
