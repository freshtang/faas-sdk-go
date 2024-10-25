module gitlab.ctyun.cn/ctg-dcos/faas-sdk-go

go 1.22.0

toolchain go1.22.3

replace ctyun.dev/faas/pkg => ctyun-code.srdcloud.cn/a/CNPaaS/fc/pkg v0.2.5

require (
	github.com/Taoja/sm4 v0.0.0-20210702124949-ed65c23ff019 // indirect
	github.com/google/uuid v1.6.0 // indirect
)

require ctyun.dev/faas/pkg v0.0.0-00010101000000-000000000000
