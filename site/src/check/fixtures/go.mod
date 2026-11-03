module example.com/app

go 1.23.0

require (
	code.gitea.io/gitea v1.20.0
	github.com/corazawaf/coraza/v3 v3.7.0 // indirect
	golang.org/x/text v0.0.0-20210101000000-abcdefabcdef
)

require github.com/radius-project/radius v0.57.0

replace github.com/radius-project/radius => ../radius
