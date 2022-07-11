module test

go 1.18

require (
	github.com/sagernet/sing v0.0.0-20220711062652-4394f7cbbae1
	github.com/sagernet/sing-dns v0.0.0
	github.com/stretchr/testify v1.8.0
	golang.org/x/net v0.0.0-20220708220712-1185a9018129
)

replace github.com/sagernet/sing-dns => ../

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
