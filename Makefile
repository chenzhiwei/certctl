NAME=certctl
BINDIR=bin
GITCOMMIT=$(shell git rev-parse --short HEAD)
BUILDVERSION=$(shell date +%Y.%-m.%-d)
GOBUILD=CGO_ENABLED=0 go build -trimpath -ldflags \
		"-X github.com/chenzhiwei/certctl/cmd.buildVersion=$(BUILDVERSION) \
		-X github.com/chenzhiwei/certctl/cmd.buildCommit=$(GITCOMMIT)"

build:
	$(GOBUILD) -o $(BINDIR)/$(NAME)
	@strip $(BINDIR)/$(NAME) || true
