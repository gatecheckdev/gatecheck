# Release Instructions

Releasing is done by maintainers with permissions to bypass the PR only rule.
This process assumes you are working from a fork with gatecheckdev/gatecheck as `upstream`.

1. Update CLI version in cmd/gatecheck/main.go
2. Update CHANGELOG.md
3. Tidy modules `go get -t -u ./... && go mod tidy && make test`
3. Release commit should be signed `git commit -s -m "release: vx.x.x`
4. Push commit to upstream `git push -u upstream main` 
5. Wait for unit testing action to pass 
6. git tag `git tag -sa "release" vx.x.x`
7. git push tag `git push -u upstream vx.x.x`
8. Run goreleaser command with ENV Variable `GITHUB_TOKEN="<token> make release`

# References

[Semantic Versioning](https://semver.org/)

[Coventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) 

[goreleaser](https://goreleaser.com/)
