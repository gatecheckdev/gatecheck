# Release Instructions

1. Update CLI version in cmd/root
2. Update CHANGELOG.md
3. Create a release branch `git switch -c release/v0.0.x`
4. Commit and Tag `git add . && git commit -m "release: v0.0.x" && git tag v0.0.x`
5. Push commits and tags `git push -u origin release/v0.0.x && git push --tags`
6. Use goreleaser with token `GITHUB_TOKEN=<token> goreleaser release --rm-dist`

# References

[Semantic Versioning](https://semver.org/)

[Coventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) 

[goreleaser](https://goreleaser.com/)
