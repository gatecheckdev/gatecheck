# Release Instructions

1. Update CLI version in cmd/root
2. Update CHANGELOG.md
3. Commit and Tag `git add . && git commit -m "release: v0.0.x" && git tag v0.0.x`
4. Push commits and tags `git push -u origin release/v0.0.x && git push --tags`
5. GitHub Action will release with goreleaser

# References

[Semantic Versioning](https://semver.org/)

[Coventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) 

[goreleaser](https://goreleaser.com/)
