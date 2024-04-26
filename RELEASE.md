# Release Instructions

Releasing is done by maintainers with permissions to bypass the PR only rule.
By pushing a tag to the main repository, the release action is triggered which
packages the app and releases it to the GitHub UI.

1. Run `just upgrade` to update dependencies and tidy modules
1. Run `just test` to make sure unit testing still passes after upgrading
1. Commit the changes `git commit -am "chore: upgrade dependencies"`
1. Update CHANGELOG.md
1. Release commit should be signed `git commit -S -m "release: vx.x.x`
1. Wait for unit testing action to pass `gh run watch`
1. git tag `git tag -sa "release" vX.X.X`
1. git push tag `git push vX.X.X`

# References

[Semantic Versioning](https://semver.org/)

[Coventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)

[goreleaser](https://goreleaser.com/)
