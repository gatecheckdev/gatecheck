Set Theme "Catppuccin Mocha"

Set FontSize 14
Set FontFamily "JetBrainsMonoNL Nerd Font Mono"
Set Margin 20
Set MarginFill "#89B4FA"
Set BorderRadius 10

Set Width 1800

Output dist/gatecheck-bundle.gif

Type "gatecheck ls grype-report.json | less"
Sleep 1
Enter
Sleep 5
Space
Sleep 2
Space
Type "q"
Enter
Sleep 1

Type "gatecheck ls semgrep-sast-report.json | less"
Sleep 1
Enter
Sleep 5
Space
Sleep 2
Space
Type "q"
Enter
Sleep 1

Type "gatecheck ls gitleaks-report.json | less"
Sleep 1
Enter
Sleep 5
Space
Sleep 2
Space
Type "q"
Enter
Sleep 1

Type "gatecheck bundle create gatecheck-bundle.tar.gz gatecheck.yaml"
Sleep 1
Enter

Type "gatecheck bundle add gatecheck-bundle.tar.gz grype-report.json"
Sleep 1
Enter

Type "gatecheck bundle add gatecheck-bundle.tar.gz semgrep-sast-report.json"
Sleep 1
Enter

Type "gatecheck bundle add gatecheck-bundle.tar.gz gitleaks-report.json"
Sleep 1
Enter
Sleep 4

Type "gatecheck ls gatecheck-bundle.tar.gz"
Sleep 1
Enter
Sleep 10
