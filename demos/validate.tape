Set Theme "Catppuccin Mocha"

Set FontSize 14
Set FontFamily "JetBrainsMonoNL Nerd Font Mono"
Set Margin 20
Set MarginFill "#89B4FA"
Set BorderRadius 10

Set Width 1700

Output dist/gatecheck-validate.gif

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

Type "cat gatecheck-severity-limit.yaml"
Sleep 1
Enter
Sleep 5

Type "gatecheck validate -f gatecheck-severity-limit.yaml grype-report.json"
Sleep 1
Enter
Sleep 8

Type "cat gatecheck-epss-limit.yaml"
Sleep 1
Enter
Sleep 5

Type "gatecheck validate -f gatecheck-epss-limit.yaml grype-report.json"
Sleep 1
Enter
Sleep 10
