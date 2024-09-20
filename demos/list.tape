Set Theme "Catppuccin Mocha"

Set FontSize 14
Set FontFamily "JetBrainsMonoNL Nerd Font Mono"
Set Margin 20
Set MarginFill "#89B4FA"
Set BorderRadius 10

Set Width 1600

Output dist/gatecheck-list.gif

Type "grype ubuntu:latest -o json | gatecheck ls -i grype | less"
Sleep 1
Enter

Sleep 15
