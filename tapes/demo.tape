# The hero asset: two owners, nine escape attempts, nine refusals.
# Real output from the real binary. Nothing here is typed by hand.
Output assets/demo.gif

Set Shell bash
Set FontSize 15
Set FontFamily "Menlo"
Set Width 1180
Set Height 560
Set Padding 24
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set TypingSpeed 45ms
Set Framerate 24

Hide
Type "export PATH=/tmp/cbin:$PATH; export TMPDIR=/tmp; clear"
Enter
Sleep 500ms
Show

Type "cordon demo /tmp/cordon-demo"
Sleep 600ms
Enter
Sleep 4s
