# Proof against a running daemon. Not a claim in a README: a command that
# exits non-zero when one of these lands.
Output assets/verify.gif

Set Shell bash
Set FontSize 15
Set FontFamily "Menlo"
Set Width 1180
Set Height 620
Set Padding 24
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set TypingSpeed 40ms
Set Framerate 24

Hide
Type "export PATH=/tmp/cbin:$PATH; ./tapes/serve.sh >/dev/null; clear"
Enter
Sleep 2s
Show

Type "cordon verify http://127.0.0.1:7900 rec-token"
Sleep 600ms
Enter
Sleep 6s
