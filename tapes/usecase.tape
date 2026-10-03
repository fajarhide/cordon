# One story in five beats: an agent writes a report for Budi, Budi gets it,
# Ani cannot, and neither can Ani's job.
Output assets/usecase.gif

Set Shell bash
Set FontSize 15
Set FontFamily "Menlo"
Set Width 1180
Set Height 560
Set Padding 24
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set TypingSpeed 24ms
Set Framerate 24

Hide
Type "export PATH=/tmp/cbin:$PATH; cd /tmp/crec; ./serve.sh >/dev/null"
Enter
Sleep 2s
Type "A=http://127.0.0.1:7900; H='Authorization: Bearer rec-token'; C='content-type: application/json'; clear"
Enter
Sleep 300ms
Show

Type "# Budi's agent renders a report. The model chose the paths."
Enter
Type "cat job.json"
Enter
Sleep 2500ms

Type `curl -s -X POST $A/v1/run -H "$H" -H "$C" -d @job.json | jq -c`
Enter
Sleep 3500ms

Type "# Output comes back as a token, never as a path."
Enter
Type `TOK=$(curl -s -X POST $A/v1/run -H "$H" -H "$C" -d @job.json | jq -r .artifacts[0].token)`
Enter
Sleep 1800ms

Type `curl -s -H "$H" "$A/v1/artifact/$TOK?owner=acme/legal/budi"`
Enter
Sleep 2200ms

Type "# Ani presents the same token."
Enter
Type `curl -s -H "$H" "$A/v1/artifact/$TOK?owner=acme/legal/ani" | jq -c`
Enter
Sleep 2500ms

Type "# And Ani's own job goes looking for the file directly."
Enter
Type `curl -s -X POST $A/v1/run -H "$H" -H "$C" -d @steal.json | jq -r .stdout`
Enter
Sleep 4s
