
<!-- token-efficiency -->
## Token-Effizienz
- Knapp antworten, Ergebnis zuerst, keine Recaps; sichtbaren Code/Diffs nicht wiederholen.
- Erst Grep/Glob, dann nur relevante Ausschnitte lesen (offset/limit); keine Datei doppelt lesen.
- Änderungen per Edit statt Datei neu schreiben; unabhängige Tool-Calls parallel.
- Shell-Output begrenzen (`| tail -n 40`, `-q`) – aber Exit-Codes von Tests/Checks nicht durch Pipes verstecken.
- Nicht lesen: node_modules, dist, build, .next, coverage, Lockfiles, *.min.js, *.map, Bilder/Fonts.
- Tests/Builds gezielt statt komplette Suite, solange nicht final verifiziert wird. Subagents nur für breite Suchen.
