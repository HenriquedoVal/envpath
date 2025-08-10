### envpath

Update Path environment variable for the current shell session. Diagnoses, adds and removes entries from Path on registry.


##### PowerShell:
~~~PowerShell
Install-Module BinEnvPath
Update-EnvPath
~~~

##### Other shells:
- Download the cli executable
- Run `envpath diag`
- Stdout will have the updated Path
- Do your shell trickery to pipe stdout to Path environment variable
