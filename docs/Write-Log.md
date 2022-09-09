---
external help file: Commonfunctions.psm1-Help.xml
Module Name: Commonfunctions
online version: https://github.com/ThatDamnOwl/Commonfunctions
schema: 2.0.0
---

# Write-Log

## SYNOPSIS
Writes a log entry to the designated log file. Default is verbose

## SYNTAX

### Default
```
Write-Log [-LogMessage] <string> [-LogToFile] [-LogPath <string>] [-LogLevel <int>]
```

## DESCRIPTION
Writes a log entry to the designated log file. Default is verbose

## EXAMPLES

### Example 1
```
PS C:\>  Write-Log "Something Happened"
```

Write a log entry saying "Something happened"

## PARAMETERS

### -LogMessage
Message to send

```yaml
Type: String
Parameter Sets: LogMessage
Aliases: LogMessage

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -LogToFile
Send Log message to file

```yaml
Type: Switch
Parameter Sets: LogToFile
Aliases: LogToFile

Required: false
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -LogPath
Send Log message to file

```yaml
Type: String
Parameter Sets: LogPath
Aliases: LogPath

Required: false
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -LogLevel
The log level of the message

```yaml
Type: Int
Parameter Sets: LogLevel
Aliases: LogLevel

Required: false
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports no common parameters

## INPUTS

### String
### Int
### Boolean
## OUTPUTS

## NOTES

## RELATED LINKS
