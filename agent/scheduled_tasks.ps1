$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)

$tasks = [Collections.Generic.List[object]]::new()
$issues = [Collections.Generic.List[object]]::new()
$folders = [Collections.Generic.Queue[object]]::new()
$visited = 0

function Add-CollectionIssue($path, $operation, $exception) {
    $code = 'read_failed'
    while ($null -ne $exception) {
        if (($exception.HResult -band 0xffff) -eq 5) {
            $code = 'access_denied'
            break
        }
        $exception = $exception.InnerException
    }
    $issues.Add(@{ path = $path; operation = $operation; code = $code })
}

try {
    $scheduler = New-Object -ComObject 'Schedule.Service'
    $scheduler.Connect()
    $folders.Enqueue($scheduler.GetFolder('\'))
} catch {
    Add-CollectionIssue '\' 'connect' $_.Exception
}

while ($folders.Count -gt 0) {
    $folder = $folders.Dequeue()
    $visited++
    $folderPath = [string]$folder.Path
    try {
        $registered = $folder.GetTasks(1) # TASK_ENUM_HIDDEN
        for ($index = 1; $index -le $registered.Count; $index++) {
            $path = $folderPath
            try {
                $task = $registered.Item($index)
                $path = [string]$task.Path
                $tasks.Add(@{ path = $path; enabled = [bool]$task.Enabled; state = [int]$task.State; xml = [string]$task.Xml })
            } catch {
                Add-CollectionIssue $path 'read_task' $_.Exception
            }
        }
    } catch {
        Add-CollectionIssue $folderPath 'enumerate_tasks' $_.Exception
    }
    try {
        $children = $folder.GetFolders(0)
        for ($index = 1; $index -le $children.Count; $index++) {
            try {
                $folders.Enqueue($children.Item($index))
            } catch {
                Add-CollectionIssue $folderPath 'read_folder' $_.Exception
            }
        }
    } catch {
        Add-CollectionIssue $folderPath 'enumerate_folders' $_.Exception
    }
}

$report = @{ tasks = $tasks.ToArray(); issues = $issues.ToArray(); folders_visited = $visited }
[Console]::Write(($report | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 5 -Compress))
