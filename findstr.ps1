<#
.SYNOPSIS
    Recursively searches a directory for .rs files containing a specific string.

.DESCRIPTION
    This script recursively traverses the specified directory to locate all files
    with the .rs extension (common for Rust source code). It then searches within 
    each file for occurrences of a user-defined search string and outputs the file
    name along with the matching line numbers and content.

.PARAMETER Path
    The path to the directory where the search will be performed.

.PARAMETER SearchString
    The text string to search for within the .rs files.

.EXAMPLE
    .\SearchRustFiles.ps1 -Path "C:\Projects" -SearchString "unsafe"

    This command searches all .rs files under C:\Projects and its subdirectories
    for the string "unsafe".
#>

param(
    [Parameter(Mandatory = $true, HelpMessage = "Enter the directory path to search.")]
    [string]$Path,
    
    [Parameter(Mandatory = $true, HelpMessage = "Enter the string to search for within .rs files.")]
    [string]$SearchString
)

# Check if the provided path exists.
if (-not (Test-Path $Path)) {
    Write-Error "The path '$Path' does not exist. Please provide a valid directory."
    exit 1
}

# Retrieve all .rs files from the directory recursively.
$RustFiles = Get-ChildItem -Path $Path -Filter *.rs -Recurse -File

if ($RustFiles.Count -eq 0) {
    Write-Output "No .rs files found in the directory '$Path'."
    exit 0
}

Write-Output "Searching for '$SearchString' in .rs files under '$Path'..."

# Iterate through each Rust file and search for the specified string.
foreach ($file in $RustFiles) {
    $matches = Select-String -Path $file.FullName -Pattern $SearchString -CaseSensitive
    if ($matches) {
        Write-Output "File: $($file.FullName)"
        foreach ($match in $matches) {
            Write-Output " Line $($match.LineNumber): $($match.Line.Trim())"
        }
        Write-Output "------------------------------"
    }
}

Write-Output "Search complete."
