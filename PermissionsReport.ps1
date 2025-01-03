function Get-NotInheritedACL {
param (    
        [Parameter(Mandatory = $true)][validatescript({Test-Path -Path $_ -PathType Container})]$Path
    )

	$acl = Get-Acl -Path $path | Select-Object -ExpandProperty Access | Where-Object { -Not $_.IsInherited } |	 Foreach-Object {
		[PSCustomObject]@{
			Path = $Path
			Access = $_
		}
	}

    if($acl){
        return $acl
    }

	$parent = Split-Path $Path

	if ($parent) {
		Get-NotInheritedACL $parent
	}
}


Function Get-PermDetail {
 param (    
        [Parameter(Mandatory = $true)][validatescript({Test-Path -Path $_ -PathType Container})]$FolderPath
    )
    
 $array = @() 
    
    Write-host "Working on the getting all the folders inside path $($FolderPath), it can take lots of time..."

 $Folders = Get-ChildItem -Recurse $FolderPath -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer }

    Write-host "Found $($Folders.count) in the path $($FolderPath). Would proceed to check the permissions of each of them now."

    $i = 0

    ForEach($Folder in $Folders){
        $i++
        Write-Progress -Activity "Getting details of $($Folder.FullName)" -Status "$("{0:N2}" -f ($i * 100 / ($folders.count))) % complete"  -PercentComplete (($i /( $folders.count)) * 100)

     $Permissions = (Get-ACL -path $Folder.FullName  -ErrorAction SilentlyContinue).Access | Select-object IdentityReference, FileSystemRights, AccessControlType, IsInherited

     $exclusiveperms = Get-NotInheritedACL $Folder.FullName

     ForEach($perm in $Permissions){        
        
        $from = ($exclusiveperms | Where-Object {
    ($_.Access.IdentityReference.Value -eq $Perm.IdentityReference.Value) -and
    ($_.Access.FileSystemRights -eq $Perm.FileSystemRights) -and
    ($_.Access.AccessControlType -eq $Perm.AccessControlType)
}).Path

        
        

        $obj = [pscustomobject] @{
            Path = $Folder.FullName
            Identity = $Perm.IdentityReference
            Accesstype = $Perm.FileSystemRights
            AccessControlType = $perm.AccessControlType
            IsInherited = $Perm.IsInherited
            InheritedFrom = $from
            DateModified = $Folder.LastWritetime
         DateLastAccessed = $Folder.LastAccesstime
        }

     $array += $obj
     }
     
    }

    return $array
} 

Get-PermDetail -folderpath c:\temp\
