Function Grant-ADPermission{
    <#
    .SYNOPSIS
        Add Access Control Entry on Active Directory Organizational Unit.
    .DESCRIPTION
        This function will create ACE and add them to the specified AD OU's.
    .EXAMPLE
        Grant-ADPermission -GroupDistinguishedName 'CN=Applications2,OU=Groups,DC=D2K12R2,DC=local' -AdRights WriteProperty -AccessControlType Allow -Inheritance Children -ObjectType user -InheritedObjectType user -OrgUnitDN 'OU=Test,DC=D2K12R2,DC=local'
    .EXAMPLE
        Grant-ADPermission -GroupDistinguishedName 'CN=StarWars-Computers_CreateDelete,OU=Groups,OU=Admins,DC=D2K8R2,DC=itfordummies,DC=net' -AdRights CreateChild,DeleteChild -AccessControlType Allow -Inheritance Children -OrgUnitDN 'OU=Computers,OU=Star Wars,OU=Production,DC=D2K8R2,DC=itfordummies,DC=net' -ObjectType computer -InheritedObjectType null -Verbose
    .EXAMPLE
        'OU=lvl2,OU=Test,DC=D2K12R2,DC=local','OU=Trash,OU=Test,DC=D2K12R2,DC=local' | Grant-ADPermission -GroupDistinguishedName 'CN=Applications2,OU=Groups,DC=D2K12R2,DC=local' -AdRights WriteProperty -AccessControlType Allow -Inheritance Children -ObjectType user -InheritedObjectType user
    .PARAMETER GroupDistinguishedName
        DistinguishedName of the group to give permission to.
    .PARAMETER AdRights
        System.DirectoryServices.ActiveDirectoryRights, autocompletion should work from PS3+.
    .PARAMETER AccessControlType
        System.Security.AccessControl.AccessControlType, autocompletion should work from PS3+.
    .PARAMETER Inheritance
        System.DirectoryServices.ActiveDirectorySecurityInheritance, autocompletion should work from PS3+.
    .PARAMETER OrgUnitDN
        String[] containing the list of OU to delegate. You can specify more than one, and use pipeline input.
    .PARAMETER InheritedObjectType
        Dynamic param containing LDAPName of all schema objects. The function will use the associated GUID.
    .PARAMETER ObjectType
        Dynamic param containing LDAPName of all schema objects. The function will use the associated GUID.
    .INPUTS
    .OUTPUTS
    .NOTES
        Uses Dynamic Parameters.
    .LINK
        http://ItForDummies.net
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [String]$GroupDistinguishedName,

        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.ActiveDirectoryRights[]]$AdRights,

        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.AccessControlType]$AccessControlType,

        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]$Inheritance,

        [Parameter(Mandatory = $true,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true)]
        [String[]]$OrgUnitDN,

        [Switch]$PassThru
    )

    DynamicParam{
        #region ObjectType
        # Set the dynamic parameters' name
        $ParameterName = 'ObjectType'
            
        # Create the dictionary 
        $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        # Create the collection of attributes
        $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            
        # Create and set the parameters' attributes
        $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
        $ParameterAttribute.Mandatory = $true
        $ParameterAttribute.Position = 1

        # Add the attributes to the attributes collection
        $AttributeCollection.Add($ParameterAttribute)

        # Generate and set the ValidateSet
        $DomainName = [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        $MasterGuidMap = @{}
        $SchemaGuidMapSearcher = [ADSISearcher]'(schemaidguid=*)'
        $SchemaGuidMapSearcher.SearchRoot = [ADSI]"LDAP://CN=Schema,$(([ADSI]"LDAP://$DomainName/RootDSE").configurationNamingContext)"
        $null = $SchemaGuidMapSearcher.PropertiesToLoad.AddRange(('ldapdisplayname','schemaidguid'))
        $SchemaGuidMapSearcher.PageSize = 10000
        $SchemaGuidMapSearcher.FindAll() | Foreach-Object -Process {
            #$MasterGuidMap[(New-Object -TypeName Guid -ArgumentList (,$_.properties.schemaidguid[0])).Guid] = "$($_.properties.ldapdisplayname)"
            $MasterGuidMap["$($_.properties.ldapdisplayname)"] = (New-Object -TypeName Guid -ArgumentList (,$_.properties.schemaidguid[0])).Guid
        } -End {$MasterGuidMap['null'] = [Guid]'00000000-0000-0000-0000-000000000000'}
        $DynamicParamValue = $MasterGuidMap.Keys

        #$DynamicParamValue
        $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($DynamicParamValue)

        # Add the ValidateSet to the attributes collection
        $AttributeCollection.Add($ValidateSetAttribute)

        # Create and return the dynamic parameter
        $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
        $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter) #ForEach DynamicParam
        #endregion

        #region InheritedObjectType
        #Second DynParam
        # Set the dynamic parameters' name
        $ParameterName = 'InheritedObjectType'
            
        # Create the dictionary 
        #$RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary #Already created

        # Create the collection of attributes
        $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            
        # Create and set the parameters' attributes
        $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
        $ParameterAttribute.Mandatory = $true
        $ParameterAttribute.Position = 1

        # Add the attributes to the attributes collection
        $AttributeCollection.Add($ParameterAttribute)

        # Generate and set the ValidateSet
        #$DomainName = [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        #$MasterGuidMap = @{}
        $RightsGuidMapSearcher = [ADSISearcher]'(&(objectclass=controlAccessRight)(rightsguid=*))'
        $RightsGuidMapSearcher.SearchRoot = [ADSI]"LDAP://CN=Schema,$(([ADSI]"LDAP://$DomainName/RootDSE").configurationNamingContext)"
        $null = $RightsGuidMapSearcher.PropertiesToLoad.AddRange(('displayname','rightsGuid'))
        $RightsGuidMapSearcher.PageSize = 10000
        $RightsGuidMapSearcher.FindAll() | Foreach-Object -Process {
            #$MasterGuidMap[(New-Object -TypeName Guid -ArgumentList (,$_.properties.rightsguid[0])).Guid] = "$($_.properties.displayname)"
            $MasterGuidMap["$($_.properties.displayname)"] = (New-Object -TypeName Guid -ArgumentList (,$_.properties.rightsguid[0])).Guid
        } -End {$MasterGuidMap['null'] = [Guid]'00000000-0000-0000-0000-000000000000'}
        $DynamicParamValue = $MasterGuidMap.Keys

        #$DynamicParamValue
        $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($DynamicParamValue)

        # Add the ValidateSet to the attributes collection
        $AttributeCollection.Add($ValidateSetAttribute)

        # Create and return the dynamic parameter
        $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
        $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter) #ForEach DynamicParam
        #endregion

        #Output
        $RuntimeParameterDictionary
    }

    Begin{
        #Dynamic Param
        $PsBoundParameters.GetEnumerator() | ForEach-Object -Process { New-Variable -Name $_.Key -Value $_.Value -ErrorAction 'SilentlyContinue' }

        #Prepare the Access Control Entry, force the type for constructor binding
        Write-Verbose -Message 'Preparing Access Control Entry attributes...'
        [System.Security.Principal.SecurityIdentifier]$Identity = (New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $(([ADSI]"LDAP://$GroupDistinguishedName").ObjectSid), 0).value #Get nice SID format
        [Guid]$InheritedObjectTypeValue = $MasterGuidMap[$InheritedObjectType]
        [Guid]$ObjectTypeValue          = $MasterGuidMap[$ObjectType]

        #Create the Access Control Entry
        Write-Verbose -Message 'Creating Access Control Entry...'
        $NewAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity,$AdRights,$AccessControlType,$ObjectTypeValue,$Inheritance,$InheritedObjectTypeValue
    }
    Process{
        try{
            Write-Verbose -Message "Connecting to $OrgUnitDN"
            $ADObject = [ADSI]("LDAP://" + $OrgUnitDN)
            $ADObject.ObjectSecurity.AddAccessRule($NewAce)
            Write-Verbose -Message 'Applying Access Control Entry'
            $ADObject.CommitChanges()
            if($PassThru){
                $ADObject.ObjectSecurity.Access
            }
        }
        catch{
            throw "$OrgUnitDN $_"
        }
    }
    End{}
}