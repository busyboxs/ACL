#include <windows.h>
#include <stdio.h>
#include <AclAPI.h>
#include <tchar.h>
#include <iostream>
#include <bitset>
#include <sddl.h>
#include <atlsecurity.h>
#include <winnt.h>

DWORD AddAceToObjectsSecurityDescriptor(
    LPTSTR pszObjName,          // name of object
    SE_OBJECT_TYPE ObjectType,  // type of object
    LPTSTR pszTrustee,          // trustee for new ACE
    TRUSTEE_FORM TrusteeForm,   // format of trustee structure
    DWORD dwAccessRights,       // access mask for new ACE
    ACCESS_MODE AccessMode,     // type of ACE
    DWORD dwInheritance         // inheritance flags for new ACE
)
{
    DWORD dwRes = 0;
    PACL pOldDACL = NULL, pNewDACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    EXPLICIT_ACCESS ea;

    if (NULL == pszObjName)
        return ERROR_INVALID_PARAMETER;

    // Get a pointer to the existing DACL.

    dwRes = GetNamedSecurityInfo(pszObjName, ObjectType,
        DACL_SECURITY_INFORMATION,
        NULL, NULL, &pOldDACL, NULL, &pSD);
    if (ERROR_SUCCESS != dwRes) {
        printf("GetNamedSecurityInfo Error %u\n", dwRes);
        goto Cleanup;
    }

    // Initialize an EXPLICIT_ACCESS structure for the new ACE. 

    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = dwAccessRights;
    ea.grfAccessMode = AccessMode;
    ea.grfInheritance = dwInheritance;
    ea.Trustee.TrusteeForm = TrusteeForm;
    ea.Trustee.ptstrName = pszTrustee;

    // Create a new ACL that merges the new ACE
    // into the existing DACL.

    dwRes = SetEntriesInAcl(1, &ea, pOldDACL, &pNewDACL);
    if (ERROR_SUCCESS != dwRes) {
        printf("SetEntriesInAcl Error %u\n", dwRes);
        goto Cleanup;
    }

    // Attach the new ACL as the object's DACL.

    dwRes = SetNamedSecurityInfo(pszObjName, ObjectType,
        DACL_SECURITY_INFORMATION,
        NULL, NULL, pNewDACL, NULL);
    if (ERROR_SUCCESS != dwRes) {
        printf("SetNamedSecurityInfo Error %u\n", dwRes);
        goto Cleanup;
    }

Cleanup:

    if (pSD != NULL)
        LocalFree((HLOCAL)pSD);
    if (pNewDACL != NULL)
        LocalFree((HLOCAL)pNewDACL);

    return dwRes;
}

BOOL getAccountNameAndDomainName(
    PSID pSidOwner, 
    LPWSTR& AcctName,
    LPWSTR& DomainName)
{
    BOOL bRtnBool = TRUE;
    SID_NAME_USE eUse = SidTypeUnknown;
    DWORD dwAcctName = 0;
    DWORD dwDomainName = 0;
    // First call to LookupAccountSid to get the buffer sizes.
    bRtnBool = LookupAccountSid(NULL, pSidOwner, NULL, (LPDWORD)&dwAcctName,
        NULL, (LPDWORD)&dwDomainName, &eUse);

    AcctName = new WCHAR[dwAcctName];
    DomainName = new WCHAR[dwDomainName];

    // Second call to LookupAccountSid to get the account name.
    bRtnBool = LookupAccountSid(NULL, pSidOwner, AcctName, (LPDWORD)&dwAcctName,
        DomainName, (LPDWORD)&dwDomainName, &eUse);

  // Check GetLastError for LookupAccountSid error condition.
    if (bRtnBool == FALSE) {
        if (GetLastError() == ERROR_NONE_MAPPED)
            _tprintf(TEXT("Account owner not found for specified SID.\n"));
        else
            _tprintf(TEXT("Error in LookupAccountSid.\n"));
        return -1;
    }
    return 0;
}

void parseMode(ACCESS_MODE mode)
{
    switch (mode)
    {
    case NOT_USED_ACCESS:
        _tprintf(TEXT("access mode: [NOT_USED_ACCESS]\n"));
        break;
    case GRANT_ACCESS:
        _tprintf(TEXT("access mode: [GRANT_ACCESS]\n"));
        break;
    case SET_ACCESS:
        _tprintf(TEXT("access mode: [SET_ACCESS]\n"));
        break;
    case DENY_ACCESS:
        _tprintf(TEXT("access mode: [DENY_ACCESS]\n"));
        break;
    case REVOKE_ACCESS:
        _tprintf(TEXT("access mode: [REVOKE_ACCESS]\n"));
        break;
    case SET_AUDIT_SUCCESS:
        _tprintf(TEXT("access mode: [SET_AUDIT_SUCCESS]\n"));
        break;
    case SET_AUDIT_FAILURE:
        _tprintf(TEXT("access mode: [SET_AUDIT_FAILURE]\n"));
        break;
    default:
        break;
    }
}

void parseInheritance(DWORD inherit)
{
    _tprintf(TEXT("\nInheritance: \n"));
    if (inherit & CONTAINER_INHERIT_ACE) 
    {
        _tprintf(TEXT(" | CONTAINER_INHERIT_ACE\n"));
    }
    if (inherit & INHERIT_NO_PROPAGATE)
    {
        _tprintf(TEXT(" | INHERIT_NO_PROPAGATE\n"));
    }
    if (inherit & INHERIT_ONLY)
    {
        _tprintf(TEXT(" | INHERIT_ONLY\n"));
    }
    if (inherit & INHERIT_ONLY_ACE)
    {
        _tprintf(TEXT(" | INHERIT_ONLY_ACE\n"));
    }
    if (inherit & NO_INHERITANCE)
    {
        _tprintf(TEXT(" | NO_INHERITANCE\n"));
    }
    if (inherit & NO_PROPAGATE_INHERIT_ACE)
    {
        _tprintf(TEXT(" | NO_PROPAGATE_INHERIT_ACE\n"));
    }
    if (inherit & OBJECT_INHERIT_ACE)
    {
        _tprintf(TEXT(" | OBJECT_INHERIT_ACE\n"));
    }
    if (inherit & SUB_CONTAINERS_AND_OBJECTS_INHERIT)
    {
        _tprintf(TEXT(" | SUB_CONTAINERS_AND_OBJECTS_INHERIT\n"));
    }
    if (inherit & SUB_CONTAINERS_ONLY_INHERIT)
    {
        _tprintf(TEXT(" | SUB_CONTAINERS_ONLY_INHERIT\n"));
    }
    if (inherit & SUB_OBJECTS_ONLY_INHERIT)
    {
        _tprintf(TEXT(" | SUB_OBJECTS_ONLY_INHERIT\n"));
    }

}

void parseStandardAccess(DWORD perm)
{
    _tprintf(TEXT("\nStandard Access: \n"));
    if (perm & DELETE)
    {
        _tprintf(TEXT(" | DELETE\n"));
    }
    if (perm & READ_CONTROL)
    {
        _tprintf(TEXT(" | READ_CONTROL\n"));
    }
    if (perm & WRITE_DAC)
    {
        _tprintf(TEXT(" | WRITE_DAC\n"));
    }
    if (perm & WRITE_OWNER)
    {
        _tprintf(TEXT(" | WRITE_OWNER\n"));
    }
    if (perm & SYNCHRONIZE)
    {
        _tprintf(TEXT(" | SYNCHRONIZE\n"));
    }
    if (perm & STANDARD_RIGHTS_READ)
    {
        _tprintf(TEXT(" | STANDARD_RIGHTS_READ\n"));
    }
    if (perm & STANDARD_RIGHTS_WRITE)
    {
        _tprintf(TEXT(" | STANDARD_RIGHTS_WRITE\n"));
    }
    if (perm & STANDARD_RIGHTS_EXECUTE)
    {
        _tprintf(TEXT(" | STANDARD_RIGHTS_EXECUTE\n"));
    }
    if (perm & STANDARD_RIGHTS_ALL)
    {
        _tprintf(TEXT(" | STANDARD_RIGHTS_ALL\n"));
    }
}

void parseSpecificAccessForFile(DWORD perm)
{
    _tprintf(TEXT("\nSpecific Access: \n"));
    if (perm & FILE_READ_DATA)
    {
        _tprintf(TEXT(" | FILE_READ_DATA(RD)\n"));
    }
    if (perm & FILE_WRITE_DATA)
    {
        _tprintf(TEXT(" | FILE_WRITE_DATA(WD)\n"));
    }
    if (perm & FILE_APPEND_DATA)
    {
        _tprintf(TEXT(" | FILE_APPEND_DATA(AD)\n"));
    }
    if (perm & FILE_READ_EA)
    {
        _tprintf(TEXT(" | FILE_READ_EA(REA)\n"));
    }
    if (perm & FILE_WRITE_EA)
    {
        _tprintf(TEXT(" | FILE_WRITE_EA(WEA)\n"));
    }
    if (perm & FILE_EXECUTE)
    {
        _tprintf(TEXT(" | FILE_EXECUTE(X)\n"));
    }
    if (perm & FILE_READ_ATTRIBUTES)
    {
        _tprintf(TEXT(" | FILE_READ_ATTRIBUTES(RA)\n"));
    }
    if (perm & FILE_WRITE_ATTRIBUTES)
    {
        _tprintf(TEXT(" | FILE_WRITE_ATTRIBUTES(WA)\n"));
    }

    _tprintf(TEXT("\nBase Access: \n"));
    if ((perm & FILE_ALL_ACCESS) == FILE_ALL_ACCESS)
    {
        _tprintf(TEXT(" | (F)\n"));
    }

    DWORD MODIFY = FILE_GENERIC_EXECUTE | FILE_GENERIC_READ | FILE_GENERIC_WRITE;
    if ((perm & MODIFY) == MODIFY)
    {
        _tprintf(TEXT(" | (M)\n"));
    }
    DWORD READEXECTE = FILE_GENERIC_EXECUTE | FILE_GENERIC_READ;
    if ((perm & READEXECTE) == READEXECTE)
    {
        _tprintf(TEXT(" | (RX)\n"));
    }
    if ((perm & FILE_GENERIC_READ) == FILE_GENERIC_READ)
    {
        _tprintf(TEXT(" | (R)\n"));
    }
    DWORD WRITE = FILE_GENERIC_WRITE & ~STANDARD_RIGHTS_WRITE;
    if ((perm & WRITE) == WRITE)
    {
        _tprintf(TEXT(" | (W)\n"));
    }
}

void parseSpecificAccessForDirectory(DWORD perm)
{
    _tprintf(TEXT("\nSpecific Access: \n"));
    if (perm & FILE_LIST_DIRECTORY)
    {
        _tprintf(TEXT(" | FILE_LIST_DIRECTORY\n"));
    }
    if (perm & FILE_ADD_FILE)
    {
        _tprintf(TEXT(" | FILE_ADD_FILE\n"));
    }
    if (perm & FILE_ADD_SUBDIRECTORY)
    {
        _tprintf(TEXT(" | FILE_ADD_SUBDIRECTORY\n"));
    }
    if (perm & FILE_READ_EA)
    {
        _tprintf(TEXT(" | FILE_READ_EA\n"));
    }
    if (perm & FILE_WRITE_EA)
    {
        _tprintf(TEXT(" | FILE_WRITE_EA\n"));
    }
    if (perm & FILE_TRAVERSE)
    {
        _tprintf(TEXT(" | FILE_TRAVERSE\n"));
    }
    if (perm & FILE_DELETE_CHILD)
    {
        _tprintf(TEXT(" | FILE_DELETE_CHILD\n"));
    }
    if (perm & FILE_READ_ATTRIBUTES)
    {
        _tprintf(TEXT(" | FILE_READ_ATTRIBUTES\n"));
    }
    if (perm & FILE_WRITE_ATTRIBUTES)
    {
        _tprintf(TEXT(" | FILE_WRITE_ATTRIBUTES\n"));
    }

    _tprintf(TEXT("\nBase Access: \n"));
    if ((perm & FILE_ALL_ACCESS) == FILE_ALL_ACCESS)
    {
        _tprintf(TEXT(" | (F)\n"));
    }

    DWORD MODIFY = FILE_GENERIC_EXECUTE | FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE;
    if ((perm & MODIFY) == MODIFY)
    {
        _tprintf(TEXT(" | (M)\n"));
    }
    DWORD READEXECTE = FILE_GENERIC_EXECUTE | FILE_GENERIC_READ;
    if ((perm & READEXECTE) == READEXECTE)
    {
        _tprintf(TEXT(" | (RX)\n"));
    }
    if ((perm & FILE_GENERIC_READ) == FILE_GENERIC_READ)
    {
        _tprintf(TEXT(" | (R)\n"));
    }
    DWORD WRITE = FILE_GENERIC_WRITE & ~STANDARD_RIGHTS_WRITE;
    if ((perm & WRITE) == WRITE)
    {
        _tprintf(TEXT(" | (W)\n"));
    }
}

int main()
{
    LPCWSTR fName = _T("G:\\parent\\child3\\03.bmp");

    PSECURITY_DESCRIPTOR pSD = NULL;
    PACL pDAcl;
    ACL_SIZE_INFORMATION aclSize = { 0 };
    PSID pSidOwner = NULL;
    PSID pSidGroup = NULL;
    DWORD dwRes = 0;

    dwRes = GetNamedSecurityInfo(
        fName,
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &pSidOwner,
        &pSidGroup, 
        &pDAcl,
        NULL,
        &pSD);

    if (dwRes != ERROR_SUCCESS)
    { 
        printf("GetNamedSecurityInfo Error %u\n", dwRes);
        return NULL;
    }    LPTSTR AcctName = NULL;
    LPTSTR DomainName = NULL;
    getAccountNameAndDomainName(pSidOwner, AcctName, DomainName);
    _tprintf(TEXT("Owner = %s/%s\n"), DomainName, AcctName);

    LPTSTR GroupName = NULL;
    LPTSTR GroupDomainName = NULL;
    getAccountNameAndDomainName(pSidGroup, GroupName, GroupDomainName);
    _tprintf(TEXT("Group = %s/%s\n"), GroupDomainName, GroupName);

    _tprintf(TEXT("count: %d\n"), (*pDAcl).AceCount);

    ULONG entryCount;
    PEXPLICIT_ACCESS entries;
    DWORD ret = 0;
    ret = GetExplicitEntriesFromAclW(pDAcl, &entryCount, &entries);
    std::wcout << entryCount << std::endl;

    for (int i = 0; i < entryCount; ++i, entries++)
    {
        PSID sid = (PSID)entries->Trustee.ptstrName;
        LPTSTR sidName = NULL;
        LPTSTR sidDomainName = NULL;
        getAccountNameAndDomainName(sid, sidName, sidDomainName);
        _tprintf(TEXT("Group = %s/%s\n"), sidDomainName, sidName);

        ACCESS_MODE accessMode = entries->grfAccessMode;
        parseMode(accessMode);

        DWORD inherit = entries->grfInheritance;
        parseInheritance(inherit);

        std::bitset<32> ib(inherit);
        std::cout << ib << std::endl;

        DWORD perm = entries->grfAccessPermissions;
        parseSpecificAccessForFile(perm);

        std::bitset<32> pb(perm);
        std::cout << pb << std::endl;
    }

    EXPLICIT_ACCESS ea;
    PACL pNewDACL = NULL;
    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
    DWORD FULL = FILE_ALL_ACCESS;
    DWORD MODIFY = FILE_GENERIC_EXECUTE | FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE;
    DWORD READEXECTE = FILE_GENERIC_EXECUTE | FILE_GENERIC_READ;
    DWORD READ = FILE_GENERIC_READ;
    DWORD WRITE = FILE_GENERIC_WRITE & ~STANDARD_RIGHTS_WRITE;
    PSID pSidEveryone;
    LPTSTR lpstr = const_cast<LPTSTR>(_T("G:\\parent\\child3\\03.bmp"));
    ConvertStringSidToSid(_T("S-1-1-0"), &pSidEveryone);

    ea.grfAccessPermissions = READ;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.ptstrName = (LPTSTR)pSidEveryone;
    ea.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;

    dwRes = SetEntriesInAcl(1, &ea, pDAcl, &pNewDACL);
    if (ERROR_SUCCESS != dwRes)
    {
        _tprintf(_T("SetEntriesInAcl Error %u\n"), dwRes);
        goto Cleanup;
    }


    dwRes = SetNamedSecurityInfo(lpstr, SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL, NULL, pNewDACL, NULL);
    if (ERROR_SUCCESS != dwRes) {
        printf("SetNamedSecurityInfo Error %u\n", dwRes);
        goto Cleanup;
    }

    Cleanup:
    if (pSD)
        LocalFree(pSD);
    if (pSidOwner)
        LocalFree(pSidOwner);
    if (pDAcl)
        LocalFree(pDAcl);

    return 0;
}