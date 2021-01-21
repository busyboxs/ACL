#include "util.h"

int PrintOwner()
{
    DWORD dwRtnCode = 0;
    PSID pSidOwner = NULL;
    BOOL bRtnBool = TRUE;
    LPTSTR AcctName = NULL;
    LPTSTR DomainName = NULL;
    DWORD dwAcctName = 1, dwDomainName = 1;
    SID_NAME_USE eUse = SidTypeUnknown;
    HANDLE hFile;
    PSECURITY_DESCRIPTOR pSD = NULL;



    // Get the handle of the file object.
    hFile = CreateFile(
        TEXT("F:\\VSProjects\\SIDTest\\myfile.txt"),
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    // Check GetLastError for CreateFile error code.
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD dwErrorCode = 0;

        dwErrorCode = GetLastError();
        _tprintf(TEXT("CreateFile error = %d\n"), dwErrorCode);
        return -1;
    }



    // Get the owner SID of the file.
    dwRtnCode = GetSecurityInfo(
        hFile,
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION,
        &pSidOwner,
        NULL,
        NULL,
        NULL,
        &pSD);

    // Check GetLastError for GetSecurityInfo error condition.
    if (dwRtnCode != ERROR_SUCCESS) {
        DWORD dwErrorCode = 0;

        dwErrorCode = GetLastError();
        _tprintf(TEXT("GetSecurityInfo error = %d\n"), dwErrorCode);
        return -1;
    }

    // First call to LookupAccountSid to get the buffer sizes.
    bRtnBool = LookupAccountSid(
        NULL,           // local computer
        pSidOwner,
        AcctName,
        (LPDWORD)&dwAcctName,
        DomainName,
        (LPDWORD)&dwDomainName,
        &eUse);

    // Reallocate memory for the buffers.
    AcctName = (LPTSTR)GlobalAlloc(
        GMEM_FIXED,
        dwAcctName);

    // Check GetLastError for GlobalAlloc error condition.
    if (AcctName == NULL) {
        DWORD dwErrorCode = 0;

        dwErrorCode = GetLastError();
        _tprintf(TEXT("GlobalAlloc error = %d\n"), dwErrorCode);
        return -1;
    }

    DomainName = (LPTSTR)GlobalAlloc(
        GMEM_FIXED,
        dwDomainName);

    // Check GetLastError for GlobalAlloc error condition.
    if (DomainName == NULL) {
        DWORD dwErrorCode = 0;

        dwErrorCode = GetLastError();
        _tprintf(TEXT("GlobalAlloc error = %d\n"), dwErrorCode);
        return -1;

    }

    // Second call to LookupAccountSid to get the account name.
    bRtnBool = LookupAccountSid(
        NULL,                   // name of local or remote computer
        pSidOwner,              // security identifier
        AcctName,               // account name buffer
        (LPDWORD)&dwAcctName,   // size of account name buffer 
        DomainName,             // domain name
        (LPDWORD)&dwDomainName, // size of domain name buffer
        &eUse);                 // SID type

  // Check GetLastError for LookupAccountSid error condition.
    if (bRtnBool == FALSE) {
        DWORD dwErrorCode = 0;

        dwErrorCode = GetLastError();

        if (dwErrorCode == ERROR_NONE_MAPPED)
            _tprintf(TEXT
            ("Account owner not found for specified SID.\n"));
        else
            _tprintf(TEXT("Error in LookupAccountSid.\n"));
        return -1;

    }
    else if (bRtnBool == TRUE)
    {
        // Print the account name.
        _tprintf(TEXT("Account owner = %s\n"), AcctName);
        _tprintf(TEXT("Domain Name = %s\n"), DomainName);
    }

    return 0;
}

int PrintDAcl()
{
    DWORD dwRtnCode = 0;
    PSID pSidOwner = NULL;
    BOOL bRtnBool = TRUE;
    LPTSTR AcctName = NULL;
    LPTSTR DomainName = NULL;
    DWORD dwAcctName = 1, dwDomainName = 1;
    SID_NAME_USE eUse = SidTypeUnknown;
    HANDLE hFile;
    PSECURITY_DESCRIPTOR pSD = NULL;



    // Get the handle of the file object.
    hFile = CreateFile(
        TEXT("F:\\VSProjects\\SIDTest\\myfile.txt"),
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    // Check GetLastError for CreateFile error code.
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD dwErrorCode = 0;

        dwErrorCode = GetLastError();
        _tprintf(TEXT("CreateFile error = %d\n"), dwErrorCode);
        return -1;
    }

    PACL pDacl;
    // Get the owner SID of the file.
    dwRtnCode = GetSecurityInfo(
        hFile,
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL,
        NULL,
        &pDacl,
        NULL,
        &pSD);

    // Check GetLastError for GetSecurityInfo error condition.
    if (dwRtnCode != ERROR_SUCCESS) {
        DWORD dwErrorCode = 0;

        dwErrorCode = GetLastError();
        _tprintf(TEXT("GetSecurityInfo error = %d\n"), dwErrorCode);
        return -1;
    }

    return 0;
}

void ACLToNewFileOrDirectory()
{
    DWORD dwRes, dwDisposition;
    PSID pAdminSID = NULL;
    PACL pACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;

    SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
    SECURITY_ATTRIBUTES sa;
    LONG lRes;
    HKEY hkSub = NULL;


    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    PSID pEveryoneSID = NULL;
    // Create a well-known SID for the Everyone group.
    if (!AllocateAndInitializeSid(&SIDAuthWorld, 1,
        SECURITY_WORLD_RID,
        0, 0, 0, 0, 0, 0, 0,
        &pEveryoneSID))
    {
        _tprintf(_T("AllocateAndInitializeSid Error %u\n"), GetLastError());
        goto Cleanup;
    }


    EXPLICIT_ACCESS ea[2];
    // Initialize an EXPLICIT_ACCESS structure for an ACE.
    // The ACE will allow Everyone read access to the key.
    ZeroMemory(&ea, 2 * sizeof(EXPLICIT_ACCESS));
    ea[0].grfAccessPermissions = KEY_READ;
    ea[0].grfAccessMode = SET_ACCESS;
    ea[0].grfInheritance = NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[0].Trustee.ptstrName = (LPTSTR)pEveryoneSID;

    // Create a SID for the BUILTIN\Administrators group.
    if (!AllocateAndInitializeSid(&SIDAuthNT, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &pAdminSID))
    {
        _tprintf(_T("AllocateAndInitializeSid Error %u\n"), GetLastError());
        goto Cleanup;
    }

    // Initialize an EXPLICIT_ACCESS structure for an ACE.
    // The ACE will allow the Administrators group full access to
    // the key.
    ea[1].grfAccessPermissions = FILE_WRITE_DATA;
    ea[1].grfAccessMode = GRANT_ACCESS;
    ea[1].grfInheritance = NO_INHERITANCE;
    ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ea[1].Trustee.ptstrName = (LPTSTR)pAdminSID;

    // Create a new ACL that contains the new ACEs.
    dwRes = SetEntriesInAcl(2, ea, NULL, &pACL);
    if (ERROR_SUCCESS != dwRes)
    {
        _tprintf(_T("SetEntriesInAcl Error %u\n"), GetLastError());
        goto Cleanup;
    }

    // Initialize a security descriptor.  
    pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR,
        SECURITY_DESCRIPTOR_MIN_LENGTH);
    if (NULL == pSD)
    {
        _tprintf(_T("LocalAlloc Error %u\n"), GetLastError());
        goto Cleanup;
    }

    if (!InitializeSecurityDescriptor(pSD,
        SECURITY_DESCRIPTOR_REVISION))
    {
        _tprintf(_T("InitializeSecurityDescriptor Error %u\n"),
            GetLastError());
        goto Cleanup;
    }

    // Add the ACL to the security descriptor. 
    if (!SetSecurityDescriptorDacl(pSD,
        TRUE,     // bDaclPresent flag   
        pACL,
        FALSE))   // not a default DACL 
    {
        _tprintf(_T("SetSecurityDescriptorDacl Error %u\n"),
            GetLastError());
        goto Cleanup;
    }

    // Initialize a security attributes structure.
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = pSD;
    sa.bInheritHandle = FALSE;
    // Use the security attributes to set the security descriptor 
    // when you create a key.
    /*lRes = RegCreateKeyExW(HKEY_CURRENT_USER, _T("mykey"), 0, NULL, 0,
        KEY_READ | KEY_WRITE, &sa, &hkSub, &dwDisposition);
    _tprintf(_T("RegCreateKeyEx result %u\n"), lRes);*/

    HANDLE FRet;
    FRet = CreateFileW(_T("F:\\VSProjects\\SIDTest\\test.txt"),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        &sa,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (FRet == INVALID_HANDLE_VALUE) {
        DWORD dwErrorCode = 0;

        dwErrorCode = GetLastError();
        _tprintf(TEXT("CreateFile error = %d\n"), dwErrorCode);
        return;
    }

    if (!CreateDirectoryW(_T("F:\\VSProjects\\SIDTest\\test"), &sa)) {
        _tprintf(TEXT("Create Directory error"));
        return;
    }

Cleanup:

    if (pEveryoneSID)
        FreeSid(pEveryoneSID);
    if (pAdminSID)
        FreeSid(pAdminSID);
    if (pACL)
        LocalFree(pACL);
    if (pSD)
        LocalFree(pSD);
    if (hkSub)
        RegCloseKey(hkSub);

    return;
}

void tmp()
{
    /*SID_NAME_USE eUse = SidTypeUnknown;
    LPTSTR ownerName = NULL;
    LPTSTR domainName = NULL;
    DWORD owenerNameLen = 0;
    DWORD domainNameLen = 0;

    LookupAccountSid(NULL, pSidOwner, ownerName, &owenerNameLen, domainName, &domainNameLen, &eUse);
    ownerName = (LPTSTR)GlobalAlloc(GMEM_FIXED, owenerNameLen);
    if (ownerName == NULL) {
        _tprintf(TEXT("GlobalAlloc error = %d\n"), GetLastError());
        return -1;
    }
    domainName = (LPTSTR)GlobalAlloc(GMEM_FIXED, domainNameLen);
    if (domainName == NULL) {
        _tprintf(TEXT("GlobalAlloc error = %d\n"), GetLastError());
        return -1;
    }
    if (!LookupAccountSid(NULL, pSidOwner, ownerName, &owenerNameLen, domainName, &domainNameLen, &eUse))
    {
        printf("LookupAccountSid Error %u\n", GetLastError());
        return FALSE;
    }
    std::wcout << "Owner: " << domainName << "/" << ownerName << "\n";

    ownerName = NULL;
    domainName = NULL;
    owenerNameLen = 0;
    domainNameLen = 0;
    LookupAccountSid(NULL, pSidGroup, ownerName, &owenerNameLen, domainName, &domainNameLen, &eUse);
    ownerName = (LPTSTR)GlobalAlloc(GMEM_FIXED, owenerNameLen);
    if (ownerName == NULL) {
        _tprintf(TEXT("GlobalAlloc error = %d\n"), GetLastError());
        return -1;
    }
    domainName = (LPTSTR)GlobalAlloc(GMEM_FIXED, domainNameLen);
    if (domainName == NULL) {
        _tprintf(TEXT("GlobalAlloc error = %d\n"), GetLastError());
        return -1;
    }
    if (!LookupAccountSid(NULL, pSidGroup, ownerName, &owenerNameLen, domainName, &domainNameLen, &eUse))
    {
        printf("LookupAccountSid Error %u\n", GetLastError());
        return FALSE;
    }
    std::wcout << "Group: " << domainName << "/" << ownerName << "\n";*/
}
