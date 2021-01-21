#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers
#include <stdio.h>
#include <atlbase.h>
#include <atlsecurity.h>
#include <atlpath.h>
#include <winspool.h> // for permission bits
#include <map>
#include <string>
#include <iostream>

using Mapping = std::map<DWORD, LPCTSTR>;

Mapping mapGenericAccess = {
    // standard access rights
    {DELETE,                    _T("(D)Delete")},
    {READ_CONTROL,              _T("(RC)Read Control")},
    {WRITE_DAC,                 _T("(WDAC)Write Dacl")},
    {WRITE_OWNER,               _T("(WO)Write Owner")},
    {SYNCHRONIZE,               _T("(S)Synchronize")},

    // misc access rights
    {ACCESS_SYSTEM_SECURITY,    _T("(AS)Access SACL")},
    {MAXIMUM_ALLOWED,           _T("(MA)Maximum Allowed")},

    // generic access rights
    {GENERIC_READ,              _T("(GR)Generic Read")},
    {GENERIC_WRITE,             _T("(GW)Generic Write")},
    {GENERIC_EXECUTE,           _T("(GE)Generic Execute")},
    {GENERIC_ALL,               _T("(GA)Generic All")}
};

Mapping mapStandardAccess = {
    {DELETE,                    _T("(D)")},
    {READ_CONTROL,              _T("(RC)")},
    {WRITE_DAC,                 _T("(WDAC)")},
    {WRITE_OWNER,               _T("(WO)")},
    {SYNCHRONIZE,               _T("(S)")}
};

Mapping mapSpecificAccess = {
    // specific access rights for files
    {FILE_READ_DATA | FILE_LIST_DIRECTORY,        _T("(RD)Read Data/List Directory")},
    {FILE_WRITE_DATA | FILE_ADD_FILE,             _T("(WD)Write Data/Add File")},
    {FILE_APPEND_DATA | FILE_ADD_SUBDIRECTORY,    _T("(AD)Append Data/Add Subdirectory")},
    {FILE_READ_EA,                                _T("(REA)Read Extended Attributes")},
    {FILE_WRITE_EA,                               _T("(WEA)Write Extended Attributes")},
    {FILE_EXECUTE | FILE_TRAVERSE,                _T("(X)Execute/Traverse")},
    {FILE_DELETE_CHILD,                           _T("(DC)Delete Child")},
    {FILE_READ_ATTRIBUTES,                        _T("(RA)Read Attributes")},
    {FILE_WRITE_ATTRIBUTES,                       _T("(WA)Write Attributes")}
};

Mapping mapFileAccess = {
    {FILE_GENERIC_READ,                           _T("(R)File Generic Read")},
    {FILE_GENERIC_WRITE,                          _T("(W)File Generic Write")},
    {FILE_GENERIC_EXECUTE,                        _T("(X)File Generic Execute")},
    {FILE_ALL_ACCESS,                             _T("(F)File Generic All Access")}
};

Mapping mapRead = {
    {FILE_READ_DATA | FILE_LIST_DIRECTORY, _T("(RD)")},
    {FILE_READ_ATTRIBUTES,                 _T("(RA)")},
    {FILE_READ_EA,                         _T("(REA)")},
    {SYNCHRONIZE,                          _T("(S)")}
};

Mapping mapWrite = {
    {FILE_WRITE_DATA | FILE_ADD_FILE,          _T("(WD)")},
    {FILE_APPEND_DATA | FILE_ADD_SUBDIRECTORY, _T("(AD)")},
    {FILE_WRITE_ATTRIBUTES,                    _T("(WA)")},
    {FILE_WRITE_EA,                            _T("(WEA)")},

};

Mapping mapExecute = {
    {FILE_EXECUTE | FILE_TRAVERSE,    _T("(X)")}
};

void DumpAccessMaskBase(ACCESS_MASK access)
{
    BOOL flagGet = FALSE;
    DWORD FULL = FILE_ALL_ACCESS;
    DWORD MODIFY = FILE_GENERIC_EXECUTE | FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE;
    DWORD READEXECTE = FILE_GENERIC_EXECUTE | FILE_GENERIC_READ;
    DWORD READ = FILE_GENERIC_READ;
    DWORD WRITE = FILE_GENERIC_WRITE & ~STANDARD_RIGHTS_WRITE;

    if ((FULL & access) == FULL)
    {
        _tprintf(_T("(F)"));
        flagGet = TRUE;
        return;
    }

    if ((MODIFY & access) == MODIFY)
    {
        _tprintf(_T("(M)"));
        flagGet = TRUE;
        return;
    }

    if ((READEXECTE & access) == READEXECTE)
    {
        _tprintf(_T("(RX)"));
        flagGet = TRUE;
    }
    else
    {
        for (auto& [dwValue, szName] : mapExecute)  // ºÏ≤‚÷¥–– Ù–‘
        {
            if (access & dwValue)
            {
                _tprintf(_T("%s"), szName);
                flagGet = TRUE;
            }
        }

        if ((READ & access) == READ)  // ºÏ≤‚∂¡ Ù–‘
        {
            _tprintf(_T("(R)"));
            flagGet = TRUE;
        }
        else
        {
            for (auto& [dwValue, szName] : mapRead)
            {
                if (access & dwValue)
                {
                    _tprintf(_T("%s"), szName);
                    flagGet = TRUE;
                }
            }
        }
    }

    if ((WRITE & access) == WRITE)
    {
        _tprintf(_T("(W)"));
        flagGet = TRUE;
    }
    else
    {
        for (auto& [dwValue, szName] : mapWrite)
        {
            if (access & dwValue)
            {
                _tprintf(_T("%s"), szName);
                flagGet = TRUE;
            }
        }
    }

    if (!flagGet)  // ºÏ≤‚±Í◊º Ù–‘
    {
        for (auto& [dwValue, szName] : mapStandardAccess)
        {
            if (access & dwValue)
            {
                _tprintf(_T("%s"), szName);
                flagGet = TRUE;
            }
        }
    }
}

void DumpAccessMask(ACCESS_MASK access)
{
    ACCESS_MASK remaining = access;

    // examine the standard and generic bits that are set.
    for (auto& [dwValue, szName] : mapGenericAccess)
    {
        if (remaining & dwValue)
        {
            remaining &= ~dwValue;
            _tprintf(_T("        - %s\n"), szName);
        }
    }

    // examine the specific bits that are set
    for (auto& [dwValue, szName] : mapSpecificAccess)
    {
        if (remaining & dwValue)
        {
            remaining &= ~dwValue;
            _tprintf(_T("        - %s\n"), szName);
        }
    }

    // take a look at the mappings for generic rights.
    // the generic bits should not have been set in the DACL
    // we got. instead, the specific and standard rights they map
    // to should have been set. now see which of the generic rights we
    // really have

    for (auto& [dwValue, szName] : mapFileAccess)
    {
        if ((access & dwValue) == dwValue)
        {
            _tprintf(_T("        - %s\n"), szName);
        }
    }

    if (remaining)
        _tprintf(_T("        Unknown Access Mask: %8.8X"), remaining);
}

void DumpAceType(BYTE type)
{
    static Mapping mapTypes = {
        {ACCESS_ALLOWED_ACE_TYPE,        _T("ACCESS_ALLOWED_ACE_TYPE")},
        {ACCESS_ALLOWED_OBJECT_ACE_TYPE, _T("ACCESS_ALLOWED_OBJECT_ACE_TYPE")},
        {ACCESS_DENIED_ACE_TYPE,         _T("ACCESS_DENIED_ACE_TYPE")},
        {ACCESS_DENIED_OBJECT_ACE_TYPE,  _T("ACCESS_DENIED_OBJECT_ACE_TYPE")},
        {SYSTEM_AUDIT_ACE_TYPE,          _T("SYSTEM_AUDIT_ACE_TYPE")},
        {SYSTEM_AUDIT_OBJECT_ACE_TYPE,   _T("SYSTEM_AUDIT_OBJECT_ACE_TYPE")}
    };

    if (auto it = mapTypes.find(type); it != mapTypes.end())
    {
        auto& [dwValue, szName] = *it;
        if (szName)
            _tprintf(_T("        - %s\n"), szName);
        else
            _tprintf(_T("        Unknown type %d"), type);
    }
}

void DumpAceFlags(BYTE flags)
{
    static Mapping mapFlags = {
        {CONTAINER_INHERIT_ACE,      _T("Container Inherit")},
        {INHERIT_ONLY_ACE,           _T("Inherit Only")},
        {INHERITED_ACE,              _T("Inherited")},
        {NO_PROPAGATE_INHERIT_ACE,   _T("Non-propagated Inherit")},
        {OBJECT_INHERIT_ACE,         _T("Object Inherit")},
        {FAILED_ACCESS_ACE_FLAG,     _T("Audit Failed Attempts")},
        {SUCCESSFUL_ACCESS_ACE_FLAG, _T("Audit Successful Attempts")}
    };

    for (auto& [dwValue, szName] : mapFlags)
    {
        if (flags & dwValue) {
            flags &= ~dwValue;
            _tprintf(_T("        - %s\n"), szName);
        }
    }

    if (flags)
        _tprintf(_T("        Unknown flags: %8.8X"), flags);
}

void DumpAce(CSid& sid, ACCESS_MASK mask, BYTE type, BYTE flags, GUID guidObjectType, GUID guidInheritedObjectType)
{
    _tprintf(_T("      Sid: %s\\%s"), sid.Domain(), sid.AccountName());
    DumpAccessMaskBase(mask);
    _tprintf(_T("\n"));

    _tprintf(_T("      Mask:\n"));
    DumpAccessMask(mask);

    _tprintf(_T("      Type:\n"));
    DumpAceType(type);

    _tprintf(_T("      Flags:\n"));
    DumpAceFlags(flags);

    if (!InlineIsEqualGUID(GUID_NULL, guidObjectType))
    {
        _tprintf(_T("Object Type:"));

        CStringW str;
        if (StringFromGUID2(guidObjectType, CStrBufW(str, 128), 128))
            _tprintf(CW2CT(str));
        else
            _tprintf(_T("Failure converting GUID to String"));
    }

    if (!InlineIsEqualGUID(GUID_NULL, guidInheritedObjectType))
    {
        _tprintf(_T("Inherited Object Type:"));

        CStringW str;
        if (StringFromGUID2(guidInheritedObjectType, CStrBufW(str, 128), 128))
            _tprintf(CW2CT(str));
        else
            _tprintf(_T("Failure converting GUID to String"));
    }
}

void DumpAcl(CAcl& acl)
{
    if (acl.IsNull())
        _tprintf(_T("ACL is NULL"));
    else if (acl.IsEmpty())
        _tprintf(_T("ACL is Empty"));
    else
    {
        _tprintf(_T("  Ace Count: %d\n"), acl.GetAceCount());

        for (UINT i = 0; i < acl.GetAceCount(); i++)
        {
            CSid sid;
            ACCESS_MASK mask;
            BYTE type;
            BYTE flags;
            GUID guidObjectType;
            GUID guidInheritedObjectType;
            
            acl.GetAclEntry(i, &sid, &mask, &type, &flags, &guidObjectType, &guidInheritedObjectType);
            std::wstring name = sid.AccountName();
            if ( name != _T("Everyone") && name != _T("Guest"))
            {
                continue;
            }
            _tprintf(_T("---------------------------------\n"));
            _tprintf(_T("    Ace %d:\n"), i);
            DumpAce(sid, mask, type, flags, guidObjectType, guidInheritedObjectType);
        }
    }
}

void DumpSecurityDescriptor(CSecurityDesc& sd, SECURITY_INFORMATION si)
{
    CSid sidOwner;
    CSid sidGroup;
    CDacl dacl;
    CSacl sacl;
    bool bPresent = false;
    bool bDefaulted = false;

    if ((si & OWNER_SECURITY_INFORMATION) && sd.GetOwner(&sidOwner, &bDefaulted))
    {
        _tprintf(_T("\nOwner: %s/%s SID: %s\n"), sidOwner.Domain(), sidOwner.AccountName(), sidOwner.Sid());
    }

    if ((si & GROUP_SECURITY_INFORMATION) && sd.GetGroup(&sidGroup, &bDefaulted))
    {
        _tprintf(_T("\nGroup: %s/%s SID: %s\n"), sidGroup.Domain(), sidGroup.AccountName(), sidGroup.Sid());
    }

    if ((si & DACL_SECURITY_INFORMATION) && sd.GetDacl(&dacl, &bPresent, &bDefaulted))
    {
        _tprintf(_T("\nDacl: %s %s\n"),
            bPresent ? _T("") : _T("[Not Present]"),
            bDefaulted ? _T("[Defaulted]") : _T(""));
        DumpAcl(dacl);
    }
}

void DumpSecurityDescriptor(LPCTSTR szObject, SE_OBJECT_TYPE type)
{
    CSecurityDesc sd;
    SECURITY_INFORMATION si =
        OWNER_SECURITY_INFORMATION |
        GROUP_SECURITY_INFORMATION |
        DACL_SECURITY_INFORMATION;

    if (!AtlGetSecurityDescriptor(szObject, type, &sd, si))
    {
        _tprintf(_T("Could not retrieve security descriptor"));
    }

    DumpSecurityDescriptor(sd, si);
}

int main(int argc, char* argv[])
{
    LPCTSTR fileName = _T("F:\\VSProjects\\SIDTest\\test");
    DumpSecurityDescriptor(fileName, SE_FILE_OBJECT);

    CDacl dacl;
    CSid guest;
    LPCTSTR account = _T("Guest");
    if (!guest.LoadAccount(account))
    {
        _tprintf(_T("Load Account Error, error code = %u.\n"), GetLastError());
        return -1;
    }
    if (!AtlGetDacl(fileName, SE_FILE_OBJECT, &dacl))
    {
        _tprintf(_T("AtlGetDacl Error, error code = %u\n"), GetLastError());
        return -1;
    }

    ACCESS_MASK FULL = FILE_ALL_ACCESS;
    ACCESS_MASK MODIFY = FILE_GENERIC_EXECUTE | FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE;
    ACCESS_MASK READEXECTE = FILE_GENERIC_EXECUTE | FILE_GENERIC_READ;
    ACCESS_MASK READ = FILE_GENERIC_READ;
    ACCESS_MASK WRITE = FILE_GENERIC_WRITE & ~STANDARD_RIGHTS_WRITE;
    UINT count = dacl.GetAceCount();
    bool everyoneAllow = false;
    bool guestAllow = false;
    for (UINT i = 0; i < count; i++)
    {
        CSid sid;
        ACCESS_MASK mask;
        BYTE type;
        BYTE flags;

        dacl.GetAclEntry(i, &sid, &mask, &type, &flags);
        _tprintf(_T("\nSID info: %s/%s SID: %s\n"), sid.Domain(), sid.AccountName(), sid.Sid());
        if (sid == Sids::World())
        {
            std::cout << "Everyone: \n";
            everyoneAllow |= ((type == ACCESS_ALLOWED_ACE_TYPE) || (type == ACCESS_ALLOWED_OBJECT_ACE_TYPE));
            std::cout << std::boolalpha << ((type == ACCESS_ALLOWED_ACE_TYPE) || (type == ACCESS_ALLOWED_OBJECT_ACE_TYPE)) << '\n';
            //dacl.RemoveAce(i);
            //dacl.AddAllowedAce(sid, FULL, flags);
            ////dacl.AddDeniedAce(sid, GENERIC_ALL, flags);
        }

        if (std::wstring_view(sid.AccountName()) == std::wstring_view(guest.AccountName()))
        {
            std::cout << "Guest: \n";
            guestAllow |= (type == ACCESS_ALLOWED_ACE_TYPE) || (type == ACCESS_ALLOWED_OBJECT_ACE_TYPE);
            std::cout << std::boolalpha << ((type == ACCESS_ALLOWED_ACE_TYPE) || (type == ACCESS_ALLOWED_OBJECT_ACE_TYPE)) << '\n';
            //dacl.RemoveAce(i);
            //dacl.AddAllowedAce(sid, FULL, flags);
            ////dacl.AddDeniedAce(sid, GENERIC_ALL, flags);
        }
    }

    std::cout << "Everyone Allow: " << std::boolalpha << everyoneAllow << '\n';
    std::cout << "Guest Allow: " << std::boolalpha << guestAllow << '\n';

    /*if (!AtlSetDacl(fileName, SE_FILE_OBJECT, dacl, PROTECTED_DACL_SECURITY_INFORMATION))
    {
        _tprintf(_T("AtlSetDacl Error. error code = %u\n"), GetLastError());
        return -1;
    }*/

    return 0;
}